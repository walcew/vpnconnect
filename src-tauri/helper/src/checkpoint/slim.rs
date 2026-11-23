//! O túnel SSL do Check Point sobre o TLS com o gateway: quadros `[tamanho][tipo]`, controle em
//! S-expression (`client_hello`, `hello_reply`, `keepalive`, `disconnect`) e dados com o pacote IP cru.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tokio::time::MissedTickBehavior;

use super::sexp::{self, Sexp};
use crate::net::Route;

const CONTROL: u32 = 1;
const DATA: u32 = 2;
const HEADER_LEN: usize = 8;
/// Teto de um quadro, para um tamanho absurdo do gateway não virar alocação sem limite.
const MAX_FRAME: usize = 1 << 20;
/// Intervalos seguidos sem resposta ao keepalive que derrubam o túnel.
const KEEPALIVE_MISSES: u32 = 3;

pub enum Frame {
    Control(Sexp),
    Data(Vec<u8>),
}

/// Quadro de controle: a S-expression seguida de um NUL, que entra no tamanho.
pub fn control(s: &Sexp) -> Vec<u8> {
    raw(CONTROL, &[s.encode().as_bytes(), b"\0"].concat())
}

fn raw(kind: u32, payload: &[u8]) -> Vec<u8> {
    [&(payload.len() as u32).to_be_bytes()[..], &kind.to_be_bytes(), payload].concat()
}

/// Tira de `buf` o próximo quadro completo; None se ainda falta byte.
pub fn take_frame(buf: &mut Vec<u8>) -> Result<Option<Frame>, String> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME {
        return Err(format!("Tunnel dropped: frame of {} bytes from the gateway", len));
    }
    if buf.len() < HEADER_LEN + len {
        return Ok(None);
    }
    let kind = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let payload: Vec<u8> = buf.drain(..HEADER_LEN + len).skip(HEADER_LEN).collect();
    match kind {
        DATA => Ok(Some(Frame::Data(payload))),
        CONTROL => sexp::parse(&String::from_utf8_lossy(&payload))
            .map(|s| Some(Frame::Control(s)))
            .map_err(|e| format!("Tunnel dropped: invalid control frame: {}", e)),
        other => Err(format!("Tunnel dropped: unknown frame type {}", other)),
    }
}

/// Lê do stream até o primeiro quadro de controle; os quadros que vierem junto ficam em `buf`.
pub async fn read_control<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>) -> Result<Sexp, String> {
    let mut chunk = vec![0u8; 65536];
    loop {
        match take_frame(buf)? {
            Some(Frame::Control(s)) => return Ok(s),
            Some(Frame::Data(_)) => continue,
            None => {}
        }
        match stream.read(&mut chunk).await {
            Ok(0) => return Err("Tunnel closed by the gateway before the hello reply".into()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("Tunnel read failed: {}", e)),
        }
    }
}

/// O motivo de um `disconnect` do gateway, com o código e a mensagem dele.
pub fn disconnect_reason(s: &Sexp) -> String {
    format!("code {}: {}", s.text("code").unwrap_or("?"), s.text("message").unwrap_or_default())
}

fn keepalive() -> Vec<u8> {
    control(&Sexp::obj("keepalive", vec![("id", Sexp::val("0"))]))
}

/// Código do `disconnect` da despedida do cliente, o mesmo que o gateway usa ao encerrar a sessão.
pub const DISCONNECT_CODE: &str = "28";

/// A despedida do túnel: `stop` a pede e `sent` diz se o `disconnect` saiu.
#[derive(Default)]
pub struct Farewell {
    pub stop: Arc<Notify>,
    pub sent: AtomicBool,
}

fn disconnect() -> Vec<u8> {
    control(&Sexp::obj("disconnect", vec![("code", Sexp::val(DISCONNECT_CODE)), ("message", Sexp::val("User disconnected"))]))
}

/// Conduz o túnel até ele cair e devolve o motivo. Pacotes IP fluem entre o stream e o canal da
/// interface, e um `keepalive` sai a cada `interval` e a cada `probe`. Três intervalos seguidos
/// sem resposta ao keepalive derrubam o túnel. `farewell.stop` encerra a sessão: manda o
/// `disconnect`, marca `farewell.sent`, fecha o TLS e termina.
pub async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    mut buf: Vec<u8>,
    interval: Duration,
    probe: Arc<Notify>,
    farewell: Arc<Farewell>,
    to_iface: mpsc::Sender<Vec<u8>>,
    mut from_iface: mpsc::Receiver<Vec<u8>>,
) -> String {
    let deadline = interval * KEEPALIVE_MISSES;
    let mut missed = 0;
    let mut chunk = vec![0u8; 65536];
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        loop {
            match take_frame(&mut buf) {
                // A interface já pode ter sido desfeita no teardown.
                Ok(Some(Frame::Data(p))) => {
                    let _ = to_iface.send(p).await;
                }
                Ok(Some(Frame::Control(s))) if s.name() == Some("disconnect") => {
                    return format!("Tunnel dropped: the gateway ended the session ({})", disconnect_reason(&s));
                }
                Ok(Some(Frame::Control(s))) if s.name() == Some("keepalive") => missed = 0,
                Ok(Some(Frame::Control(_))) => {}
                Ok(None) => break,
                Err(e) => return e,
            }
        }
        // Só `read`, `recv`, `tick` e `notified` dentro do select: podem ser cancelados sem perder dados.
        let out = tokio::select! {
            r = stream.read(&mut chunk) => match r {
                Ok(0) => return "Tunnel dropped: connection closed by the gateway".into(),
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    continue;
                }
                Err(e) => return format!("Tunnel dropped: read failed: {}", e),
            },
            Some(packet) = from_iface.recv() => raw(DATA, &packet),
            _ = tick.tick() => {
                // Com a última resposta logo depois de um tick, a queda sai ~3 intervalos depois dela.
                missed += 1;
                if missed == KEEPALIVE_MISSES {
                    return "Tunnel dropped: no response from the gateway".into();
                }
                keepalive()
            }
            _ = probe.notified() => keepalive(),
            _ = farewell.stop.notified() => {
                if write(&mut stream, &disconnect(), deadline).await.is_ok() {
                    farewell.sent.store(true, Ordering::SeqCst);
                }
                let _ = stream.shutdown().await;
                return "Tunnel closed by the client".into();
            }
        };
        if let Err(e) = write(&mut stream, &out, deadline).await {
            return e;
        }
    }
}

/// Escrita com prazo: num TCP meio aberto um `write_all` sem prazo travaria o laço para sempre.
pub async fn write<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8], deadline: Duration) -> Result<(), String> {
    match tokio::time::timeout(deadline, stream.write_all(data)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("Tunnel dropped: write failed: {}", e)),
        Err(_) => Err("Tunnel dropped: write timed out".into()),
    }
}

/// Um intervalo de endereços em blocos CIDR, do maior alinhado possível em diante. `from` depois
/// de `to` não dá rota.
pub fn range_to_routes(from: Ipv4Addr, to: Ipv4Addr) -> Vec<Route> {
    let (mut start, end) = (u64::from(u32::from(from)), u64::from(u32::from(to)));
    let mut routes = Vec::new();
    while start <= end {
        let mut size = 1u64 << start.trailing_zeros().min(32);
        while start + size - 1 > end {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros();
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        routes.push(Route { addr: Ipv4Addr::from(start as u32), mask: Ipv4Addr::from(mask) });
        start += size;
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routes(from: &str, to: &str) -> Vec<String> {
        range_to_routes(from.parse().unwrap(), to.parse().unwrap()).iter().map(|r| format!("{}/{}", r.addr, r.mask)).collect()
    }

    /// Amostras de `docs/checkpoint-protocol.md`.
    #[test]
    fn ranges_become_the_cidr_blocks_that_cover_them() {
        assert_eq!(routes("10.1.0.0", "10.1.255.255"), ["10.1.0.0/255.255.0.0"]);
        assert_eq!(routes("192.168.50.7", "192.168.50.7"), ["192.168.50.7/255.255.255.255"]);
        assert_eq!(routes("172.16.4.0", "172.16.6.255"), ["172.16.4.0/255.255.254.0", "172.16.6.0/255.255.255.0"]);
        assert_eq!(
            routes("10.0.0.1", "10.0.0.6"),
            ["10.0.0.1/255.255.255.255", "10.0.0.2/255.255.255.254", "10.0.0.4/255.255.255.254", "10.0.0.6/255.255.255.255"]
        );
        assert_eq!(routes("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0.0.0.0"]);
        assert_eq!(routes("255.255.255.255", "255.255.255.255"), ["255.255.255.255/255.255.255.255"]);
        assert!(routes("10.0.0.9", "10.0.0.1").is_empty());
    }

    #[test]
    fn frames_are_taken_only_when_complete() {
        let mut buf = control(&Sexp::obj("keepalive", vec![("id", Sexp::val("0"))]));
        assert_eq!(&buf[4..8], &[0, 0, 0, 1]);
        assert_eq!(buf.last(), Some(&0));
        buf.extend(raw(DATA, &[0x45, 1, 2]));
        let mut partial = buf[..buf.len() - 1].to_vec();
        assert!(matches!(take_frame(&mut partial), Ok(Some(Frame::Control(s))) if s.name() == Some("keepalive")));
        assert!(matches!(take_frame(&mut partial), Ok(None)));
        let mut whole = buf.clone();
        take_frame(&mut whole).unwrap();
        assert!(matches!(take_frame(&mut whole), Ok(Some(Frame::Data(p))) if p == [0x45, 1, 2]));
        assert!(whole.is_empty());
        assert!(take_frame(&mut raw(7, b"x")).is_err());
        assert!(take_frame(&mut vec![0x7f, 0, 0, 0, 0, 0, 0, 2]).is_err());
    }
}
