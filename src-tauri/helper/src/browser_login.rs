//! Listener local do login pelo navegador externo: recebe o valor que o gateway manda o
//! navegador entregar em `127.0.0.1:<porta>`. O que conta como entrega válida é de cada Engine.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};

/// Prazo de cada conexão para mandar o cabeçalho; a pré-conexão vazia do navegador cai nele.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST: usize = 8192;
const MAX_CONNECTIONS: usize = 16;

const DONE_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>VPN login</title></head>\
<body style=\"font-family:sans-serif;text-align:center;margin-top:4em\">\
<h2>Login complete</h2><p>You can close this tab and return to the app.</p></body></html>";
const INVALID_PAGE: &str = "<!doctype html><html><body><h2>Invalid login response</h2></body></html>";

/// Escuta só em loopback, nunca em 0.0.0.0. `holder` é o exemplo de app que costuma ocupar a porta.
pub async fn listen(port: u16, holder: &str) -> Result<TcpListener, String> {
    TcpListener::bind(("127.0.0.1", port)).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => format!(
            "Local SSO port {} is already in use; close the app using it (e.g. {}) and try again",
            port, holder
        ),
        _ => format!("Cannot listen on 127.0.0.1:{}: {}", port, e),
    })
}

/// Espera um pedido cuja linha `accept` aceite, responde 200 ao navegador e devolve o que
/// `accept` extraiu. Conexões vazias (o navegador abre algumas antes da real) são fechadas sem
/// resposta; qualquer outro pedido recebe 400 e o listener segue escutando, para que uma página
/// qualquer apontando para a porta não derrube o login. O listener fecha quando a função volta.
pub async fn wait_for(listener: TcpListener, accept: fn(&str) -> Option<String>) -> Result<String, String> {
    let (tx, mut rx) = mpsc::channel::<(TcpStream, String)>(4);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        tokio::select! {
            Ok((stream, _)) = listener.accept() => {
                // Acima do limite a conexão nova é fechada: um processo local não esgota os fds do Helper.
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                let tx = tx.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    let Ok(Some((mut stream, line))) = tokio::time::timeout(REQUEST_TIMEOUT, read_head(stream)).await else { return };
                    match accept(&line) {
                        Some(value) => { let _ = tx.send((stream, value)).await; }
                        None => respond(&mut stream, "400 Bad Request", INVALID_PAGE).await,
                    }
                });
            }
            Some((mut stream, value)) = rx.recv() => {
                respond(&mut stream, "200 OK", DONE_PAGE).await;
                return Ok(value);
            }
        }
    }
}

async fn respond(stream: &mut TcpStream, status: &str, page: &str) {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        page.len(),
        page
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Lê o cabeçalho inteiro (fechar com dados não lidos faria o navegador ver um reset) e
/// devolve a linha do pedido. None em conexão vazia, grande demais ou sem texto.
async fn read_head(mut stream: TcpStream) -> Option<(TcpStream, String)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 || buf.len() + n > MAX_REQUEST {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = String::from_utf8(buf).ok()?.lines().next()?.to_string();
    Some((stream, line))
}
