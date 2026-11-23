//! Gateway Check Point falso em loopback, sobre o apoio comum de `fake_server`. Implementa o canal
//! de controle (`POST /clients/`: informações do servidor, início do login pelo IdP, resposta do
//! desafio, `ClientSettings` com as faixas de rede e signout) e o lado servidor do túnel SSL
//! (`client_hello`, `hello_reply`, quadros de dados, keepalive e `disconnect`). Como o gateway de
//! validação, responde 699 ao `Signout` de uma sessão cujo túnel já foi aberto. As respostas são texto escrito à mão a partir de `docs/checkpoint-protocol.md`;
//! só a leitura dos pedidos e a ofuscação usam o codec do Engine, que tem testes de unidade próprios.
//! Modos novos entram como campos em `CheckpointOptions`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};

use super::fake_gateway::PROFILE_ID;
use super::fake_server::{free_login_port, read_request, CertOptions, TlsServer};
use crate::checkpoint::sexp::{self, Sexp};

pub const LOGIN_OPTION: &str = "vpn_Corp_SSO";
/// URL do IdP que o desafio traz (ofuscada) e que vira o `url` do `waiting-saml`.
pub const IDP_URL: &str = "https://idp.example/sso/start?gw=corp&relay=7779";
/// Código que o navegador entrega no listener e que a resposta do desafio precisa levar.
pub const IDP_CODE: &str = "c0de-Idp_42.Zx9~a";
const AUTH_SESSION: &str = "auth-0042";
const SESSION_ID: &str = "5e55-0001";
/// Chave da sessão que o login entrega (ofuscada) e que o `client_hello` precisa apresentar.
pub const ACTIVE_KEY: &str = "fake-active-key-7f3a";
pub const ASSIGNED_IP: Ipv4Addr = Ipv4Addr::new(10, 20, 30, 40);
pub const DNS: [Ipv4Addr; 2] = [Ipv4Addr::new(10, 1, 0, 53), Ipv4Addr::new(10, 1, 0, 54)];
pub const DNS_SUFFIXES: [&str; 2] = ["corp.example", "lab.example"];
/// O último intervalo não é um bloco CIDR: vira um /23 e um /24.
pub const RANGES: [(&str, &str); 3] = [("10.1.0.0", "10.1.255.255"), ("192.168.50.0", "192.168.50.255"), ("172.16.4.0", "172.16.6.255")];
/// Faixa do próprio gateway (o host do Profile), que o `ClientSettings` também manda e a sessão ignora.
pub const GATEWAY_RANGE: (&str, &str) = ("127.0.0.1", "127.0.0.1");
/// As rotas que os `RANGES` viram, em ordem.
pub const ROUTES: [(&str, &str); 4] =
    [("10.1.0.0", "255.255.0.0"), ("192.168.50.0", "255.255.255.0"), ("172.16.4.0", "255.255.254.0"), ("172.16.6.0", "255.255.255.0")];
pub const AUTH_TIMEOUT: u64 = 43200;

const CONTROL: u32 = 1;
const DATA: u32 = 2;

#[derive(Default, Clone)]
pub struct CheckpointOptions {
    /// Aceita o signout e nunca responde.
    pub mute_logout: bool,
    /// O `hello_reply` anuncia `timeouts` enormes, no limite do u64.
    pub huge_timeouts: bool,
    /// Opções de login como (id, factor_type), no lugar da única opção de IdP `LOGIN_OPTION`.
    pub login_options: Option<Vec<(&'static str, &'static str)>>,
    /// As informações do servidor não oferecem o túnel `SSL`.
    pub no_ssl: bool,
    /// Responde só aos primeiros n keepalives; `Some(0)` nunca responde.
    pub keepalive_answers: Option<usize>,
    /// `timeouts:keepalive` do `hello_reply`, em segundos (padrão 20).
    pub keepalive: Option<u64>,
    /// `timeouts:authentication` do `hello_reply`, em segundos (padrão `AUTH_TIMEOUT`).
    pub auth_timeout: Option<u64>,
    /// Responde ao `UserPass` sem `authn_status`.
    pub no_authn_status: bool,
    /// O `hello_reply` traz os `RANGES` em `range`; o gateway de validação não traz.
    pub hello_range: bool,
    /// Recusa o `ClientSettings` com um retorno diferente de 600.
    pub refuse_client_settings: bool,
    /// Faixas do `ClientSettings` no lugar de `RANGES` + `GATEWAY_RANGE`.
    pub settings_ranges: Option<Vec<(&'static str, &'static str)>>,
}

struct Shared {
    options: CheckpointOptions,
    logouts: AtomicUsize,
    /// Keepalives recebidos pelo túnel.
    keepalives: AtomicUsize,
    close_tunnel: Notify,
    stop_reading: Notify,
    send_disconnect: Notify,
    /// O túnel da sessão chegou ao `hello_reply`.
    tunnel_opened: AtomicBool,
    /// Pedidos do canal de controle e `disconnect` do cliente pelo túnel, na ordem em que chegaram.
    requests: Mutex<Vec<Sexp>>,
    from_client: mpsc::UnboundedSender<Vec<u8>>,
    to_client: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

pub struct FakeCheckpoint {
    pub port: u16,
    /// Porta livre que o teste dá ao Helper no lugar da 7779.
    pub login_port: u16,
    /// sha256 hex do DER do certificado, como em `trusted_certs`.
    pub digest: String,
    shared: Arc<Shared>,
    from_client: tokio::sync::Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    to_client: mpsc::UnboundedSender<Vec<u8>>,
}

impl FakeCheckpoint {
    pub async fn start(options: CheckpointOptions) -> Self {
        let tls = TlsServer::new(CertOptions::default());
        let acceptor = tls.acceptor.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (from_tx, from_rx) = mpsc::unbounded_channel();
        let (to_tx, to_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            options,
            logouts: AtomicUsize::new(0),
            keepalives: AtomicUsize::new(0),
            close_tunnel: Notify::new(),
            stop_reading: Notify::new(),
            send_disconnect: Notify::new(),
            tunnel_opened: AtomicBool::new(false),
            requests: Mutex::new(Vec::new()),
            from_client: from_tx,
            to_client: Mutex::new(Some(to_rx)),
        });
        let s = shared.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (acceptor, s) = (acceptor.clone(), s.clone());
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        handle(tls, s).await;
                    }
                });
            }
        });
        Self { port, login_port: free_login_port(), digest: tls.digest, shared, from_client: tokio::sync::Mutex::new(from_rx), to_client: to_tx }
    }

    /// O Profile Check Point do comando `connect` apontando para este gateway, sem opção de login.
    pub fn profile(&self) -> Value {
        json!({
            "id": PROFILE_ID,
            "engine": "checkpoint",
            "host": "127.0.0.1",
            "port": self.port,
            "auth": "saml",
            "trusted_certs": [self.digest],
            "ignore_cert_errors": false,
        })
    }

    pub fn logouts(&self) -> usize {
        self.shared.logouts.load(Ordering::SeqCst)
    }

    pub fn keepalives(&self) -> usize {
        self.shared.keepalives.load(Ordering::SeqCst)
    }

    /// Fecha o túnel do lado do gateway (close_notify do TLS).
    pub fn close_tunnel(&self) {
        self.shared.close_tunnel.notify_one();
    }

    /// Para de ler o túnel e segura a conexão aberta, como um TCP meio aberto.
    pub fn stop_reading(&self) {
        self.shared.stop_reading.notify_one();
    }

    /// Encerra a sessão pelo túnel com um quadro `disconnect`.
    pub fn send_disconnect(&self) {
        self.shared.send_disconnect.notify_one();
    }

    /// Pedidos do canal de controle e quadros `disconnect` do cliente recebidos até agora.
    pub fn requests(&self) -> Vec<Sexp> {
        self.shared.requests.lock().unwrap().clone()
    }

    /// Manda um pacote IP ao cliente pelo túnel.
    pub fn send_ip(&self, packet: Vec<u8>) {
        self.to_client.send(packet).unwrap();
    }

    /// Próximo pacote IP que o cliente mandou pelo túnel.
    pub async fn recv_ip(&self) -> Vec<u8> {
        let mut rx = self.from_client.lock().await;
        tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("no IP packet reached the gateway").unwrap()
    }
}

/// O canal de controle e o túnel chegam na mesma porta: um pedido HTTP começa com `POST`, o
/// túnel com o tamanho do primeiro quadro.
async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut stream: S, shared: Arc<Shared>) {
    let mut head = [0u8; 4];
    if stream.read_exact(&mut head).await.is_err() {
        return;
    }
    if &head != b"POST" {
        return tunnel(stream, u32::from_be_bytes(head), shared).await;
    }
    let Some(request) = read_request(&mut (&head[..]).chain(&mut stream)).await else { return };
    let body = if request.path == "/clients/" { sexp::parse(&String::from_utf8_lossy(&request.body)).ok() } else { None };
    let Some(body) = body else {
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        return;
    };
    shared.requests.lock().unwrap().push(body.clone());
    let kind = body.text("RequestHeader:type").unwrap_or_default().to_string();
    let reply = match kind.as_str() {
        "ClientHello" => server_info(&shared.options),
        "UserPass" if shared.options.no_authn_status => response("UserPass", "", &format!("\t\t:session_id ({})", AUTH_SESSION)),
        "UserPass" if body.text("RequestData:selectedLoginOption") == Some(LOGIN_OPTION) => response(
            "UserPass",
            "",
            &format!("\t\t:authn_status (continue)\n\t\t:session_id ({})\n\t\t:prompt ({})", AUTH_SESSION, sexp::obfuscate(IDP_URL.as_bytes())),
        ),
        "MultiChallange" => {
            let code = body.text("RequestData:user_input").and_then(|v| sexp::deobfuscate(v).ok());
            let ok = body.text("RequestHeader:session_id") == Some(AUTH_SESSION)
                && body.text("RequestData:auth_session_id") == Some(AUTH_SESSION)
                && code.as_deref() == Some(IDP_CODE.as_bytes());
            let data = if ok {
                format!(
                    "\t\t:authn_status (done)\n\t\t:is_authenticated (true)\n\t\t:active_key ({})\n\t\t:session_id ({})\n\t\t:active_key_timeout ({})",
                    sexp::obfuscate(ACTIVE_KEY.as_bytes()),
                    SESSION_ID,
                    AUTH_TIMEOUT
                )
            } else {
                format!("\t\t:authn_status (done)\n\t\t:is_authenticated (false)\n\t\t:error_message ({})", sexp::obfuscate(b"Authentication failed"))
            };
            response("MultiChallange", AUTH_SESSION, &data)
        }
        "ClientSettings" if !shared.options.refuse_client_settings && body.text("RequestHeader:session_id") == Some(SESSION_ID) => {
            let ranges = shared.options.settings_ranges.clone().unwrap_or_else(|| RANGES.iter().copied().chain([GATEWAY_RANGE]).collect());
            let settings: String =
                ranges.iter().map(|(from, to)| format!("\n\t\t\t\t: (\n\t\t\t\t\t:from ({})\n\t\t\t\t\t:to ({}))", from, to)).collect();
            response(
                "ClientSettings",
                SESSION_ID,
                &format!("\t\t:gw_internal_ip (10.1.0.1)\n\t\t:updated_policies (\n\t\t\t:range (\n\t\t\t\t:settings ({})\n\t\t\t\t:name (range)))", settings),
            )
        }
        "ClientSettings" => response("ClientSettings", SESSION_ID, "").replace(":return_code (600)", ":return_code (1)"),
        "Signout" if body.text("RequestHeader:session_id") == Some(SESSION_ID) => {
            shared.logouts.fetch_add(1, Ordering::SeqCst);
            if shared.options.mute_logout {
                let _ = stream.read(&mut [0u8; 1]).await; // segura a conexão até o cliente desistir
                return;
            }
            let signout = response("Signout", SESSION_ID, "");
            // O gateway de validação responde 699 ao Signout depois do túnel: a sessão já acabou.
            if shared.tunnel_opened.load(Ordering::SeqCst) {
                signout.replace(":return_code (600)", ":return_code (699)")
            } else {
                signout
            }
        }
        _ => response(&kind, "", "\t\t:authn_status (failed)"),
    };
    let http = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", reply.len(), reply);
    let _ = stream.write_all(http.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn response(kind: &str, session_id: &str, data: &str) -> String {
    let data = if data.is_empty() { "()".to_string() } else { format!("(\n{})", data) };
    format!(
        "(CCCserverResponse\n\t:ResponseHeader (\n\t\t:id (1)\n\t\t:type ({})\n\t\t:session_id ({})\n\t\t:return_code (600))\n\t:ResponseData {})\n",
        kind, session_id, data
    )
}

fn server_info(options: &CheckpointOptions) -> String {
    let login_options = options.login_options.clone().unwrap_or_else(|| vec![(LOGIN_OPTION, "identity_provider")]);
    let list: String = login_options
        .iter()
        .enumerate()
        .map(|(i, (id, factor))| {
            format!(
                "\n\t\t\t\t:{} (\n\t\t\t\t\t:id ({})\n\t\t\t\t\t:display_name (\"{}\")\n\t\t\t\t\t:show_realm (1)\n\
                 \t\t\t\t\t:factors (\n\t\t\t\t\t\t:0 (\n\t\t\t\t\t\t\t:factor_type ({}))))",
                i, id, id, factor
            )
        })
        .collect();
    let protocols = if options.no_ssl { "\n\t\t\t\t: (IPSec)\n\t\t\t\t: (L2TP)" } else { "\n\t\t\t\t: (IPSec)\n\t\t\t\t: (SSL)\n\t\t\t\t: (L2TP)" };
    response(
        "ClientHello",
        "",
        &format!(
            "\t\t:protocol_version (\n\t\t\t:protocol_version (100))\n\
             \t\t:connectivity_info (\n\t\t\t:client_enabled (true)\n\
             \t\t\t:supported_data_tunnel_protocols ({})\n\
             \t\t\t:tcpt_port (443)\n\t\t\t:natt_port (4500))\n\
             \t\t:login_options_data (\n\t\t\t:login_options_list ({})\n\
             \t\t\t:login_options_md5 (00112233445566778899aabbccddeeff))",
            protocols, list
        ),
    )
}

fn hello_reply(options: &CheckpointOptions) -> String {
    let (auth, keepalive) =
        if options.huge_timeouts { (u64::MAX, u64::MAX) } else { (options.auth_timeout.unwrap_or(AUTH_TIMEOUT), options.keepalive.unwrap_or(20)) };
    let ranges: String = RANGES.iter().map(|(from, to)| format!("\n\t\t: (\n\t\t\t:from ({})\n\t\t\t:to ({}))", from, to)).collect();
    // Como no gateway de validação, sem `range` por padrão.
    let range = if options.hello_range { format!("\t:range ({})\n", ranges) } else { String::new() };
    format!(
        "(hello_reply\n\t:version (1)\n\t:protocol_version (1)\n\
         \t:OM (\n\t\t:ipaddr ({})\n\t\t:dns_servers (\n\t\t\t: ({})\n\t\t\t: ({}))\n\t\t:dns_suffix (\"{}\"))\n\
         {}\
         \t:timeouts (\n\t\t:authentication ({})\n\t\t:keepalive ({}))\n\
         \t:optional (\n\t\t:subnet (255.255.255.0)))",
        ASSIGNED_IP,
        DNS[0],
        DNS[1],
        DNS_SUFFIXES.join(","),
        range,
        auth,
        keepalive
    )
}

fn frame(kind: u32, payload: &[u8]) -> Vec<u8> {
    [&(payload.len() as u32).to_be_bytes()[..], &kind.to_be_bytes(), payload].concat()
}

fn control(text: &str) -> Vec<u8> {
    frame(CONTROL, &[text.as_bytes(), b"\0"].concat())
}

async fn read_frame<R: AsyncRead + Unpin>(rd: &mut R, len: u32) -> Option<(u32, Vec<u8>)> {
    let mut kind = [0u8; 4];
    rd.read_exact(&mut kind).await.ok()?;
    let mut payload = vec![0u8; len as usize];
    rd.read_exact(&mut payload).await.ok()?;
    Some((u32::from_be_bytes(kind), payload))
}

/// Lado servidor do túnel: o primeiro quadro é o `client_hello` com a chave da sessão.
async fn tunnel<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, first_len: u32, shared: Arc<Shared>) {
    let (mut rd, mut wr) = tokio::io::split(stream);
    let Some((CONTROL, hello)) = read_frame(&mut rd, first_len).await else { return };
    let hello = sexp::parse(&String::from_utf8_lossy(&hello)).expect("client_hello is not an S-expression");
    assert_eq!(hello.name(), Some("client_hello"), "first tunnel frame");
    if hello.text("cookie") != Some(ACTIVE_KEY) {
        let _ = wr.write_all(&control("(disconnect\n\t:code (201)\n\t:message (\"Authentication failed\"))")).await;
        return;
    }
    let _ = wr.write_all(&control(&hello_reply(&shared.options))).await;
    shared.tunnel_opened.store(true, Ordering::SeqCst);

    let (frames_tx, mut frames) = mpsc::unbounded_channel::<(u32, Vec<u8>)>();
    let reader = shared.clone();
    tokio::spawn(async move {
        loop {
            let mut len = [0u8; 4];
            tokio::select! {
                r = rd.read_exact(&mut len) => if r.is_err() {
                    return;
                },
                // Segura o stream aberto e nunca mais lê.
                _ = reader.stop_reading.notified() => std::future::pending::<()>().await,
            }
            let Some(f) = read_frame(&mut rd, u32::from_be_bytes(len)).await else { return };
            if frames_tx.send(f).is_err() {
                return;
            }
        }
    });
    let mut to_client = shared.to_client.lock().unwrap().take().expect("one tunnel at a time");
    loop {
        tokio::select! {
            f = frames.recv() => match f {
                Some((DATA, packet)) => { let _ = shared.from_client.send(packet); }
                Some((CONTROL, text)) => {
                    let text = sexp::parse(&String::from_utf8_lossy(&text)).expect("control frame is not an S-expression");
                    if text.name() == Some("disconnect") {
                        shared.requests.lock().unwrap().push(text);
                    } else if text.name() == Some("keepalive") {
                        let n = shared.keepalives.fetch_add(1, Ordering::SeqCst);
                        if shared.options.keepalive_answers.is_none_or(|answers| n < answers) {
                            let _ = wr.write_all(&control("(keepalive\n\t:id (0))")).await;
                        }
                    }
                }
                Some((kind, _)) => panic!("unknown frame type {} from client", kind),
                None => break,
            },
            Some(p) = to_client.recv() => { let _ = wr.write_all(&frame(DATA, &p)).await; }
            _ = shared.close_tunnel.notified() => {
                let _ = wr.shutdown().await;
                break;
            }
            _ = shared.send_disconnect.notified() => {
                let _ = wr.write_all(&control("(disconnect\n\t:code (28)\n\t:message (\"Session terminated\"))")).await;
            }
        }
    }
    *shared.to_client.lock().unwrap() = Some(to_client);
}
