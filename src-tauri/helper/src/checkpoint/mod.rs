//! Engine Check Point: túnel SSL com login pelo IdP. Canal de controle "CCC" em HTTPS com corpo em
//! S-expression, listener local para o código do IdP e o túnel em `slim`. O protocolo está em
//! `docs/checkpoint-protocol.md`.

pub mod sexp;
pub(crate) mod slim;
#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Notify};

use crate::browser_login;
use crate::engine::{self, Credentials, LoginError, Tuning, Tunnel, Waiting};
use crate::http;
use crate::net::{Packets, Route, TunnelConfig};
use crate::profile::{Auth, Profile};
use crate::tls::GatewayTls;
use crate::LogFn;
use sexp::Sexp;

/// Porta fixa para onde o portal do gateway manda o navegador entregar o código do IdP.
const LOGIN_PORT: u16 = 7779;
/// Espera pelo login no navegador; o mesmo prazo do snx-rs.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(120);
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
/// Sem MTU no `hello_reply`, o mesmo valor do snx-rs.
// shortcut: MTU fixo, sem campo conhecido no `hello_reply`, confirmar no gateway real (#52).
const DEFAULT_MTU: u16 = 1350;
/// Sem `keepalive` no `hello_reply` (**inf**).
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(20);
/// Tetos dos `timeouts` do `hello_reply`, para um valor absurdo do gateway não estourar a conta do prazo.
const MAX_KEEPALIVE_SECS: u64 = 3600;
const MAX_AUTH_TIMEOUT_SECS: u64 = 30 * 24 * 3600;
/// Teto da mensagem de erro do gateway que entra na razão do `disconnected`.
const MAX_ERROR_MESSAGE: usize = 200;
/// Família de cliente que o canal de controle espera (o Endpoint Security VPN); não é o sistema.
const CLIENT_TYPE: &str = "TRAC";
/// Retorno de sucesso no cabeçalho das respostas do canal de controle.
const RETURN_OK: &str = "600";
/// Retorno do `Signout` depois da despedida pelo túnel: a sessão já não existe no gateway.
const RETURN_SIGNED_OUT: &str = "699";
const MAX_LOGIN_OPTION_LEN: usize = 64;
/// Tetos das faixas de rede anunciadas e das rotas que elas viram.
const MAX_RANGES: usize = 1024;
const MAX_ROUTES: usize = 4096;
/// O formato do código é **inf**: aceita o que cabe num caminho de URL sem escape, com folga no tamanho.
const MAX_CODE: usize = 1024;

/// A sessão do gateway depois do login. Sem `Debug` de propósito: guarda a chave da sessão.
struct GatewaySession {
    id: String,
    /// `active_key` já desofuscada; vai no `client_hello`.
    key: String,
}

/// Resposta de um passo do login.
enum Step {
    /// O gateway pede o código do IdP: sessão de autenticação e URL a abrir no navegador.
    Challenge { auth_session: String, url: String },
    Done(GatewaySession),
}

/// O Engine Check Point de um `connect`: o gateway do Profile e, depois do login, a sessão dele.
pub struct CheckPoint {
    host: String,
    /// Porta do Profile, para o canal de controle e o túnel.
    // shortcut: ignora o `tcpt_port` das informações do servidor, confirmar no gateway real (#52).
    port: u16,
    /// Id da opção de login do Profile; vazio usa a única opção de IdP.
    login_option: String,
    tls: Arc<GatewayTls>,
    login_port: u16,
    login_timeout: Duration,
    keepalive: Option<Duration>,
    next_id: AtomicU32,
    session: Option<GatewaySession>,
    /// A despedida do túnel aberto, que o `logout` consulta.
    farewell: Arc<slim::Farewell>,
    log: LogFn,
}

impl CheckPoint {
    pub fn new(profile: &Profile, tls: Arc<GatewayTls>, log: LogFn, tuning: Tuning) -> Result<Self, String> {
        if profile.auth != Auth::Saml {
            return Err("Check Point profiles sign in only through the identity provider (auth saml)".into());
        }
        let login_option = profile.realm.clone().unwrap_or_default();
        if login_option.len() > MAX_LOGIN_OPTION_LEN || !login_option.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) {
            return Err("Invalid login option".into());
        }
        Ok(Self {
            host: profile.host.clone(),
            port: profile.port,
            login_option,
            tls,
            login_port: tuning.login_port.unwrap_or(LOGIN_PORT),
            login_timeout: tuning.login_timeout.unwrap_or(LOGIN_TIMEOUT),
            keepalive: tuning.keepalive,
            next_id: AtomicU32::new(1),
            session: None,
            farewell: Arc::default(),
            log,
        })
    }

    /// Um pedido do canal de controle; devolve o `ResponseData` de uma resposta com retorno 600.
    async fn request(&self, kind: &str, session_id: &str, data: Sexp) -> Result<Sexp, String> {
        let reply = self.reply(kind, session_id, data).await?;
        let code = return_code(&reply);
        if code != RETURN_OK {
            return Err(refused(kind, code));
        }
        reply.get("ResponseData").cloned().ok_or_else(|| format!("Gateway answer to {} has no data", kind))
    }

    /// A `CCCserverResponse` inteira de um pedido, com qualquer retorno.
    async fn reply(&self, kind: &str, session_id: &str, data: Sexp) -> Result<Sexp, String> {
        tokio::time::timeout(STEP_TIMEOUT, self.exchange(kind, session_id, data))
            .await
            .map_err(|_| format!("Gateway request {} timed out", kind))?
    }

    async fn exchange(&self, kind: &str, session_id: &str, data: Sexp) -> Result<Sexp, String> {
        let mut header = vec![
            ("id", Sexp::val(self.next_id.fetch_add(1, Ordering::Relaxed).to_string())),
            ("type", Sexp::val(kind)),
            ("session_id", Sexp::val(session_id)),
        ];
        if matches!(kind, "Signout" | "ClientSettings") {
            header.push(("protocol_version", Sexp::val("100")));
        }
        let body = Sexp::obj("CCCclientRequest", vec![("RequestHeader", Sexp::obj("", header)), ("RequestData", data)]).encode();
        let req = format!(
            "POST /clients/ HTTP/1.1\r\nHost: {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http::host_header(&self.host, self.port),
            body.len(),
            body
        );
        let mut stream = self.tls.connect().await?;
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("Gateway request {} failed: {}", kind, e))?;
        let resp = http::read_response(&mut stream).await.map_err(|e| format!("Gateway request {} failed: {}", kind, e))?;
        if resp.status != 200 {
            return Err(format!("Gateway refused the request {} (HTTP {})", kind, resp.status));
        }
        let reply = sexp::parse(&String::from_utf8_lossy(&resp.body)).map_err(|e| format!("Invalid gateway answer to {}: {}", kind, e))?;
        if reply.name() != Some("CCCserverResponse") {
            return Err(format!("Invalid gateway answer to {}: not a CCCserverResponse", kind));
        }
        Ok(reply)
    }

    /// Escolhe a opção de login nas informações do servidor; falha se o gateway não oferece o túnel SSL.
    fn choose_login_option(&self, info: &Sexp) -> Result<String, String> {
        let protocols = info.get("connectivity_info:supported_data_tunnel_protocols").map(Sexp::children).unwrap_or_default();
        if !protocols.iter().any(|p| matches!(p, Sexp::Value(v) if v == "SSL")) {
            return Err("The gateway does not offer the SSL tunnel".into());
        }
        let options = info.get("login_options_data:login_options_list").map(Sexp::children).unwrap_or_default();
        let is_idp = |o: &Sexp| o.get("factors").is_some_and(|f| f.children().iter().any(|f| f.text("factor_type") == Some("identity_provider")));
        let ids = |list: &[&Sexp]| list.iter().filter_map(|o| o.text("id")).collect::<Vec<_>>().join(", ");
        if !self.login_option.is_empty() {
            return match options.iter().find(|o| o.text("id") == Some(&self.login_option)) {
                Some(o) if is_idp(o) => Ok(self.login_option.clone()),
                Some(_) => Err(format!("Login option {} is not an identity provider login", self.login_option)),
                None => Err(format!("The gateway has no login option {}; available: {}", self.login_option, ids(&options))),
            };
        }
        let idp: Vec<&Sexp> = options.into_iter().filter(|o| is_idp(o)).collect();
        match idp.as_slice() {
            [one] => one.text("id").map(str::to_string).ok_or_else(|| "Login option without an id".into()),
            [] => Err("The gateway offers no identity provider login".into()),
            several => Err(format!("The gateway offers several identity provider logins; set the login option to one of: {}", ids(several))),
        }
    }

    /// Lê a resposta de um passo do login. Só a recusa explícita do gateway é `Refused`.
    fn auth_step(data: &Sexp) -> Result<Step, LoginError> {
        let session_id = data.text("session_id").unwrap_or_default().to_string();
        let reveal = |path: &str| data.text(path).and_then(|v| sexp::deobfuscate(v).ok()).map(|v| String::from_utf8_lossy(&v).into_owned());
        match data.text("authn_status") {
            Some("continue") => match reveal("prompt") {
                Some(url) if url.starts_with("https://") => Ok(Step::Challenge { auth_session: session_id, url }),
                _ => Err(LoginError::Failed("The gateway asked for a login step other than the identity provider".into())),
            },
            Some("done") if data.text("is_authenticated") == Some("true") => match reveal("active_key").filter(|k| !k.is_empty()) {
                Some(key) => Ok(Step::Done(GatewaySession { id: session_id, key })),
                None => Err(LoginError::Failed("The gateway returned no session key".into())),
            },
            Some("done") => Err(LoginError::Refused(format!(
                "Login failed: {}",
                reveal("error_message")
                    .map(|m| m.chars().filter(|c| !c.is_control()).take(MAX_ERROR_MESSAGE).collect::<String>())
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| "the gateway refused the login".into())
            ))),
            _ => Err(LoginError::Failed("Unexpected gateway answer to the login".into())),
        }
    }

    /// Segundos de `timeouts:<name>` do `hello_reply`: 0 ou ausente é None, acima de `max` vira
    /// `max` e ilegível é ignorado, os dois últimos com log.
    fn timeout_secs(&self, reply: &Sexp, name: &str, max: u64) -> Option<u64> {
        let text = reply.text(&format!("timeouts:{}", name))?;
        match text.parse::<u64>() {
            Ok(0) => None,
            Ok(secs) if secs <= max => Some(secs),
            Ok(secs) => {
                (self.log)(format!("gateway {} timeout of {} s capped at {} s", name, secs, max));
                Some(max)
            }
            Err(_) => {
                (self.log)(format!("ignoring invalid gateway {} timeout", name));
                None
            }
        }
    }

    fn client_hello(&self, key: &str) -> Sexp {
        Sexp::obj(
            "client_hello",
            vec![
                ("client_version", Sexp::val("2")),
                ("protocol_version", Sexp::val("2")),
                ("OM", Sexp::obj("", vec![("ipaddr", Sexp::val("0.0.0.0")), ("keep_address", Sexp::val("false"))])),
                ("optional", Sexp::obj("", vec![("client_type", Sexp::val("4"))])),
                ("cookie", Sexp::val(key)),
            ],
        )
    }
}

/// O código de uma linha `GET /<código> HTTP/1.x`, só com caracteres de URL sem escape especial.
fn extract_code(request_line: &str) -> Option<String> {
    let code = request_line.strip_prefix("GET /")?.split(' ').next()?;
    let valid = !code.is_empty() && code.len() <= MAX_CODE && code.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~%=+".contains(&b));
    valid.then(|| code.to_string())
}

/// Pedido `ClientSettings` das políticas atuais; a lista `range` vazia pede as faixas da rede.
fn settings_request() -> Sexp {
    Sexp::obj("ClientSettings", vec![("requested_policies_and_current_versions", Sexp::obj("", vec![("range", Sexp::val(""))]))])
}

/// Faixas `from`/`to` de uma lista, ignorando as ilegíveis.
fn range_list(node: Option<&Sexp>) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    node.map(Sexp::children).unwrap_or_default().iter().filter_map(|r| Some((r.text("from")?.parse().ok()?, r.text("to")?.parse().ok()?))).collect()
}

/// Rotas das faixas, na ordem e sem repetir bloco. Faixa que começa em 0.0.0.0/8 sai com log, como
/// nos clientes de referência: seria um túnel completo disfarçado. Acima dos tetos é erro.
fn range_routes(ranges: &[(Ipv4Addr, Ipv4Addr)], log: &LogFn) -> Result<Vec<Route>, String> {
    if ranges.len() > MAX_RANGES {
        return Err(format!("The gateway announced {} network ranges, more than the limit of {}", ranges.len(), MAX_RANGES));
    }
    let mut seen = HashSet::new();
    let mut routes = Vec::new();
    for (from, to) in ranges {
        if from.octets()[0] == 0 {
            log(format!("ignoring advertised range {}-{}: it starts in 0.0.0.0/8", from, to));
            continue;
        }
        routes.extend(slim::range_to_routes(*from, *to).into_iter().filter(|r| seen.insert((r.addr, r.mask))));
        if routes.len() > MAX_ROUTES {
            return Err(format!("The gateway network ranges make more than {} routes", MAX_ROUTES));
        }
    }
    Ok(routes)
}

/// Servidores de uma lista de valores IPv4, ignorando o que não for endereço.
fn addresses(node: Option<&Sexp>) -> Vec<Ipv4Addr> {
    node.map(Sexp::children).unwrap_or_default().iter().filter_map(|v| if let Sexp::Value(v) = v { v.parse().ok() } else { None }).collect()
}

/// Sufixos DNS: um valor com vírgulas ou `;`, ou uma lista de valores.
fn suffixes(node: Option<&Sexp>) -> Vec<String> {
    let values: Vec<String> = match node {
        Some(Sexp::Value(v)) => vec![v.clone()],
        Some(list) => list.children().iter().filter_map(|v| if let Sexp::Value(v) = v { Some(v.clone()) } else { None }).collect(),
        None => Vec::new(),
    };
    values.iter().flat_map(|v| v.split([',', ';'])).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
}

impl engine::Engine for CheckPoint {
    async fn login(&mut self, _credentials: &Credentials, waiting: &(dyn Fn(Waiting) + Sync)) -> Result<(), LoginError> {
        use LoginError::Failed;
        let client_info = Sexp::obj(
            "",
            vec![("client_info", Sexp::obj("", vec![("client_type", Sexp::val(CLIENT_TYPE)), ("client_version", Sexp::val("1")), ("client_support_saml", Sexp::val("true"))]))],
        );
        let info = self.request("ClientHello", "", client_info).await.map_err(Failed)?;
        let option = self.choose_login_option(&info).map_err(Failed)?;

        // O Engine se declara como é: cliente macOS (ver a doc de protocolo).
        let identity = Sexp::obj(
            "",
            vec![("client_name", Sexp::val("VPN Connect")), ("client_ver", Sexp::val(env!("CARGO_PKG_VERSION"))), ("os_name", Sexp::val("macOS"))],
        );
        let start = Sexp::obj(
            "",
            vec![
                ("client_type", Sexp::val(CLIENT_TYPE)),
                ("username", Sexp::val(sexp::obfuscate(b""))),
                ("password", Sexp::val(sexp::obfuscate(b""))),
                ("client_logging_data", identity),
                ("selectedLoginOption", Sexp::val(option)),
            ],
        );
        let step = Self::auth_step(&self.request("UserPass", "", start).await.map_err(Failed)?)?;
        let (auth_session, url) = match step {
            Step::Challenge { auth_session, url } => (auth_session, url),
            Step::Done(session) => {
                self.session = Some(session);
                return Ok(());
            }
        };

        let listener = browser_login::listen(self.login_port, "Check Point Endpoint Security or snx-rs").await.map_err(Failed)?;
        waiting(Waiting::Browser(url));
        let code = tokio::time::timeout(self.login_timeout, browser_login::wait_for(listener, extract_code))
            .await
            .map_err(|_| Failed(format!("Identity provider login timed out after {} s", self.login_timeout.as_secs_f32())))?
            .map_err(Failed)?;

        let answer = Sexp::obj(
            "",
            vec![
                ("client_type", Sexp::val(CLIENT_TYPE)),
                ("auth_session_id", Sexp::val(auth_session.clone())),
                ("user_input", Sexp::val(sexp::obfuscate(code.as_bytes()))),
            ],
        );
        // "MultiChallange" é a grafia do protocolo.
        match Self::auth_step(&self.request("MultiChallange", &auth_session, answer).await.map_err(Failed)?)? {
            Step::Done(session) => {
                self.session = Some(session);
                Ok(())
            }
            Step::Challenge { .. } => Err(Failed("The gateway asked for another login step after the identity provider".into())),
        }
    }

    /// Abre o túnel SSL, apresenta a chave da sessão, lê a rede do `hello_reply` e pede as faixas
    /// de rede com `ClientSettings`.
    async fn open_tunnel(&self, login_started: DateTime<Utc>) -> Result<(TunnelConfig, Packets, Tunnel), String> {
        let session = self.session.as_ref().ok_or("Not logged in")?;
        let mut stream = tokio::time::timeout(STEP_TIMEOUT, self.tls.connect()).await.map_err(|_| "Tunnel connection timed out".to_string())??;
        let gateway = stream.get_ref().0.peer_addr().map_err(|e| e.to_string())?.ip();
        slim::write(&mut stream, &slim::control(&self.client_hello(&session.key)), STEP_TIMEOUT).await?;
        let mut buf = Vec::new();
        let reply = tokio::time::timeout(STEP_TIMEOUT, slim::read_control(&mut stream, &mut buf))
            .await
            .map_err(|_| "Tunnel hello timed out".to_string())??;
        match reply.name() {
            Some("hello_reply") => {}
            Some("disconnect") => return Err(format!("Gateway refused the tunnel ({})", slim::disconnect_reason(&reply))),
            other => return Err(format!("Unexpected tunnel answer {:?}", other)),
        }
        let ip: Ipv4Addr = reply.text("OM:ipaddr").and_then(|v| v.parse().ok()).ok_or("The gateway assigned no tunnel address")?;
        // O gateway de validação não manda `range` no `hello_reply`: as faixas vêm do `ClientSettings`.
        // Se ele falhar sem `range` no hello, o túnel falha: sem rota ele pareceria conectado e não passaria nada.
        let mut ranges = range_list(reply.get("range"));
        match self.request("ClientSettings", &session.id, settings_request()).await {
            Ok(data) => ranges.extend(range_list(data.get("updated_policies:range:settings"))),
            Err(e) if !ranges.is_empty() => (self.log)(format!("using the hello_reply ranges only: {}", e)),
            Err(e) => return Err(format!("Could not get the network ranges from the gateway: {}", e)),
        }
        let routes = range_routes(&ranges, &self.log)?;
        if routes.is_empty() {
            return Err("The gateway announced no network ranges for the tunnel".into());
        }
        let auth_timeout = self.timeout_secs(&reply, "authentication", MAX_AUTH_TIMEOUT_SECS);
        let keepalive = self.timeout_secs(&reply, "keepalive", MAX_KEEPALIVE_SECS).map_or(DEFAULT_KEEPALIVE, Duration::from_secs);
        let keepalive = self.keepalive.unwrap_or(keepalive);

        let (to_iface, rx) = mpsc::channel(256);
        let (tx, from_iface) = mpsc::channel(256);
        let probe = Arc::new(Notify::new());
        let task = tokio::spawn(slim::run(stream, buf, keepalive, probe.clone(), self.farewell.clone(), to_iface, from_iface));
        let config = TunnelConfig {
            gateway,
            ip,
            // O protocolo não dá endereço de par.
            peer: ip,
            dns_servers: addresses(reply.get("OM:dns_servers")),
            dns_suffixes: suffixes(reply.get("OM:dns_suffix")),
            routes,
            full_tunnel: false,
            mtu: DEFAULT_MTU,
            expires_at: auth_timeout.map(|s| login_started + chrono::Duration::seconds(s as i64)),
        };
        Ok((config, Packets { tx, rx }, Tunnel::new(task, probe).with_stop(self.farewell.stop.clone())))
    }

    async fn logout(&self) -> Result<(), String> {
        let session = self.session.as_ref().ok_or("Not logged in")?;
        let reply = self.reply("Signout", &session.id, Sexp::val("")).await?;
        match return_code(&reply) {
            RETURN_OK => Ok(()),
            // Depois do `disconnect` pelo túnel o gateway de validação responde 699, como o snx-rs e o
            // cpyvpn também viam. Sem a despedida (túnel que não abriu, cancelamento) o 699 segue erro.
            code @ RETURN_SIGNED_OUT if self.farewell.sent.load(Ordering::SeqCst) => {
                (self.log)(format!("Signout answered with return code {}: the tunnel disconnect already ended the session", code));
                Ok(())
            }
            code => Err(refused("Signout", code)),
        }
    }
}

fn return_code(reply: &Sexp) -> &str {
    reply.text("ResponseHeader:return_code").unwrap_or_default()
}

fn refused(kind: &str, code: &str) -> String {
    format!("Gateway answered the request {} with return code {:?}", kind, code)
}
