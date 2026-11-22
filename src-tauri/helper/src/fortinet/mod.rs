//! Engine Fortinet SSL VPN: login HTTP, `fortisslvpn_xml`, túnel TLS e PPP.
//! O protocolo está descrito em `docs/fortinet-protocol.md`.

mod ppp;
mod saml;
mod xml;

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::browser_login;
use crate::http;
use crate::engine::{self, Credentials, LoginError, Tuning, Tunnel, Waiting};
use crate::net::{Packets, TunnelConfig};
use crate::profile::{Auth, Profile};
use crate::tls::GatewayTls;
use crate::LogFn;

const DEFAULT_MTU: u16 = 1354;
const STEP_TIMEOUT: Duration = Duration::from_secs(15);
/// Prazo da aprovação do push. Que o gateway segure a resposta até a aprovação é inferência
/// (ver `docs/fortinet-protocol.md`); os 60 s são escolha nossa, não do protocolo.
const PUSH_TIMEOUT: Duration = Duration::from_secs(60);
/// Intervalo do LCP Echo-Request com o túnel de pé; 3 sem resposta = túnel morto (~30 s).
pub const ECHO_INTERVAL: Duration = Duration::from_secs(10);
/// Alguns gateways (o do CNJ) fecham a conexão do `logincheck` sem `User-Agent`; é o mesmo do openfortivpn.
const USER_AGENT: &str = "Mozilla/5.0 SV1";
/// Valores do pedido de token que o segundo passo do login devolve ao gateway.
const CHALLENGE_FIELDS: [&str; 6] = ["reqid", "polid", "grp", "portal", "peer", "magic"];
// shortcut: sem `sso_port` e `remoteauthtimeout` no `/remote/info` valem 8020 e 120 s, os do gateway testado; trocar por erro se aparecer gateway com outros valores e sem os campos.
const DEFAULT_SSO_PORT: u16 = 8020;
const DEFAULT_SAML_TIMEOUT: u64 = 120;
/// Passo comum do FortiClient depois do SAML: `logincheck` sem credencial.
const SAML_LOGINCHECK: &str = "username=&credential=&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1";

const MAX_REALM_LEN: usize = 64;

/// O gateway pediu o segundo fator (OTP ou push) no primeiro passo do login.
struct Challenge {
    fields: Vec<(&'static str, String)>,
    /// O gateway oferece aprovação por push do FortiToken Mobile.
    push: bool,
}

/// Resultado do primeiro passo do login.
enum Login {
    Cookie(String),
    Challenge(Challenge),
}

/// Valor do cabeçalho `Cookie` com o cookie de sessão.
fn svpn_header(cookie: &str) -> String {
    format!("SVPNCOOKIE={}", cookie)
}

/// O `SVPNCOOKIE` de uma resposta; vazio conta como ausente (é como o gateway o apaga).
fn session_cookie(resp: &http::Response) -> Option<String> {
    resp.cookie("SVPNCOOKIE").filter(|c| !c.is_empty())
}

/// Número de um atributo `nome='valor'` (ou com aspas duplas) no corpo do `/remote/info`.
fn info_number(body: &str, name: &str) -> Option<u64> {
    let rest = body.split(&format!("{}=", name)).nth(1)?.trim_start_matches(['\'', '"']);
    rest.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok().filter(|n| *n > 0)
}

/// Pares `chave=valor` do corpo do `logincheck`, separados por vírgula.
// shortcut: valor com vírgula vem truncado, trocar por um parser de verdade se um campo do desafio passar a levar vírgula.
fn parse_pairs(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// O Engine Fortinet de um `connect`: o gateway do Profile e, depois do login, o cookie da sessão.
pub struct Fortinet {
    host: String,
    port: u16,
    auth: Auth,
    username: String,
    realm: String,
    tls: Arc<GatewayTls>,
    log: LogFn,
    push_timeout: Duration,
    echo_interval: Duration,
    /// `SVPNCOOKIE` do login; só existe entre o login e o fim da sessão.
    cookie: Option<String>,
}

impl Fortinet {
    pub fn new(profile: &Profile, tls: Arc<GatewayTls>, log: LogFn, tuning: Tuning) -> Result<Self, String> {
        let realm = profile.realm.clone().unwrap_or_default();
        if realm.len() > MAX_REALM_LEN || realm.chars().any(char::is_control) {
            return Err("Invalid realm".into());
        }
        Ok(Self {
            host: profile.host.clone(),
            port: profile.port,
            auth: profile.auth,
            username: profile.username.clone(),
            realm,
            tls,
            log,
            push_timeout: tuning.push_timeout.unwrap_or(PUSH_TIMEOUT),
            echo_interval: tuning.keepalive.unwrap_or(ECHO_INTERVAL),
            cookie: None,
        })
    }

    fn cookie(&self) -> Result<&str, String> {
        self.cookie.as_deref().ok_or_else(|| "Not logged in".to_string())
    }

    /// `cookie` é o valor inteiro do cabeçalho `Cookie`. `host` vai no cabeçalho `Host`: o do gateway, ou `sslvpn` nos passos do túnel.
    async fn request(&self, method: &str, path: &str, host: &str, cookie: Option<&str>, form: Option<&str>) -> Result<http::Response, String> {
        tokio::time::timeout(STEP_TIMEOUT, self.exchange(method, path, host, cookie, form))
            .await
            .map_err(|_| format!("{} {} timed out", method, path))?
    }

    /// Uma troca HTTP sem prazo próprio; quem chama decide quanto esperar.
    async fn exchange(&self, method: &str, path: &str, host: &str, cookie: Option<&str>, form: Option<&str>) -> Result<http::Response, String> {
        let mut req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n", method, path, host, USER_AGENT);
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {}\r\n", c));
        }
        if let Some(body) = form {
            req.push_str(&format!(
                "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            ));
        } else {
            req.push_str("\r\n");
        }
        let mut stream = self.tls.connect().await?;
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("{} {} failed: {}", method, path, e))?;
        http::read_response(&mut stream).await.map_err(|e| format!("{} {} failed: {}", method, path, e))
    }

    /// Login por senha em um ou dois passos. Com o gateway pedindo token: usa o OTP se houver,
    /// senão pede o push (e avisa a espera) quando o gateway o oferece.
    async fn password_login(&self, credentials: &Credentials, waiting: &(dyn Fn(Waiting) + Sync)) -> Result<String, LoginError> {
        let challenge = match self.first_step(&credentials.password).await? {
            Login::Cookie(cookie) => return Ok(cookie),
            Login::Challenge(challenge) => challenge,
        };
        let otp = credentials.otp.as_deref().map(str::trim).filter(|o| !o.is_empty());
        if otp.is_none() {
            if !challenge.push {
                return Err(LoginError::Failed("Gateway requires an OTP code but none was provided".into()));
            }
            waiting(Waiting::Push);
        }
        self.complete_challenge(&challenge, otp).await
    }

    /// `POST /remote/logincheck`: devolve o `SVPNCOOKIE` ou o pedido de token do gateway.
    async fn first_step(&self, password: &str) -> Result<Login, LoginError> {
        let form = format!(
            "username={}&credential={}&realm={}&just_logged_in=1&redir=%2Fremote%2Findex&ajax=1",
            http::form_encode(&self.username),
            http::form_encode(password),
            http::form_encode(&self.realm)
        );
        let resp = self.request("POST", "/remote/logincheck", &http::host_header(&self.host, self.port), None, Some(&form)).await.map_err(LoginError::Failed)?;
        if let Some(c) = session_cookie(&resp) {
            return Ok(Login::Cookie(c));
        }
        let pairs = parse_pairs(&resp.body);
        let Some((_, tokeninfo)) = pairs.iter().find(|(k, _)| k == "tokeninfo") else {
            return Err(LoginError::Refused("Login failed: invalid username or password".into()));
        };
        let fields: Vec<_> = CHALLENGE_FIELDS
            .iter()
            .filter_map(|name| pairs.iter().find(|(k, _)| k == name).map(|(_, v)| (*name, v.clone())))
            .collect();
        // shortcut: só `reqid` é exigido, o gateway real pode omitir os outros; apertar quando houver prova contra ele.
        if !fields.iter().any(|(k, _)| *k == "reqid") {
            return Err(LoginError::Refused("Login failed: incomplete login challenge from the gateway".into()));
        }
        Ok(Login::Challenge(Challenge { fields, push: tokeninfo == "ftm_push" }))
    }

    /// Segundo passo do login: reenvia o desafio com o OTP, ou pede o push quando não há OTP.
    /// Com push a chamada espera a aprovação do usuário.
    async fn complete_challenge(&self, challenge: &Challenge, otp: Option<&str>) -> Result<String, LoginError> {
        let mut form = format!("username={}", http::form_encode(&self.username));
        for (name, value) in &challenge.fields {
            form.push_str(&format!("&{}={}", name, http::form_encode(value)));
        }
        match otp {
            Some(code) => form.push_str(&format!("&code={}", http::form_encode(code))),
            None => form.push_str("&ftm_push=1"),
        }
        form.push_str("&just_logged_in=1&ajax=1");
        let host = http::host_header(&self.host, self.port);
        let resp = match otp {
            Some(_) => self.request("POST", "/remote/logincheck", &host, None, Some(&form)).await,
            None => tokio::time::timeout(self.push_timeout, self.exchange("POST", "/remote/logincheck", &host, None, Some(&form)))
                .await
                .map_err(|_| LoginError::Refused("Login failed: push notification expired".into()))?,
        }
        .map_err(LoginError::Failed)?;
        match session_cookie(&resp) {
            Some(c) => Ok(c),
            _ if otp.is_some() => Err(LoginError::Refused("Login failed: invalid or expired OTP code".into())),
            _ => Err(LoginError::Refused("Login failed: push notification was denied or expired".into())),
        }
    }

    /// Login SAML pelo navegador externo. `waiting` recebe a URL que a GUI abre no navegador,
    /// depois que o listener local já está de pé. Só o gateway sem cookie de sessão é recusa
    /// (`Refused`); o resto (rede, porta ocupada, prazo do navegador) é `Failed`.
    async fn saml_login(&self, waiting: &(dyn Fn(Waiting) + Sync)) -> Result<String, LoginError> {
        use LoginError::Failed;
        let host = http::host_header(&self.host, self.port);
        let info = self.request("GET", "/remote/info", &host, None, None).await.map_err(Failed)?;
        let body = if (200..300).contains(&info.status) { String::from_utf8_lossy(&info.body).into_owned() } else { String::new() };
        let port = info_number(&body, "sso_port").and_then(|p| u16::try_from(p).ok());
        let secs = info_number(&body, "remoteauthtimeout");
        if port.is_none() || secs.is_none() {
            let line = format!(
                "GET /remote/info (HTTP {}) lacks sso_port or remoteauthtimeout; using sso_port {} and {} s where missing",
                info.status, DEFAULT_SSO_PORT, DEFAULT_SAML_TIMEOUT
            );
            log::warn!("{}", line);
            (self.log)(line);
        }
        let port = port.unwrap_or(DEFAULT_SSO_PORT);
        let timeout = Duration::from_secs(secs.unwrap_or(DEFAULT_SAML_TIMEOUT));

        let listener = browser_login::listen(port, "FortiClient").await.map_err(Failed)?;
        waiting(Waiting::Browser(format!("https://{}/remote/saml/start?redirect=1", host)));
        let id = tokio::time::timeout(timeout, browser_login::wait_for(listener, saml::extract_id))
            .await
            .map_err(|_| Failed(format!("SAML login timed out after {} s", timeout.as_secs())))?
            .map_err(Failed)?;

        let resp = self.request("GET", &format!("/remote/saml/auth_id?id={}", id), &host, None, None).await.map_err(Failed)?;
        if let Some(c) = session_cookie(&resp) {
            return Ok(c);
        }
        // Sem o cookie no `auth_id`, o passo comum do FortiClient, levando os cookies que o `auth_id` deixou (**inf**).
        let cookies = resp.cookies();
        let resp = self
            .request("POST", "/remote/logincheck", &host, Some(&cookies).filter(|c| !c.is_empty()).map(String::as_str), Some(SAML_LOGINCHECK))
            .await
            .map_err(Failed)?;
        session_cookie(&resp).ok_or_else(|| LoginError::Refused("SAML login failed: the gateway returned no session cookie".into()))
    }
}

impl engine::Engine for Fortinet {
    async fn login(&mut self, credentials: &Credentials, waiting: &(dyn Fn(Waiting) + Sync)) -> Result<(), LoginError> {
        let cookie = match self.auth {
            Auth::Saml => self.saml_login(waiting).await?,
            Auth::Password => self.password_login(credentials, waiting).await?,
        };
        self.cookie = Some(cookie);
        Ok(())
    }

    /// Lê a config do túnel, abre o `sslvpn-tunnel` e negocia o PPP até o IPCP subir.
    /// `login_started` é o início do login, de onde o `auth-timeout` conta.
    async fn open_tunnel(&self, login_started: chrono::DateTime<chrono::Utc>) -> Result<(TunnelConfig, Packets, Tunnel), String> {
        let cookie = self.cookie()?;
        let resp = self.request("GET", "/remote/fortisslvpn_xml", "sslvpn", Some(&svpn_header(cookie)), None).await?;
        if resp.status != 200 {
            return Err(format!("Gateway refused the tunnel configuration (HTTP {})", resp.status));
        }
        let xml = xml::parse(&resp.body)?;
        let mtu = xml.mtu.unwrap_or(DEFAULT_MTU);

        let mut stream = tokio::time::timeout(STEP_TIMEOUT, self.tls.connect())
            .await
            .map_err(|_| "Tunnel connection timed out".to_string())??;
        let gateway = stream.get_ref().0.peer_addr().map_err(|e| e.to_string())?.ip();
        let req = format!("GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: sslvpn\r\nCookie: {}\r\n\r\n", svpn_header(cookie));
        stream.write_all(req.as_bytes()).await.map_err(|e| format!("Tunnel request failed: {}", e))?;

        let (to_iface, rx) = mpsc::channel(256);
        let (tx, from_iface) = mpsc::channel(256);
        let (up_tx, up_rx) = oneshot::channel();
        let probe = Arc::new(Notify::new());
        let ppp = ppp::run(stream, mtu, self.echo_interval, probe.clone(), up_tx, to_iface, from_iface);
        let mut tunnel = Tunnel::new(tokio::spawn(ppp), probe);
        let up = match tokio::time::timeout(STEP_TIMEOUT, up_rx).await {
            Ok(Ok(up)) => up,
            Ok(Err(_)) => return Err(tunnel.closed().await),
            Err(_) => return Err("PPP negotiation timed out".into()),
        };

        let config = TunnelConfig {
            gateway,
            ip: up.ip,
            peer: up.peer,
            dns_servers: if xml.dns_servers.is_empty() { up.dns_servers } else { xml.dns_servers },
            dns_suffixes: xml.dns_suffixes,
            full_tunnel: xml.routes.is_empty(),
            routes: xml.routes,
            mtu,
            expires_at: xml.auth_timeout.map(|s| login_started + chrono::Duration::seconds(s as i64)),
        };
        Ok((config, Packets { tx, rx }, tunnel))
    }

    async fn logout(&self) -> Result<(), String> {
        let cookie = svpn_header(self.cookie()?);
        self.request("GET", "/remote/logout", &http::host_header(&self.host, self.port), Some(&cookie), None).await.map(|_| ())
    }
}
