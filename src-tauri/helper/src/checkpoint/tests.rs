//! O Engine Check Point no seam da sessão: cliente do socket, sessão real, `FakeOs` e gateway
//! Check Point falso. O navegador é simulado chamando o listener de login.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::engine::Tuning;
use crate::net::Route;
use crate::session::Session;
use crate::testing::fake_checkpoint::*;
use crate::testing::fake_gateway::{FakeGateway, GatewayOptions, PASSWORD, PROFILE_ID};
use crate::testing::fake_os::{FakeOs, OsCall};
use crate::testing::{allow_all, client, disconnect, start_session, Client, SAML_PORTS};

/// Sessão com o listener de login na porta do gateway falso; `bandwidth` encurta o intervalo da banda.
async fn start(gw: &FakeCheckpoint, bandwidth: Option<Duration>) -> (PathBuf, Arc<FakeOs>) {
    let os = Arc::new(FakeOs::default());
    let mut session = Session::new(os.clone()).with_tuning(Tuning { login_port: Some(gw.login_port), ..Default::default() });
    if let Some(interval) = bandwidth {
        session = session.with_bandwidth_interval(interval);
    }
    let (path, _session) = start_session(allow_all(), session).await;
    (path, os)
}

fn connect_cmd(profile: Value) -> Value {
    json!({"v": 2, "cmd": "connect", "profile": profile})
}

/// Manda `<linha> HTTP/1.1` ao listener de login, como o navegador, e devolve a resposta.
async fn browser(port: u16, line: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let req = format!("{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAccept: text/html\r\n\r\n", line, port);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut resp)).await.unwrap().unwrap();
    String::from_utf8_lossy(&resp).into_owned()
}

/// Conecta pelo IdP: espera o `waiting-saml`, entrega o código no listener e devolve o estado
/// `connected` com todos os quadros vistos até ele.
async fn idp_connect(c: &mut Client, gw: &FakeCheckpoint, profile: Value) -> (Value, Vec<Value>) {
    c.send(connect_cmd(profile)).await;
    let mut frames = Vec::new();
    loop {
        let v = c.recv().await.expect("server closed the connection");
        frames.push(v.clone());
        if v["state"] == "waiting-saml" {
            assert_eq!(v, json!({"v": 2, "type": "event", "event": "state", "state": "waiting-saml", "profile_id": PROFILE_ID, "url": IDP_URL}));
            let resp = browser(gw.login_port, &format!("GET /{}", IDP_CODE)).await;
            assert!(resp.starts_with("HTTP/1.1 200 OK"), "{}", resp);
        }
        if v["state"] == "connected" {
            assert!(frames.iter().any(|f| f["state"] == "waiting-saml"), "connected without waiting-saml");
            return (v, frames);
        }
        assert_ne!(v["state"], "disconnected", "{}", v);
    }
}

fn route(addr: &str, mask: &str) -> Route {
    Route { addr: addr.parse().unwrap(), mask: mask.parse().unwrap() }
}

#[tokio::test]
async fn idp_login_connects_and_applies_the_gateway_network_without_leaking_secrets() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let (state, mut frames) = idp_connect(&mut c, &gw, gw.profile()).await;

    assert_eq!(state["profile_id"], PROFILE_ID);
    assert_eq!(state["ip"], ASSIGNED_IP.to_string());
    assert_eq!(state["dns_servers"], json!(DNS.map(|d| d.to_string())));
    assert_eq!(state["dns_suffixes"], json!(DNS_SUFFIXES));
    let since = chrono::DateTime::parse_from_rfc3339(state["since"].as_str().unwrap()).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(state["expires_at"].as_str().unwrap()).unwrap();
    // O prazo conta do início do login, um pouco antes do `since`; os dois truncados em segundos.
    let ttl = (expires - since).num_seconds();
    assert!(ttl == AUTH_TIMEOUT as i64 || ttl == AUTH_TIMEOUT as i64 - 1, "{}", ttl);

    // O protocolo não dá par: o próprio IP do túnel; sem MTU anunciado, 1350.
    let mut calls = vec![OsCall::AddGatewayRoute(IpAddr::V4(Ipv4Addr::LOCALHOST)), OsCall::Up { ip: ASSIGNED_IP, peer: ASSIGNED_IP, mtu: 1350 }];
    calls.extend(ROUTES.iter().map(|(a, m)| OsCall::AddRoute(route(a, m))));
    calls.push(OsCall::SetDns { servers: DNS.to_vec(), suffixes: DNS_SUFFIXES.map(String::from).to_vec() });
    assert_eq!(os.calls(), calls);

    // O listener fecha depois do código.
    assert!(tokio::net::TcpStream::connect(("127.0.0.1", gw.login_port)).await.is_err());

    // O Engine se declara cliente macOS.
    let login = gw.requests().into_iter().find(|r| r.text("RequestHeader:type") == Some("UserPass")).expect("no login request");
    assert_eq!(login.text("RequestData:selectedLoginOption"), Some(LOGIN_OPTION));
    assert_eq!(login.text("RequestData:client_logging_data:os_name"), Some("macOS"));
    assert_eq!(login.text("RequestData:client_logging_data:client_name"), Some("VPN Connect"));

    // O signout também não pode vazar: todos os quadros até o `disconnected`, logs inclusive.
    c.send(json!({"v": 2, "cmd": "disconnect"})).await;
    loop {
        let v = c.recv().await.expect("server closed the connection");
        frames.push(v.clone());
        if v["state"] == "disconnected" {
            break;
        }
    }
    assert_eq!(gw.logouts(), 1);
    assert!(frames.iter().any(|f| f["line"] == "logged out"), "no signout log");
    let secrets = [ACTIVE_KEY.to_string(), crate::checkpoint::sexp::obfuscate(ACTIVE_KEY.as_bytes()), IDP_CODE.to_string()];
    for f in &frames {
        for secret in &secrets {
            assert!(!f.to_string().contains(secret.as_str()), "secret leaked: {}", f);
        }
    }
}

#[tokio::test]
async fn huge_gateway_timeouts_are_capped_and_the_tunnel_comes_up() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions { huge_timeouts: true, ..Default::default() }).await;
    let (path, _os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let (state, frames) = idp_connect(&mut c, &gw, gw.profile()).await;
    let since = chrono::DateTime::parse_from_rfc3339(state["since"].as_str().unwrap()).unwrap();
    let expires = chrono::DateTime::parse_from_rfc3339(state["expires_at"].as_str().unwrap()).unwrap();
    let ttl = (expires - since).num_seconds();
    assert!((30 * 24 * 3600 - 1..=30 * 24 * 3600).contains(&ttl), "{}", ttl);
    for name in ["authentication", "keepalive"] {
        assert!(frames.iter().any(|f| f["line"].as_str().is_some_and(|l| l.contains(name) && l.contains("capped"))), "no cap log for {}", name);
    }
    assert_eq!(disconnect(&mut c).await["state"], "disconnected");
}

#[test]
fn gateway_error_message_is_cut_and_stripped_of_control_characters() {
    use crate::checkpoint::sexp::{obfuscate, Sexp};
    use crate::engine::LoginError;
    let message = format!("bad\x1b[31m\nlogin{}", "x".repeat(1000));
    let data = Sexp::obj("", vec![("authn_status", Sexp::val("done")), ("error_message", Sexp::val(obfuscate(message.as_bytes())))]);
    let Err(LoginError::Refused(reason)) = super::CheckPoint::auth_step(&data) else { panic!("not a refusal") };
    assert!(reason.starts_with("Login failed: bad[31mlogin"), "{}", reason);
    assert!(!reason.chars().any(char::is_control) && reason.len() < 250, "{}", reason);
}

#[tokio::test]
async fn profile_match_domains_replace_the_gateway_suffixes() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let mut profile = gw.profile();
    profile["dns_match_domains"] = json!(["intra.example"]);
    let (state, _) = idp_connect(&mut c, &gw, profile).await;
    assert_eq!(state["dns_servers"], json!(DNS.map(|d| d.to_string())));
    assert_eq!(state["dns_suffixes"], json!(["intra.example"]));
    assert!(os.calls().contains(&OsCall::SetDns { servers: DNS.to_vec(), suffixes: vec!["intra.example".into()] }));
}

/// Próximo evento de banda, como (rx, tx).
async fn next_bandwidth(c: &mut Client) -> (u64, u64) {
    loop {
        let v = c.recv().await.expect("server closed the connection");
        if v["event"] == "bandwidth" {
            return (v["rx_bytes"].as_u64().unwrap(), v["tx_bytes"].as_u64().unwrap());
        }
    }
}

#[tokio::test]
async fn ip_packets_flow_both_ways_and_bandwidth_counts_them() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, Some(Duration::from_millis(50))).await;
    let mut c = client(&path).await;
    idp_connect(&mut c, &gw, gw.profile()).await;
    let mut iface = os.take_packets();

    let outbound = vec![0x45; 100];
    iface.tx.send(outbound.clone()).await.unwrap();
    assert_eq!(gw.recv_ip().await, outbound);
    let inbound = vec![0x45, 0, 0, 40, 9, 8, 7, 6];
    gw.send_ip(inbound.clone());
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), iface.rx.recv()).await.unwrap(), Some(inbound));
    // Um tick pode cair entre os dois sentidos; o total final é o que importa.
    loop {
        let (rx, tx) = next_bandwidth(&mut c).await;
        assert!(rx <= 8 && tx <= 100, "{} {}", rx, tx);
        if (rx, tx) == (8, 100) {
            break;
        }
    }
}

#[tokio::test]
async fn disconnect_signs_out_at_the_gateway_and_tears_everything_down() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    idp_connect(&mut c, &gw, gw.profile()).await;
    let state = disconnect(&mut c).await;
    assert_eq!(state, json!({"v": 2, "type": "event", "event": "state", "state": "disconnected"}));
    assert_eq!(gw.logouts(), 1);
    assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
    assert_eq!(os.saved_state(), None);
    assert!(os.calls().contains(&OsCall::Down) && os.calls().contains(&OsCall::RemoveDns));
}

#[tokio::test]
async fn mute_gateway_on_signout_does_not_hold_the_disconnect() {
    let _ports = SAML_PORTS.lock().await;
    let gw = FakeCheckpoint::start(CheckpointOptions { mute_logout: true, ..Default::default() }).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    idp_connect(&mut c, &gw, gw.profile()).await;
    let started = Instant::now();
    let state = disconnect(&mut c).await;
    assert!(started.elapsed() < Duration::from_millis(2500), "took {:?}", started.elapsed());
    assert!(state.get("reason").is_none(), "{}", state);
    assert_eq!(gw.logouts(), 1);
    assert!(os.applied().is_empty(), "left behind: {:?}", os.applied());
}

#[tokio::test]
async fn untrusted_certificate_is_refused_with_its_digest() {
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let mut profile = gw.profile();
    profile["trusted_certs"] = json!(["00"]);
    c.send(connect_cmd(profile)).await;
    let state = loop {
        let v = c.recv_skipping_logs().await;
        if v["state"] == "disconnected" {
            break v;
        }
    };
    assert!(state["reason"].as_str().unwrap().contains(&gw.digest), "{}", state);
    assert_eq!(state["cert_digest"], gw.digest);
    assert!(state.get("cause").is_none(), "{}", state);
    assert!(gw.requests().is_empty());
    assert!(os.calls().is_empty());
}

/// Responde a um `connect` com o erro, sem estado novo.
async fn refused(c: &mut Client, cmd: Value) -> String {
    c.send(cmd).await;
    let r = c.recv_skipping_logs().await;
    assert_eq!(r["type"], "response", "{}", r);
    assert_eq!(r["ok"], false, "{}", r);
    r["error"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn checkpoint_connect_is_refused_while_a_fortinet_session_is_active() {
    let fortinet = FakeGateway::start(GatewayOptions::default()).await;
    let checkpoint = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, _os) = start(&checkpoint, None).await;
    let mut c = client(&path).await;
    c.send(json!({"v": 2, "cmd": "connect", "profile": fortinet.profile(), "password": PASSWORD})).await;
    loop {
        if c.recv_skipping_logs().await["state"] == "connected" {
            break;
        }
    }
    assert!(refused(&mut c, connect_cmd(checkpoint.profile())).await.contains("already active"));
    assert!(checkpoint.requests().is_empty());
}

#[tokio::test]
async fn fortinet_connect_is_refused_while_a_checkpoint_session_is_active() {
    let _ports = SAML_PORTS.lock().await;
    let fortinet = FakeGateway::start(GatewayOptions::default()).await;
    let checkpoint = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, _os) = start(&checkpoint, None).await;
    let mut c = client(&path).await;
    idp_connect(&mut c, &checkpoint, checkpoint.profile()).await;
    let cmd = json!({"v": 2, "cmd": "connect", "profile": fortinet.profile(), "password": PASSWORD});
    assert!(refused(&mut c, cmd).await.contains("already active"));
    assert!(fortinet.realms().is_empty(), "the Fortinet login started");
}

/// Sem `engine` o Profile é Fortinet: é o que toda a suíte da sessão já exercita.
#[tokio::test]
async fn unknown_engine_is_an_invalid_request() {
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let mut profile = gw.profile();
    profile["engine"] = json!("ipsec");
    let error = refused(&mut c, connect_cmd(profile)).await;
    assert!(error.contains("Invalid request") && error.contains("ipsec"), "{}", error);
    assert!(gw.requests().is_empty());
    assert!(os.calls().is_empty());
}

#[tokio::test]
async fn checkpoint_profile_with_password_auth_is_refused_before_any_login() {
    let gw = FakeCheckpoint::start(CheckpointOptions::default()).await;
    let (path, os) = start(&gw, None).await;
    let mut c = client(&path).await;
    let mut profile = gw.profile();
    profile["auth"] = json!("password");
    let error = refused(&mut c, connect_cmd(profile)).await;
    assert!(error.contains("saml"), "{}", error);
    assert!(gw.requests().is_empty());
    assert!(os.calls().is_empty());
}
