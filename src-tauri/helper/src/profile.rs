//! O Profile como chega no `connect`, comum a todos os Engines.

use std::net::Ipv4Addr;

use serde::Deserialize;

use crate::net::Route;

/// Métodos de autenticação que o Helper já fala.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    Password,
    /// Navegador externo; sem username nem senha.
    Saml,
}

/// O Engine do Profile; sem o campo, Fortinet (Profiles de antes do Check Point).
#[derive(Debug, Clone, Copy, Default, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineKind {
    #[default]
    Fortinet,
    Checkpoint,
}

/// Só o que o Helper usa; o resto é ignorado.
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    pub id: String,
    #[serde(default)]
    pub engine: EngineKind,
    pub host: String,
    pub port: u16,
    pub auth: Auth,
    /// Vazio no SAML.
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub trusted_certs: Vec<String>,
    /// Auto-trust: aceita qualquer certificado, só deste host.
    #[serde(default)]
    pub ignore_cert_errors: bool,
    /// Split DNS do Profile: se houver, só estes domínios usam o DNS da VPN, no lugar
    /// dos sufixos do gateway. Vazio mantém os sufixos do gateway.
    #[serde(default)]
    pub dns_match_domains: Vec<String>,
    /// Redes pela VPN, em CIDR IPv4: se houver, substituem as rotas do gateway, inclusive a
    /// default e o full tunnel. Vazio mantém as rotas do gateway. Validadas no `connect`.
    #[serde(default)]
    pub tunnel_routes: Vec<String>,
    /// `tunnel_routes` já lidas, preenchidas pelo `Session::connect`; nunca vêm do JSON.
    #[serde(skip)]
    pub tunnel_networks: Vec<Route>,
    /// DNS do sistema lido pela GUI antes de conectar (vazio com o fallback desligado ou
    /// sem DNS no sistema). Só valem, com os do Google, se o gateway não mandar servidor.
    #[serde(default)]
    pub dns_fallback_servers: Vec<Ipv4Addr>,
    /// Fortinet: realm do login por senha; ausente ou vazio manda `realm=` vazio. Check Point:
    /// id da opção de login; ausente ou vazio usa a única opção de IdP do gateway.
    #[serde(default)]
    pub realm: Option<String>,
}
