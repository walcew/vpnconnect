use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthType {
    Password,
    Saml,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::Password
    }
}

/// O protocolo de VPN do Profile (o Engine do Helper). Fixo depois da criação.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    /// Também o valor de um Profile gravado antes do campo existir.
    #[default]
    Fortinet,
    Checkpoint,
}

impl Engine {
    pub fn default_port(self) -> u16 {
        match self {
            Engine::Fortinet => 8443,
            Engine::Checkpoint => 443,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnProfile {
    pub id: String,
    pub name: String,
    /// Sem o campo no arquivo, vale `fortinet`; o arquivo não é migrado.
    #[serde(default)]
    pub engine: Engine,
    pub host: String,
    pub port: u16,
    pub auth_type: AuthType,
    pub username: Option<String>,
    #[serde(default)]
    pub otp_required: bool,
    pub realm: Option<String>,
    pub trusted_certs: Vec<String>,
    #[serde(default)]
    pub ignore_cert_errors: bool,
    /// Split-DNS domains that should use the VPN's DNS. When set, only these
    /// domains go to the VPN's DNS and everything else keeps the system DNS;
    /// empty keeps the previous behavior (suffixes sent by the gateway, or
    /// global DNS if the gateway sends none).
    #[serde(default)]
    pub dns_match_domains: Vec<String>,
    pub extra_args: Vec<String>,
}

impl Default for VpnProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            engine: Engine::default(),
            host: String::new(),
            port: Engine::default().default_port(),
            auth_type: AuthType::default(),
            username: None,
            otp_required: false,
            realm: None,
            trusted_certs: Vec::new(),
            ignore_cert_errors: false,
            dns_match_domains: Vec::new(),
            extra_args: Vec::new(),
        }
    }
}

impl VpnProfile {
    /// A regra do Engine sobre o que o Profile guarda, comum à GUI e à CLI: o Check Point entra
    /// sempre por SAML, sem usuário nem OTP. Chamada em `VpnManager::save_profile`.
    pub fn normalize_for_engine(&mut self) {
        if self.engine == Engine::Checkpoint {
            self.auth_type = AuthType::Saml;
            self.username = None;
            self.otp_required = false;
        }
    }

    /// Profile Fortinet com senha que exige OTP a cada conexão; o Check Point entra só pelo IdP.
    pub fn needs_otp(&self) -> bool {
        self.engine == Engine::Fortinet && self.auth_type == AuthType::Password && self.otp_required
    }

    /// O OTP que vale para este Profile: sem espaços nas pontas, e só se ele exigir OTP
    /// e o código não for vazio. Único ponto de normalização do OTP no app.
    pub fn otp_to_send<'a>(&self, otp: Option<&'a str>) -> Option<&'a str> {
        otp.map(str::trim).filter(|o| self.needs_otp() && !o.is_empty())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectionState {
    Disconnected,
    Connecting { profile_id: String },
    WaitingSaml { profile_id: String, url: String },
    /// Push do FortiToken enviado, aguardando aprovação no celular.
    WaitingPush { profile_id: String },
    Connected {
        profile_id: String,
        ip: String,
        since: DateTime<Utc>,
        /// DNS servers applied by the app on connect.
        dns_servers: Vec<String>,
        /// Domains that use this DNS; empty = the VPN's DNS is the global resolver.
        dns_domains: Vec<String>,
    },
    Disconnecting,
    Error { message: String },
}

impl Default for ConnectionState {
    fn default() -> Self {
        ConnectionState::Disconnected
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStatusPayload {
    pub state: String,
    pub profile_id: Option<String>,
    pub ip: Option<String>,
    pub since: Option<String>,
    pub message: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub dns_domains: Vec<String>,
}

impl From<&ConnectionState> for ConnectionStatusPayload {
    fn from(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => ConnectionStatusPayload {
                state: "Disconnected".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: None,
                ..Default::default()
            },
            ConnectionState::Connecting { profile_id } => ConnectionStatusPayload {
                state: "Connecting".into(),
                profile_id: Some(profile_id.clone()),
                ip: None,
                since: None,
                message: None,
                ..Default::default()
            },
            ConnectionState::WaitingSaml { profile_id, url } => ConnectionStatusPayload {
                state: "WaitingSaml".into(),
                profile_id: Some(profile_id.clone()),
                ip: None,
                since: None,
                message: Some(url.clone()),
                ..Default::default()
            },
            ConnectionState::WaitingPush { profile_id } => ConnectionStatusPayload {
                state: "WaitingPush".into(),
                profile_id: Some(profile_id.clone()),
                ..Default::default()
            },
            ConnectionState::Connected {
                profile_id,
                ip,
                since,
                dns_servers,
                dns_domains,
            } => ConnectionStatusPayload {
                state: "Connected".into(),
                profile_id: Some(profile_id.clone()),
                ip: Some(ip.clone()),
                since: Some(since.to_rfc3339()),
                message: None,
                dns_servers: dns_servers.clone(),
                dns_domains: dns_domains.clone(),
                ..Default::default()
            },
            ConnectionState::Disconnecting => ConnectionStatusPayload {
                state: "Disconnecting".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: None,
                ..Default::default()
            },
            ConnectionState::Error { message } => ConnectionStatusPayload {
                state: "Error".into(),
                profile_id: None,
                ip: None,
                since: None,
                message: Some(message.clone()),
                ..Default::default()
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLinePayload {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthPayload {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_speed: f64,
    pub tx_speed: f64,
    pub timestamp: String,
}

/// Emitido pelo tray para a janela principal pedir o OTP de um Profile.
#[derive(Debug, Clone, Serialize)]
pub struct OtpRequestedPayload {
    pub profile_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_needs_otp() {
        let profile = |auth_type, otp_required| VpnProfile {
            auth_type,
            otp_required,
            ..VpnProfile::default()
        };
        assert!(profile(AuthType::Password, true).needs_otp());
        assert!(!profile(AuthType::Password, false).needs_otp());
        assert!(!profile(AuthType::Saml, true).needs_otp());
        assert!(!profile(AuthType::Saml, false).needs_otp());
        let checkpoint = VpnProfile { engine: Engine::Checkpoint, ..profile(AuthType::Password, true) };
        assert!(!checkpoint.needs_otp());
    }

    #[test]
    fn test_normalize_for_engine() {
        let mut checkpoint = VpnProfile {
            engine: Engine::Checkpoint,
            username: Some("alice".into()),
            otp_required: true,
            ..VpnProfile::default()
        };
        checkpoint.normalize_for_engine();
        assert_eq!((checkpoint.auth_type, checkpoint.username, checkpoint.otp_required), (AuthType::Saml, None, false));

        // O Fortinet fica como está.
        let mut fortinet = VpnProfile { username: Some("alice".into()), otp_required: true, ..VpnProfile::default() };
        fortinet.normalize_for_engine();
        assert_eq!((fortinet.auth_type, fortinet.username.as_deref(), fortinet.otp_required), (AuthType::Password, Some("alice"), true));
    }

    #[test]
    fn test_otp_to_send() {
        let profile = |otp_required| VpnProfile { otp_required, ..VpnProfile::default() };
        assert_eq!(profile(true).otp_to_send(Some(" 123456 ")), Some("123456"));
        for blank in [None, Some(""), Some("   ")] {
            assert_eq!(profile(true).otp_to_send(blank), None);
        }
        // Sem otp_required um código sobrando não vale.
        assert_eq!(profile(false).otp_to_send(Some("123456")), None);
    }
}
