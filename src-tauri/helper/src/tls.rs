//! TLS com o gateway, comum a todos os Engines: raízes do sistema, digest fixado no Profile,
//! Auto-trust e o digest do certificado recusado.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{self, CryptoProvider};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use tokio_rustls::TlsConnector;

use crate::engine::LogFn;
use crate::profile::Profile;
use crate::validation::is_valid_hostname;

/// Raízes de confiança e histórico de digests, vivos enquanto o Helper roda.
pub struct CertTrust {
    /// None usa as raízes do sistema; o teste injeta as suas.
    roots: Option<Arc<RootCertStore>>,
    // shortcut: o histórico de digests vive em memória e se perde quando o Helper reinicia; persistir em disco quando a troca de certificado entre reinícios importar.
    digests: Mutex<HashMap<String, String>>,
}

impl CertTrust {
    pub fn system() -> Self {
        Self { roots: None, digests: Mutex::default() }
    }

    #[cfg(test)]
    pub fn with_roots(roots: RootCertStore) -> Self {
        Self { roots: Some(Arc::new(roots)), digests: Mutex::default() }
    }

    fn roots_verifier(&self, provider: &Arc<CryptoProvider>) -> Result<Arc<dyn ServerCertVerifier>, String> {
        match &self.roots {
            Some(roots) => Ok(WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                .build()
                .map_err(|e| e.to_string())?),
            None => Ok(Arc::new(rustls_platform_verifier::Verifier::new(provider.clone()).map_err(|e| e.to_string())?)),
        }
    }

    /// Guarda o digest do host e devolve (antigo, novo) quando ele mudou.
    fn record(&self, host: &str, cert: &CertificateDer<'_>) -> Option<(String, String)> {
        let new = digest(cert);
        let old = self.digests.lock().unwrap().insert(host.to_string(), new.clone())?;
        (old != new).then_some((old, new))
    }
}

/// Ponto único da validação do certificado do gateway. Nasce por conexão do Profile,
/// então o auto-trust não vaza para outro host.
struct GatewayCertVerifier {
    trusted_certs: Vec<String>,
    auto_trust: bool,
    roots: Arc<dyn ServerCertVerifier>,
    /// Digest do último certificado recusado, para o estado `disconnected`.
    refused: Arc<Mutex<Option<String>>>,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for GatewayCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayCertVerifier").finish_non_exhaustive()
    }
}

/// sha256 em hex do DER, o mesmo formato de `trusted_certs` no app.
fn digest(cert: &CertificateDer<'_>) -> String {
    Sha256::digest(cert.as_ref()).iter().map(|b| format!("{:02x}", b)).collect()
}

impl ServerCertVerifier for GatewayCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.auto_trust {
            return Ok(ServerCertVerified::assertion());
        }
        let digest = digest(end_entity);
        if self.trusted_certs.iter().any(|c| c.eq_ignore_ascii_case(&digest)) {
            return Ok(ServerCertVerified::assertion());
        }
        self.roots.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now).map_err(|cause| {
            *self.refused.lock().unwrap() = Some(digest.clone());
            Error::General(format!("untrusted gateway certificate ({}), sha256 digest {}", cause, digest))
        })
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(profile: &Profile, trust: &CertTrust, refused: Arc<Mutex<Option<String>>>) -> Result<ClientConfig, String> {
    let provider = Arc::new(crypto::ring::default_provider());
    let verifier = GatewayCertVerifier {
        trusted_certs: profile.trusted_certs.clone(),
        auto_trust: profile.ignore_cert_errors,
        roots: trust.roots_verifier(&provider)?,
        refused,
        provider: provider.clone(),
    };
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// Conexões TLS com o gateway de um Profile, uma por `connect` da sessão.
pub struct GatewayTls {
    host: String,
    port: u16,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    /// Só o auto-trust registra o digest de cada conexão.
    auto_trust: bool,
    trust: Arc<CertTrust>,
    log: LogFn,
    /// Digest do último certificado que o verificador recusou.
    refused: Arc<Mutex<Option<String>>>,
}

impl GatewayTls {
    pub fn new(profile: &Profile, trust: &Arc<CertTrust>, log: LogFn) -> Result<Self, String> {
        if !is_valid_hostname(&profile.host) {
            return Err(format!("Invalid host: {}", profile.host));
        }
        let server_name = ServerName::try_from(profile.host.clone()).map_err(|e| format!("Invalid host: {}", e))?;
        let refused = Arc::new(Mutex::new(None));
        Ok(Self {
            host: profile.host.clone(),
            port: profile.port,
            server_name,
            connector: TlsConnector::from(Arc::new(client_config(profile, trust, refused.clone())?)),
            auto_trust: profile.ignore_cert_errors,
            trust: trust.clone(),
            log,
            refused,
        })
    }

    /// Digest do certificado que o verificador recusou, se foi o caso.
    pub fn refused_digest(&self) -> Option<String> {
        self.refused.lock().unwrap().clone()
    }

    pub async fn connect(&self) -> Result<TlsStream<TcpStream>, String> {
        let tcp = TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| format!("Cannot reach {}:{}: {}", self.host, self.port, e))?;
        let stream = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| format!("TLS handshake failed: {}", e))?;
        // Só depois do handshake, que prova a posse da chave: um certificado copiado não vira "troca".
        if self.auto_trust {
            if let Some(cert) = stream.get_ref().1.peer_certificates().and_then(|c| c.first()) {
                if let Some((old, new)) = self.trust.record(&self.host, cert) {
                    let line = format!("gateway certificate of {} changed: sha256 {} -> {}", self.host, old, new);
                    log::warn!("{}", line);
                    (self.log)(line);
                }
            }
        }
        Ok(stream)
    }
}
