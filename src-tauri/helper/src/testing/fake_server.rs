//! Apoio comum dos gateways falsos: servidor TLS em loopback com certificado gerado no teste
//! (autoassinado, assinado por CA de teste, nome errado, chave trocada) e leitura de requisições HTTP.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, SanType};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use tokio_rustls::TlsAcceptor;

/// Variações do certificado do servidor de teste; o padrão é autoassinado para `localhost`.
#[derive(Default, Clone, Copy)]
pub struct CertOptions {
    /// Certificado assinado por uma CA de teste (ver `TlsServer::roots`) em vez de autoassinado.
    pub ca_signed: bool,
    /// Com `ca_signed`: o certificado vale para outro nome, não para 127.0.0.1 nem localhost.
    pub wrong_name: bool,
    /// Apresenta um certificado cuja chave privada não é a usada no handshake (como um MITM que só copiou o certificado).
    pub mismatched_key: bool,
}

/// Lado servidor do TLS de teste: o aceitador para o `accept` de cada conexão e o que o cliente precisa para confiar nele.
pub struct TlsServer {
    pub acceptor: TlsAcceptor,
    /// sha256 hex do DER do certificado, como em `trusted_certs`.
    pub digest: String,
    ca: Option<CertificateDer<'static>>,
}

impl TlsServer {
    pub fn new(options: CertOptions) -> Self {
        let (der, key_pair, ca) = if options.ca_signed {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            let ca_cert = ca_params.self_signed(&ca_key).unwrap();
            let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            params.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
            if options.wrong_name {
                params.subject_alt_names = vec![SanType::DnsName("other.example".try_into().unwrap())];
            }
            let key_pair = KeyPair::generate().unwrap();
            let cert = params.signed_by(&key_pair, &ca_cert, &ca_key).unwrap();
            (cert.der().clone(), key_pair, Some(ca_cert.der().clone()))
        } else {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
            (cert.cert.der().clone(), cert.key_pair, None)
        };
        let digest = Sha256::digest(der.as_ref()).iter().map(|b| format!("{:02x}", b)).collect();
        let key_pair = if options.mismatched_key { KeyPair::generate().unwrap() } else { key_pair };
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        // O resolvedor não confere se a chave é a do certificado, ao contrário do `with_single_cert`.
        let signing_key = ring::sign::any_supported_type(&key).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(Arc::new(CertifiedKey::new(vec![der], signing_key)))));
        Self { acceptor: TlsAcceptor::from(Arc::new(config)), digest, ca }
    }

    /// Raízes de teste que confiam na CA deste servidor (vazias se o certificado é autoassinado).
    pub fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        if let Some(ca) = &self.ca {
            roots.add(ca.clone()).unwrap();
        }
        roots
    }
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Requisição HTTP/1.1 como o servidor falso a leu.
pub struct Request {
    pub method: String,
    /// Caminho com a query, como na linha da requisição.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// Valor do primeiro cabeçalho com este nome (sem distinguir maiúsculas).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// Lê uma requisição inteira (cabeçalhos e, com `Content-Length`, o corpo); None se a conexão fecha antes ou o cabeçalho não é UTF-8.
pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> Option<Request> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.ok()? == 0 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).ok()?;
    let mut lines = head.lines();
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let (method, path) = (request_line.next().unwrap_or_default().to_string(), request_line.next().unwrap_or_default().to_string());
    let headers: Vec<(String, String)> =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.to_string(), v.trim().to_string())).collect();
    let mut request = Request { method, path, headers, body: Vec::new() };
    let len = request.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    request.body = vec![0u8; len];
    stream.read_exact(&mut request.body).await.ok()?;
    Some(request)
}
