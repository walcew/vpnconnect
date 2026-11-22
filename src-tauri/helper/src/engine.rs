//! A fronteira entre a sessão e os Engines (ADR 0004): login, abrir o túnel e logout.
//! O que o login produz (cookie, chave de sessão) fica dentro do Engine.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::net::{Packets, TunnelConfig};

/// Credenciais do `connect`, repassadas ao Engine sem a sessão olhar dentro.
pub struct Credentials {
    /// Vazia no login pelo navegador.
    pub password: String,
    pub otp: Option<String>,
}

/// Espera do login por uma ação do usuário, que a sessão anuncia como estado.
pub enum Waiting {
    /// Listener local de pé; o usuário faz o login no navegador, nesta URL.
    Browser(String),
    /// O gateway mandou a notificação; o usuário aprova no celular.
    Push,
}

/// Por que o login falhou.
pub enum LoginError {
    /// O gateway recusou o login; a sessão marca o `disconnected` com `cause: login-failed`. No
    /// Fortinet: usuário ou senha, OTP, push negado ou expirado, desafio de token incompleto e
    /// SAML sem cookie de sessão.
    Refused(String),
    /// Qualquer outra falha. No Fortinet: rede, TLS, OTP exigido e não informado e o resto
    /// do SAML (porta local ocupada, prazo do navegador).
    Failed(String),
}

/// Intervalos e prazos que os testes encurtam; `None` usa o padrão do Engine.
#[derive(Clone, Copy, Default)]
pub struct Tuning {
    /// Sondagem periódica do túnel de pé.
    pub keepalive: Option<Duration>,
    /// Espera pela aprovação no celular.
    pub push_timeout: Option<Duration>,
    /// Porta do listener do login pelo IdP do Check Point (7779 na produção).
    pub login_port: Option<u16>,
    /// Espera pelo login no navegador do Check Point (120 s na produção).
    pub login_timeout: Option<Duration>,
}

/// Um protocolo de VPN, conduzido pela sessão numa ordem fixa: `login`, `open_tunnel` e,
/// no fim pedido pelo usuário, `logout`. A sessão cancela qualquer passo soltando o future.
pub trait Engine: Send + Sync {
    /// Autentica no gateway e guarda a sessão dele. `waiting` anuncia cada espera pelo usuário.
    fn login(&mut self, credentials: &Credentials, waiting: &(dyn Fn(Waiting) + Sync)) -> impl Future<Output = Result<(), LoginError>> + Send;

    /// Abre o túnel da sessão do login. `login_started` é o início do login, de onde conta o
    /// prazo de autenticação que vira o `expires_at`.
    fn open_tunnel(&self, login_started: DateTime<Utc>) -> impl Future<Output = Result<(TunnelConfig, Packets, Tunnel), String>> + Send;

    /// Encerra a sessão no gateway; o prazo é da sessão.
    fn logout(&self) -> impl Future<Output = Result<(), String>> + Send;
}

/// A task do túnel; abortá-la (ou soltá-la) fecha a conexão com o gateway.
pub struct Tunnel {
    task: JoinHandle<String>,
    /// Pede ao Engine uma sondagem fora do intervalo.
    probe: Arc<Notify>,
}

impl Tunnel {
    /// `task` conduz o túnel e devolve o motivo da queda; `probe` dispara uma sondagem imediata.
    pub fn new(task: JoinHandle<String>, probe: Arc<Notify>) -> Self {
        Self { task, probe }
    }

    /// Espera o túnel cair e devolve o motivo.
    pub async fn closed(&mut self) -> String {
        (&mut self.task).await.unwrap_or_else(|e| format!("Tunnel task failed: {}", e))
    }

    /// Sonda o gateway agora, sem esperar o próximo intervalo; sem resposta, o túnel cai como
    /// em qualquer sondagem perdida.
    pub fn probe(&self) {
        self.probe.notify_one();
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}
