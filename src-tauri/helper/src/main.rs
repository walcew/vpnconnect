mod browser_login;
mod checkpoint;
mod engine;
mod fortinet;
mod http;
mod net;
mod profile;
mod protocol;
mod server;
mod session;
#[cfg(test)]
mod testing;
mod tls;
mod validation;

use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Emite uma linha como evento de log da sessão.
pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;

#[tokio::main]
async fn main() {
    env_logger::init();
    log::info!(
        "vpnconnect-helper v{} starting",
        env!("CARGO_PKG_VERSION")
    );

    // No SIGTERM/SIGINT, o server encerra a sessão ativa antes de voltar.
    if let Err(e) = server::run(shutdown_signal()).await {
        log::error!("Server error: {}", e);
        std::process::exit(1);
    }
    let socket_path = Path::new(server::SOCKET_PATH);
    if socket_path.exists() {
        let _ = fs::remove_file(socket_path);
    }

    log::info!("vpnconnect-helper stopped");
}

async fn shutdown_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to register SIGTERM handler");
    let mut sigint =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => log::info!("Received SIGTERM"),
        _ = sigint.recv() => log::info!("Received SIGINT"),
    }
}
