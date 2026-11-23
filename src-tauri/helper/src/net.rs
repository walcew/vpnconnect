//! Camada de rede, independente de protocolo: recebe do Engine a config do túnel e o
//! canal de pacotes IP e os entrega ao sistema (interface, rotas, /32 do gateway, DNS).

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub mod system;
pub mod watch;

pub use system::SystemOs;

/// Rede IPv4 por endereço e máscara, como o gateway as envia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub addr: Ipv4Addr,
    pub mask: Ipv4Addr,
}

/// Máximo de redes pela VPN num Profile; acima disso é engano, não configuração.
pub const MAX_TUNNEL_ROUTES: usize = 256;

impl Route {
    /// Lê `a.b.c.d/n` (n de 1 a 32) ou um endereço sozinho (/32), zerando os bits de host.
    /// A /0 é recusada: full tunnel não é algo que o Profile peça.
    pub fn parse_cidr(text: &str) -> Result<Route, String> {
        let invalid = || format!("Invalid tunnel route: {}", text);
        let (addr, len) = match text.split_once('/') {
            Some((addr, len)) if !len.is_empty() && len.bytes().all(|b| b.is_ascii_digit()) => {
                (addr, len.parse::<u32>().map_err(|_| invalid())?)
            }
            Some(_) => return Err(invalid()),
            None => (text, 32),
        };
        let addr: Ipv4Addr = addr.parse().map_err(|_| invalid())?;
        if !(1..=32).contains(&len) {
            return Err(invalid());
        }
        let mask = u32::MAX << (32 - len);
        Ok(Route { addr: Ipv4Addr::from(u32::from(addr) & mask), mask: Ipv4Addr::from(mask) })
    }

    /// O intervalo `[início, fim)` de endereços da rede; `None` com máscara não contígua.
    fn range(&self) -> Option<(u64, u64)> {
        let mask = u32::from(self.mask);
        (mask.leading_ones() + mask.trailing_zeros() == 32).then(|| {
            let start = u64::from(u32::from(self.addr) & mask);
            (start, start + u64::from(!mask) + 1)
        })
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mask = u32::from(self.mask);
        if mask.leading_ones() + mask.trailing_zeros() == 32 {
            write!(f, "{}/{}", self.addr, mask.leading_ones())
        } else {
            write!(f, "{}/{}", self.addr, self.mask)
        }
    }
}

/// As redes pela VPN de um Profile, validadas; a primeira inválida recusa todas.
pub fn parse_tunnel_routes(routes: &[String]) -> Result<Vec<Route>, String> {
    let mut parsed: Vec<Route> = Vec::new();
    for text in routes {
        let route = Route::parse_cidr(text.trim())?;
        if !parsed.contains(&route) {
            parsed.push(route);
        }
    }
    // Conta depois de tirar as repetidas, como o app faz ao salvar o Profile.
    if parsed.len() > MAX_TUNNEL_ROUTES {
        return Err(format!("Too many tunnel routes: {} (at most {})", parsed.len(), MAX_TUNNEL_ROUTES));
    }
    Ok(parsed)
}

/// O que o Engine negociou e a camada de rede precisa aplicar.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelConfig {
    /// Endereço do gateway, que ganha um /32 pela interface física.
    pub gateway: IpAddr,
    pub ip: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub dns_servers: Vec<Ipv4Addr>,
    pub dns_suffixes: Vec<String>,
    /// Vazio quando `full_tunnel`.
    pub routes: Vec<Route>,
    pub full_tunnel: bool,
    pub mtu: u16,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Canal de pacotes IP visto do lado da interface: `tx` manda para o gateway e `rx`
/// entrega o que chegou dele.
#[derive(Debug)]
pub struct Packets {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
}

/// Operações de SO que a camada de rede usa. A implementação real (utun, `route`,
/// scutil) é o `SystemOs`; os testes usam um fake que registra as chamadas.
/// As remoções não falham: o teardown sempre tenta tudo.
pub trait Os: Send + Sync {
    /// Cria a interface do túnel e assume o canal de pacotes. Rotas dela somem com ela.
    /// Em erro, não deixa interface para trás.
    fn up(&self, ip: Ipv4Addr, peer: Ipv4Addr, mtu: u16, packets: Packets) -> Result<(), String>;
    /// Rota pela interface do túnel.
    fn add_route(&self, route: Route) -> Result<(), String>;
    /// /32 do gateway pelo default atual; devolve o next-hop usado.
    fn add_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String>;
    /// Leva o /32 do gateway para o default atual sem removê-lo antes (o tráfego do gateway nunca
    /// cai no túnel); cria se ele não existir. Devolve o next-hop usado.
    fn move_gateway_route(&self, gateway: IpAddr) -> Result<IpAddr, String>;
    /// `global`: os servidores respondem por todos os nomes, e os sufixos ficam só como domínios de
    /// busca. Sem ele, respondem só pelos sufixos (ou por tudo, sem sufixos).
    fn set_dns(&self, servers: &[Ipv4Addr], suffixes: &[String], global: bool) -> Result<(), String>;
    fn remove_dns(&self);
    /// Remove o /32 só se ele ainda sai por `via`: outro software pode ter um /32 do mesmo IP.
    fn remove_gateway_route(&self, gateway: IpAddr, via: IpAddr);
    fn down(&self);
    /// Arquivo de estado da recuperação de crash: o que está aplicado no SO enquanto há sessão.
    fn state_file(&self) -> PathBuf;
}

/// Full tunnel em duas metades, para nunca trocar a rota default.
const FULL_TUNNEL: [Route; 2] = [
    Route { addr: Ipv4Addr::new(0, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
    Route { addr: Ipv4Addr::new(128, 0, 0, 0), mask: Ipv4Addr::new(128, 0, 0, 0) },
];

/// O que já entrou no SO, para o teardown desfazer só isso. O /32 e o DNS vão também para o
/// arquivo de estado; a interface não, porque o utun some com o processo.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Applied {
    gateway_route: Option<IpAddr>,
    /// Next-hop do /32; ausente em arquivos de estado antigos.
    #[serde(default)]
    gateway_via: Option<IpAddr>,
    #[serde(skip)]
    interface: bool,
    dns: bool,
}

/// Muda `applied` e grava o arquivo de estado. Falha ao gravar não derruba a sessão: só perde a
/// recuperação de crash, e o log diz isso.
fn record(os: &dyn Os, applied: &Mutex<Applied>, change: impl FnOnce(&mut Applied)) {
    let mut applied = applied.lock().unwrap();
    change(&mut applied);
    if let Err(e) = save_state(&os.state_file(), &applied) {
        log::warn!("crash recovery state not saved: {}", e);
    }
}

/// Grava de forma atômica (temporário + rename), só para root (0700 no diretório, 0600 no arquivo).
fn save_state(path: &Path, applied: &Applied) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    // Um temporário que já existia mantém o modo antigo.
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(&serde_json::to_vec(applied)?)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

/// Ao iniciar o Helper: desfaz o que uma sessão anterior deixou no arquivo de estado (crash ou
/// `kill -9`) e apaga o arquivo. Sem arquivo, nada.
pub fn recover(os: &dyn Os) {
    let path = os.state_file();
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => return log::warn!("crash recovery state unreadable: {}: {}", path.display(), e),
    };
    match serde_json::from_slice::<Applied>(&data) {
        Ok(applied) => {
            log::info!("undoing leftovers of a previous session: {:?}", applied);
            teardown(os, &Mutex::new(applied));
        }
        Err(e) => {
            log::warn!("crash recovery state invalid, discarding: {}", e);
            remove_state(&path);
        }
    }
}

/// Cria o diretório 0700, ou o corrige se já existe com outro modo. Recusa diretório de outro dono
/// ou que não é diretório (symlink incluído): o arquivo guarda o que o root vai remover no boot.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    // SAFETY: geteuid não falha nem toca memória.
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::other(format!("{} is not a directory owned by this user", dir.display())));
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn remove_state(path: &Path) {
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            log::warn!("crash recovery state not removed: {}: {}", path.display(), e);
        }
    }
}

/// Aplica a config, marcando em `applied` cada passo que deu certo. Em erro (ou pânico),
/// o chamador faz `teardown` para desfazer o que entrou. A falha do DNS não é fatal: o túnel
/// sobe sem DNS e `Ok(Some(aviso))` diz por quê.
pub fn apply(os: &dyn Os, config: &TunnelConfig, packets: Packets, applied: &Mutex<Applied>) -> Result<Option<String>, String> {
    // O /32 entra antes das rotas do túnel para o gateway nunca ser roteado por dentro dele.
    let via = os.add_gateway_route(config.gateway)?;
    record(os, applied, |a| (a.gateway_route, a.gateway_via) = (Some(config.gateway), Some(via)));
    os.up(config.ip, config.peer, config.mtu, packets)?;
    applied.lock().unwrap().interface = true;
    for route in tunnel_routes(config) {
        os.add_route(route)?;
    }
    if !config.dns_servers.is_empty() {
        // Em full tunnel o DNS do sistema também sai pelo túnel, e o gateway pode bloquear DNS
        // externo: o da VPN resolve todos os nomes. Restringir aos sufixos só vale em split tunnel.
        match os.set_dns(&config.dns_servers, &config.dns_suffixes, is_full_tunnel(config)) {
            Ok(()) => record(os, applied, |a| a.dns = true),
            Err(e) => return Ok(Some(format!("DNS setup failed, tunnel stays up without DNS: {}", e))),
        }
    }
    Ok(None)
}

/// Tira de `config.routes` a rota anunciada que é exatamente o /32 do gateway: ela colidiria com o
/// /32 pela interface física. Devolve as rotas tiradas, para o chamador registrar no log.
pub fn drop_gateway_routes(config: &mut TunnelConfig) -> Vec<Route> {
    let IpAddr::V4(gateway) = config.gateway else { return Vec::new() };
    let (ignored, kept) = config.routes.iter().partition(|r| r.addr == gateway && r.mask == Ipv4Addr::BROADCAST);
    config.routes = kept;
    ignored
}

/// Rotas pelo túnel. Uma default (máscara 0) vinda do gateway vira as duas metades,
/// como no full tunnel: a rota default do sistema nunca é tocada.
fn tunnel_routes(config: &TunnelConfig) -> Vec<Route> {
    if config.full_tunnel {
        return FULL_TUNNEL.to_vec();
    }
    config
        .routes
        .iter()
        .flat_map(|r| if r.mask.is_unspecified() { FULL_TUNNEL.to_vec() } else { vec![*r] })
        .collect()
}

/// A sessão leva todo o tráfego IPv4 da máquina: a união das rotas pelo túnel cobre o espaço de
/// endereços inteiro, venha do full tunnel, de uma default do gateway ou de várias redes que,
/// somadas, cobrem tudo.
pub fn is_full_tunnel(config: &TunnelConfig) -> bool {
    let mut ranges: Vec<(u64, u64)> = tunnel_routes(config).iter().filter_map(Route::range).collect();
    ranges.sort_unstable();
    let mut covered = 0u64;
    for (start, end) in ranges {
        if start > covered {
            return false;
        }
        covered = covered.max(end);
    }
    covered == 1 << 32
}

/// As rotas pelo túnel, para o log: as primeiras e quantas faltam (o gateway pode mandar milhares).
pub fn describe_routes(config: &TunnelConfig) -> String {
    const SHOWN: usize = 20;
    let routes = tunnel_routes(config);
    if routes.is_empty() {
        return "none".into();
    }
    let mut text = routes.iter().take(SHOWN).map(Route::to_string).collect::<Vec<_>>().join(", ");
    if routes.len() > SHOWN {
        text.push_str(&format!(" and {} more", routes.len() - SHOWN));
    }
    text
}

pub fn teardown(os: &dyn Os, applied: &Mutex<Applied>) {
    let applied = std::mem::take(&mut *applied.lock().unwrap());
    if applied.dns {
        os.remove_dns();
    }
    if applied.interface {
        os.down();
    }
    match (applied.gateway_route, applied.gateway_via) {
        (Some(gateway), Some(via)) => os.remove_gateway_route(gateway, via),
        (Some(gateway), None) => log::warn!("host route to {} left in place: its next hop was not recorded", gateway),
        _ => {}
    }
    remove_state(&os.state_file());
}

/// Há /32 do gateway aplicado, logo uma troca de rede precisa refazê-lo.
pub fn has_gateway_route(applied: &Mutex<Applied>) -> bool {
    applied.lock().unwrap().gateway_route.is_some()
}

/// Depois de uma troca de rede: leva o /32 do `gateway` da sessão para o default atual. Se falhar
/// (na troca de Wi-Fi a default some antes da nova chegar), o registro fica como estava e o próximo
/// evento tenta de novo; até lá a detecção de túnel morto decide.
// shortcut: só IPv4, como o resto da camada de rede; evoluir junto com o suporte a gateway IPv6.
pub fn rehome_gateway_route(os: &dyn Os, gateway: IpAddr, applied: &Mutex<Applied>) -> Result<(), String> {
    let via = os.move_gateway_route(gateway)?;
    record(os, applied, |a| (a.gateway_route, a.gateway_via) = (Some(gateway), Some(via)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ovg-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn cidr(text: &str) -> Route {
        Route::parse_cidr(text).unwrap()
    }

    fn config_with(routes: &[&str], full_tunnel: bool) -> TunnelConfig {
        TunnelConfig {
            gateway: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            ip: Ipv4Addr::new(10, 100, 0, 2),
            peer: Ipv4Addr::new(169, 254, 2, 1),
            dns_servers: vec![],
            dns_suffixes: vec![],
            routes: routes.iter().map(|r| cidr(r)).collect(),
            full_tunnel,
            mtu: 1354,
            expires_at: None,
        }
    }

    #[test]
    fn cidr_is_read_with_the_host_bits_cleared() {
        assert_eq!(cidr("10.1.2.3/8"), Route { addr: Ipv4Addr::new(10, 0, 0, 0), mask: Ipv4Addr::new(255, 0, 0, 0) });
        assert_eq!(cidr("172.16.0.0/12").mask, Ipv4Addr::new(255, 240, 0, 0));
        assert_eq!(cidr("192.0.2.7"), Route { addr: Ipv4Addr::new(192, 0, 2, 7), mask: Ipv4Addr::BROADCAST });
        assert_eq!(cidr("10.0.0.0/8").to_string(), "10.0.0.0/8");
    }

    #[test]
    fn invalid_or_default_cidr_is_refused() {
        for bad in ["", "0.0.0.0/0", "10.0.0.0/33", "10.0.0.0/", "10.0.0.0/+8", "10.0.0/8", "corp.example/8", "::1/128", "10.0.0.0/8 x"] {
            let err = Route::parse_cidr(bad).unwrap_err();
            assert!(err.contains("Invalid tunnel route"), "{bad}: {err}");
        }
    }

    #[test]
    fn tunnel_routes_drop_duplicates_and_have_a_limit() {
        let routes = parse_tunnel_routes(&[" 10.0.0.0/8".into(), "10.9.9.9/8".into(), "172.16.0.0/12".into()]).unwrap();
        assert_eq!(routes, [cidr("10.0.0.0/8"), cidr("172.16.0.0/12")]);
        let mut many: Vec<String> = (0..=MAX_TUNNEL_ROUTES).map(|i| format!("10.{}.{}.0/24", i / 256, i % 256)).collect();
        assert!(parse_tunnel_routes(&many).unwrap_err().contains("Too many tunnel routes"));
        // As repetidas não contam para o limite.
        many.pop();
        many.push("10.0.0.0/24".into());
        assert_eq!(parse_tunnel_routes(&many).unwrap().len(), MAX_TUNNEL_ROUTES);
    }

    #[test]
    fn full_tunnel_is_any_set_of_routes_that_covers_everything() {
        assert!(is_full_tunnel(&config_with(&[], true)));
        assert!(is_full_tunnel(&config_with(&["10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1"], false)));
        // Uma default no split vira as duas metades.
        let mut default_in_split = config_with(&["10.0.0.0/8"], false);
        default_in_split.routes.push(Route { addr: Ipv4Addr::UNSPECIFIED, mask: Ipv4Addr::UNSPECIFIED });
        assert!(is_full_tunnel(&default_in_split));
        assert!(!is_full_tunnel(&config_with(&["10.0.0.0/8", "172.16.0.0/12"], false)));
        assert!(!is_full_tunnel(&config_with(&["0.0.0.0/1"], false)));
        assert!(!is_full_tunnel(&config_with(&[], false)));
        // Fragmentado em redes menores, também cobre tudo.
        assert!(is_full_tunnel(&config_with(&["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/3"], false)));
        assert!(!is_full_tunnel(&config_with(&["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/3"], false)));
        assert!(is_full_tunnel(&config_with(&["128.0.0.0/2", "0.0.0.0/1", "192.0.0.0/2", "10.0.0.0/8"], false)));
    }

    #[test]
    fn routes_are_described_up_to_a_limit() {
        assert_eq!(describe_routes(&config_with(&["10.0.0.0/8", "172.16.0.0/12"], false)), "10.0.0.0/8, 172.16.0.0/12");
        assert_eq!(describe_routes(&config_with(&[], true)), "0.0.0.0/1, 128.0.0.0/1");
        assert_eq!(describe_routes(&config_with(&[], false)), "none");
        let many: Vec<String> = (0..25).map(|i| format!("10.{i}.0.0/16")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(describe_routes(&config_with(&refs, false)).ends_with("10.19.0.0/16 and 5 more"));
    }

    #[test]
    fn state_dir_and_file_are_private() {
        let dir = temp_dir("state-dir");
        let file = dir.join("session-state.json");
        save_state(&file, &Applied::default()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn existing_state_dir_with_a_loose_mode_is_tightened() {
        let dir = temp_dir("loose-dir");
        fs::DirBuilder::new().mode(0o755).create(&dir).unwrap();
        save_state(&dir.join("session-state.json"), &Applied::default()).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn state_dir_that_is_a_symlink_is_refused() {
        let target = temp_dir("link-target");
        let link = temp_dir("link");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = save_state(&link.join("session-state.json"), &Applied::default()).unwrap_err();
        assert!(err.to_string().contains("not a directory owned by this user"), "{}", err);
        fs::remove_file(&link).unwrap();
        fs::remove_dir_all(&target).unwrap();
    }
}
