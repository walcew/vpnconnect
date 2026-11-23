# VPN Connect

Cliente macOS para VPNs FortiGate SSL-VPN e Check Point, com um Engine próprio para cada um rodando no Helper.

## Language

**Profile**:
A configuração salva de um gateway VPN: Engine, host, porta, método de autenticação, certificados confiáveis e domínios DNS. O Engine é fixo depois da criação; no Check Point o Profile entra sempre pelo IdP, sem usuário, senha nem OTP.
_Avoid_: Connection, account, server

**Helper**:
O daemon privilegiado que roda como root. É o dono da sessão: hospeda o Engine, cria o túnel, aplica rotas e DNS e desfaz tudo quando a sessão termina. A GUI e a CLI `vpnconnect` são clientes iguais do socket dele.
_Avoid_: Daemon, service, agent

**Engine**:
A implementação de um protocolo de VPN dentro do Helper: faz o login e o túnel e entrega a configuração à camada de rede. Existem dois: o Fortinet SSL VPN e o Check Point (túnel SSL, com o login pelo IdP). O Profile escolhe o seu na criação (`engine`).
_Avoid_: Motor externo, backend, driver

**Login option**:
O id da opção de login do gateway Check Point, a que leva ao IdP. Fica no campo `realm` do Profile e é opcional: vazio, vale a única opção do gateway.
_Avoid_: Realm (no Check Point), login method

**Auto-trust**:
Opção do Profile que aceita qualquer certificado do gateway, só do host daquele Profile, registrando no log as trocas de digest entre conexões. No código, `ignore_cert_errors`.
_Avoid_: Ignorar certificado, insecure, skip verify

**Full tunnel**:
Sessão em que todo o tráfego IPv4 da máquina passa pela VPN, porque o gateway mandou (full tunnel ou rota default) ou porque as redes do Profile cobrem tudo. É questão de privacidade: a organização da VPN vê todo esse tráfego. O Helper marca `full_tunnel` no estado, e a GUI (painel, tray, notificação) e a CLI (`status`, `connect`) avisam. Em full tunnel o DNS da VPN resolve todos os nomes; os domínios de split DNS ficam só como domínios de busca.
_Avoid_: Túnel completo, all traffic mode

**Redes pela VPN**:
Opção do Profile com as redes, em CIDR IPv4, que passam pelo túnel. Preenchida, substitui as rotas do gateway, inclusive a default e o full tunnel; vazia, valem as rotas do gateway. No código, `tunnel_routes`; na CLI, `--route`.
_Avoid_: Split routes, rotas customizadas

**OTP**:
Código de uso único que o usuário digita para concluir o segundo fator de um Profile com senha.
_Avoid_: Token, 2FA code, TOTP code

**FortiToken push**:
Segundo fator em que o gateway envia uma notificação ao celular do usuário, que a aprova sem digitar nenhum OTP.
_Avoid_: Push token, push OTP

**CLI**:
O modo de linha de comando do executável do app, o comando `vpnconnect`. Faz pelo terminal o que a GUI faz e é cliente do Helper, igual a ela.
_Avoid_: Binário da CLI, app de terminal
