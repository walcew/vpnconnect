# Protocolo Check Point (túnel SSL) no Engine

O que o Engine Check Point do Helper (`src-tauri/helper/src/checkpoint/`) implementa hoje: canal de controle, login pelo provedor de identidade (IdP) no navegador, túnel SSL com quadros de controle e de dados, e signout. Escrito a partir do entendimento do comportamento público de clientes de terceiros (snx-rs, AGPL-3.0, e cpyvpn, GPLv3), lidos só como referência de protocolo, como manda o [ADR 0004](adr/0004-engine-trait-and-checkpoint-engine.md). Nenhum código deles foi copiado, traduzido ou linkado.

Marcas: **ref** = como os clientes de referência fazem, ainda sem prova contra o gateway de validação; **obs** = visto no gateway de validação; **inf** = inferência nossa.

## Conexões

Todo tráfego vai ao host e à porta do Profile (443 por padrão), em TLS, com as mesmas regras de confiança do Fortinet: raízes do sistema, digest fixado em `trusted_certs`, Auto-trust e o digest do certificado recusado no `disconnected` (`tls.rs`, código comum; ver `fortinet-protocol.md`, seção "Conexões"). O gateway de validação recusa um hello só TLS 1.3 e aceita TLS 1.2 com ECDHE e AES-GCM (**obs**); o Engine usa a negociação padrão do rustls, que oferece os dois.

O canal de controle e o túnel chegam na mesma porta. As informações do servidor trazem um `tcpt_port` (443 nas referências); o Engine o ignora e usa a porta do Profile (**inf**).

## S-expression

O canal de controle e os quadros de controle do túnel levam texto numa S-expression própria do Check Point:

```
(CCCserverResponse
	:ResponseHeader (
		:id (2)
		:type (UserPass)
		:session_id ()
		:return_code (600))
	:ResponseData (
		:authn_status (continue)
		:message ("Hello world")
		:servers (
			: (10.0.0.1)
			: (10.0.0.2))
		:free (text here)))
```

- Todo nó fica entre parênteses. Um objeto tem nome opcional (`CCCserverResponse`) e campos `:nome (valor)`; uma lista tem itens `: (valor)`, com espaço ou nada entre `:` e `(`; um valor é uma palavra ou um texto entre aspas.
- `()` é o valor vazio, que também serve de objeto ou lista vazia.
- O texto entre aspas não tem escape. Valor com algo fora de letras, dígitos, `_`, `-` e `.` sai entre aspas. Valor sem aspas com espaços vai até o `)`, como o `:free (text here)` da amostra, lido como `text here` (**inf**).
- Algumas listas chegam como objeto de chaves numéricas (`:0 (...) :1 (...)`), como a lista de opções de login. O Engine lê as duas formas.
- Espaço, tab, quebra de linha e NUL separam os elementos. O Engine escreve um campo por linha, recuado com tab, como as referências (**ref**); não se sabe se o gateway exige esse layout.
- O Engine recusa aninhamento acima de 64 níveis, e o canal de controle recusa resposta HTTP acima de 4 MiB.

### Ofuscação

Valores secretos (credenciais, URL do IdP, chave da sessão, código do IdP, mensagem de erro) trafegam ofuscados por um esquema fixo, sem segredo nenhum (**ref**):

1. cada byte `b` na posição `i` vira `(b mod 255) XOR K[i mod 77]`, e um resultado 0 vira 255;
2. os bytes saem em ordem inversa;
3. em hex minúsculo.

`K` é a chave fixa de 77 bytes do protocolo, em ASCII: ``-ODIFIED&W0ROPERTY3HEET7ITH/+4HE3HEET)$3?,$!0?!5?02/0%24)%3.5,,`` seguido do byte `0x10` e de ``&7?70?/"*%#43``. Desofuscar é desfazer o hex, voltar à ordem original e aplicar o passo 1 de novo. O esquema devolve qualquer byte ASCII de 1 a 127; fora disso, e no NUL, dois bytes diferentes podem sair como o mesmo 255.

Amostras: `vpnconnect` vira `2345212b27292a2a3f5b`; o texto vazio vira o valor vazio.

## Canal de controle

Cada pedido é um `POST /clients/` numa conexão TLS nova, com `Connection: close`, `Content-Type: text/plain` e o corpo:

```
(CCCclientRequest
	:RequestHeader (
		:id (<n>)
		:type (<tipo>)
		:session_id (<sessão ou vazio>))
	:RequestData (...))
```

`id` conta a partir de 1 em cada Engine. Só o `Signout` e o `ClientSettings` levam também `:protocol_version (100)` no cabeçalho (**ref**). A resposta é `(CCCserverResponse :ResponseHeader (... :return_code (600)) :ResponseData (...))`; o Engine exige HTTP 200, o nome `CCCserverResponse` e o retorno `600` (sucesso), e usa o `ResponseData`.

### Identificação do cliente

Os pedidos levam `client_type (TRAC)`, a família de cliente que o gateway espera (a do Endpoint Security VPN, **ref**), e não o sistema. O pedido de login traz `client_logging_data` com `client_name ("VPN Connect")`, `client_ver (<versão do Helper>)` e `os_name (macOS)`: o Engine se declara como é. O snx-rs se declara Windows e manda também um `device_id`; se o gateway de validação recusar a identificação honesta, este trecho registra o motivo (a confirmar no #52).

## Login pelo IdP

1. **Informações do servidor**: pedido `ClientHello` com `:RequestData (:client_info (:client_type (TRAC) :client_version (1) :client_support_saml (true)))`. A resposta traz `connectivity_info:supported_data_tunnel_protocols`, uma lista com valores como `IPSec`, `SSL` e `L2TP`, e `login_options_data:login_options_list`, com as opções de login: cada uma tem `id`, `display_name` e `factors`, cujos `factor_type` dizem o tipo (`password`, `certificate`, `identity_provider`...). Sem `SSL` na lista, o login falha com "The gateway does not offer the SSL tunnel".
2. **Opção de login**: com o `realm` do Profile preenchido, a opção com esse `id`, que precisa ter um fator `identity_provider`; vazio, a única opção com esse fator. Sem nenhuma, com várias (a mensagem lista os ids) ou com a opção do Profile inexistente ou de outro tipo, o login falha. O `realm` só aceita até 64 caracteres entre letras, dígitos, `_`, `-` e `.`, conferidos antes de qualquer login (`Invalid login option`), e o Profile precisa ter `auth: "saml"`.
3. **Início da autenticação**: pedido `UserPass` com `client_type`, `username` e `password` vazios (ofuscados), o `client_logging_data` e `selectedLoginOption (<id>)`. A resposta traz `authn_status (continue)`, o `session_id` da autenticação e o `prompt` ofuscado, que desofuscado é a URL do IdP (**ref**). O Engine só aceita uma URL `https://`.
4. **Espera no navegador**: o Helper escuta em `127.0.0.1:7779`, a porta fixa para onde o portal do gateway manda o navegador no fim do login (**ref**), e só então emite `waiting-saml` com a URL do passo 3. Porta ocupada vira `disconnected` com "Local SSO port 7779 is already in use", que cita quem costuma ocupá-la (o Check Point Endpoint Security ou o snx-rs). A espera dura 120 s, o prazo do snx-rs.
5. **Código**: o navegador chega com `GET /<código>`. O listener é o mesmo do SAML do Fortinet (`browser_login.rs`: limite de tamanho e de conexões, 400 para qualquer outro pedido e o login continua). Vale só `GET` com um código de 1 a 1024 caracteres entre letras, dígitos e `-_.~%=+` (**inf**: o formato real do código não foi visto; o snx-rs aceita também `OPTIONS`).
6. **Resposta do desafio**: pedido `MultiChallange` (a grafia é a do protocolo), com o `session_id` da autenticação no cabeçalho e `:RequestData (:client_type (TRAC) :auth_session_id (<sessão>) :user_input (<código ofuscado>))`. A resposta de sucesso traz `authn_status (done)`, `is_authenticated (true)`, `active_key` (a chave da sessão, ofuscada), o `session_id` da sessão e `active_key_timeout`. `authn_status (done)` sem `is_authenticated (true)`, aqui ou no passo 3, é recusa do gateway (`cause: login-failed`), com o `error_message` desofuscado quando vier, sem caracteres de controle e cortado em 200 caracteres.

A chave da sessão e o código do IdP ficam no Helper: não vão em evento, log nem resposta.

### Respostas de erro

Só a recusa explícita do gateway nos passos 3 e 6 leva `cause: login-failed`; as outras falhas terminam em `disconnected` com a razão e sem `cause`. As do Profile são recusadas na resposta do `connect`, antes de qualquer contato com o gateway.

| Situação | Onde | Razão |
|---|---|---|
| `auth` diferente de `saml` | resposta do `connect` | "Check Point profiles sign in only through the identity provider (auth saml)" |
| `realm` fora do formato | resposta do `connect` | "Invalid login option" |
| Sem `SSL` em `supported_data_tunnel_protocols` | `disconnected` | "The gateway does not offer the SSL tunnel" |
| `realm` sem opção com esse `id` | `disconnected` | "The gateway has no login option <id>; available: <ids>" |
| `realm` de opção sem fator `identity_provider` | `disconnected` | "Login option <id> is not an identity provider login" |
| `realm` vazio e nenhuma opção de IdP | `disconnected` | "The gateway offers no identity provider login" |
| `realm` vazio e várias opções de IdP | `disconnected` | "The gateway offers several identity provider logins; set the login option to one of: <ids>" |
| Porta do listener ocupada | `disconnected` | "Local SSO port <porta> is already in use; close the app using it (e.g. Check Point Endpoint Security or snx-rs) and try again" |
| Sem código em 120 s | `disconnected` | "Identity provider login timed out after 120 s" |
| Desafio que não é do IdP, sem chave da sessão ou outro passo depois do código | `disconnected` | mensagem do passo |
| Recusa no `UserPass` ou no `MultiChallange` (`authn_status (done)` sem `is_authenticated (true)`) | `disconnected`, `cause: login-failed` | "Login failed: <error_message>" |
| Resposta do `UserPass` ou do `MultiChallange` sem `authn_status` ou com outro valor | `disconnected` | "Unexpected gateway answer to the login" |
| HTTP diferente de 200 ou `return_code` diferente de 600 | `disconnected` | "Gateway refused the request <tipo> (HTTP <n>)" ou "... with return code <n>" |

## Túnel

Nova conexão TLS na mesma porta, sem HTTP: direto os quadros, nos dois sentidos.

```
[tamanho: u32 big-endian][tipo: u32 big-endian][conteúdo]
```

- `tamanho` conta só o conteúdo. O Engine recusa quadro acima de 1 MiB.
- Tipo `1` é controle: a S-expression seguida de um NUL, que entra no tamanho.
- Tipo `2` é dado: um pacote IP cru, sem PPP.

### Apresentação da sessão

O primeiro quadro do cliente (**ref**):

```
(client_hello
	:client_version (2)
	:protocol_version (2)
	:OM (
		:ipaddr (0.0.0.0)
		:keep_address (false))
	:optional (
		:client_type (4))
	:cookie (<chave da sessão, desofuscada>))
```

### Resposta inicial

O gateway responde com o `hello_reply`, ou com `(disconnect :code (<n>) :message (<texto>))` quando recusa a sessão:

```
(hello_reply
	:version (1)
	:protocol_version (1)
	:OM (
		:ipaddr (10.20.30.40)
		:dns_servers (
			: (10.1.0.53)
			: (10.1.0.54))
		:dns_suffix ("corp.example,lab.example"))
	:range (
		: (
			:from (10.1.0.0)
			:to (10.1.255.255)))
	:timeouts (
		:authentication (43200)
		:keepalive (20))
	:optional (
		:subnet (255.255.255.0)))
```

| Campo | Uso |
|---|---|
| `OM:ipaddr` | IP do túnel (Office Mode); também vira o par da interface, porque o protocolo não dá par |
| `OM:dns_servers` | servidores DNS |
| `OM:dns_suffix` | sufixos DNS, separados por vírgula ou `;`, ou como lista |
| `range` | redes a rotear, como intervalos `from`–`to`; opcional, ver "Faixas de rede" |
| `timeouts:authentication` | `expires_at` = início do login + segundos; `0` ou ausente = sem expiração; teto de 30 dias |
| `timeouts:keepalive` | intervalo do keepalive em segundos; `0` ou ausente vale 20 (**inf**); teto de 3600 |
| `optional:subnet` | ignorado: a interface é ponto a ponto |

- Valor de `timeouts` acima do teto vale o teto, e ilegível conta como ausente; os dois saem no log.
- O MTU é 1350, o do snx-rs: nenhum campo de MTU é conhecido (**inf**).
- Cada intervalo vira os blocos CIDR que o cobrem, do maior alinhado em diante. Amostras: `10.1.0.0`–`10.1.255.255` vira `10.1.0.0/16`; `172.16.4.0`–`172.16.6.255` vira `172.16.4.0/23` e `172.16.6.0/24`; `10.0.0.1`–`10.0.0.6` vira `.1/32`, `.2/31`, `.4/31` e `.6/32`; `0.0.0.0`–`255.255.255.255` vira a rota default, que a camada de rede aplica em duas metades. Intervalo invertido não dá rota.
- O snx-rs descarta intervalos que começam em `0.0.0.1`; o Engine roteia o intervalo como vem (**inf**: o significado desse início não é conhecido).
- Os domínios DNS do Profile substituem os sufixos do gateway, como no Fortinet.

### Faixas de rede (`ClientSettings`)

No gateway de validação o `hello_reply` não traz `range` (**obs**): as redes vêm de um pedido `ClientSettings` no canal de controle, que o Engine faz depois do `hello_reply` e antes de entregar o túnel à sessão, com o `session_id` da sessão autenticada (o do passo 6 do login) no cabeçalho (**ref**; é como o snx-rs obtém as rotas nesse gateway):

```
:RequestData (ClientSettings
	:requested_policies_and_current_versions (
		:range ()))
```

A lista `range` vazia pede a política de faixas sem versão conhecida (**inf**). A resposta traz as políticas em `updated_policies`, cada uma com `settings`, `expiry`, `id` e `name`; as faixas ficam em `updated_policies:range:settings`, uma lista de `(:from (<ip>) :to (<ip>))` (**ref**):

```
:ResponseData (
	:gw_internal_ip (10.1.0.1)
	:updated_policies (
		:range (
			:settings (
				: (
					:from (10.1.0.0)
					:to (10.1.255.255)))
			:expiry (0)
			:name (range))))
```

- As rotas são a união das faixas do `range` do `hello_reply`, quando vier, com as do `ClientSettings`, sem repetir bloco. Cada faixa vira blocos CIDR como na seção anterior.
- O resto da resposta (`gw_internal_ip`, outras políticas como `mep` e `scv`) é ignorado.
- A faixa que é exatamente o /32 do próprio gateway sai das rotas, com log, como no Fortinet: ela colidiria com o /32 pela interface física.
- Falha do `ClientSettings` (HTTP, `return_code` ou resposta ilegível) sem `range` no `hello_reply` derruba o `connect`, com `Signout`: sem rota o túnel pareceria conectado e não passaria nada. Com `range` no `hello_reply`, a falha sai no log e o túnel sobe com essas faixas.
- Nenhuma faixa no fim, de nenhuma das duas fontes, também derruba o `connect`.

| Situação | Razão no `disconnected` |
|---|---|
| `ClientSettings` falhou e o `hello_reply` não trouxe `range` | "Could not get the network ranges from the gateway: <motivo>" |
| Nenhuma faixa no `hello_reply` nem no `ClientSettings` | "The gateway announced no network ranges for the tunnel" |

### Com o túnel de pé

- Dados nos dois sentidos, um pacote IP por quadro.
- O cliente manda `(keepalive :id (0))` a cada intervalo de `timeouts:keepalive`, contado da abertura do túnel, e o gateway responde com o mesmo quadro.
- Cada intervalo sem resposta conta uma falta; a resposta zera a contagem. Na terceira falta seguida o túnel cai com `Tunnel dropped: no response from the gateway` (`cause: tunnel-dropped`): três intervalos depois da última resposta, com dois keepalives sem resposta no meio.
- Troca de rede ou wake: a sessão move o /32 do gateway para a rota default nova e pede uma sondagem, que é um keepalive fora de hora. Ele não conta falta; se o gateway não responder, as faltas seguem nos ticks normais.
- Outros quadros de controle do gateway que não são `keepalive` nem `disconnect` são ignorados.
- `disconnect` do gateway e conexão fechada derrubam o túnel na hora. Uma escrita que não termina em três intervalos (TCP meio aberto) também derruba.
- Em qualquer queda a sessão desfaz interface, rotas e DNS, sem `Signout`.

### Prazos

- `expires_at` é o início do login mais `timeouts:authentication`; a sessão emite `expiring` 15 minutos antes e encerra com `cause: expired` no horário, como no Fortinet.
- A sessão confere o relógio de parede a cada 10 s, além de dormir até o prazo: depois de um sleep do Mac, o aviso e a expiração saem no primeiro tick.

## Signout

No `disconnect` do usuário, a sessão fecha o túnel, desfaz a rede e manda o pedido `Signout` com o `session_id` da sessão no cabeçalho e `:RequestData ()`, dentro do prazo curto que a sessão já impõe: um gateway mudo não segura a desconexão.
