# Trait de Engine e Engine Check Point próprio

**Status:** aceito, desde a trait de Engine (spec #43). Substitui o trecho "Sem trait de Engine por enquanto" do [ADR 0002](0002-own-engine-replaces-openfortivpn.md); o resto do 0002 continua valendo.

O ADR 0002 adiou a abstração entre a sessão do Helper e o Engine até existir um segundo Engine. Esse momento chegou: o Helper vai hospedar um Engine Check Point ao lado do Fortinet. Enquanto a sessão chamar os tipos do Fortinet e conhecer cookie, OTP e push, cada Engine novo seria uma edição da sessão. Decidimos pôr uma **trait de Engine** entre a sessão e os Engines, com o Fortinet como primeira implementação, e escrever o Engine Check Point do zero atrás dela.

- **A trait tem três operações, desenhadas só a partir dos dois Engines reais.** O `login` recebe as credenciais do `connect` e avisa a sessão das esperas pelo usuário (login no navegador, com a URL; push no celular). O que o login produz (cookie, chave de sessão) fica dentro do Engine, e a falha diz se foi recusa do gateway ou outro erro. O `open_tunnel` devolve a configuração para a camada de rede, o canal de pacotes IP e um controle do túnel, que avisa quando o túnel morreu e aceita um pedido de sondagem imediata. O `logout` encerra a sessão no gateway.
- **O Engine nasce do Profile.** O construtor de cada Engine recebe o Profile e valida o que é dele antes de qualquer login. A sessão escolhe o Engine pelo campo `engine` do Profile.
- **A sessão fica com o que não é protocolo.** Máquina de estados, eventos, cancelamento, prazo do logout, expiração, banda, troca de rede, regras de DNS (fallback e domínios do Profile), aplicação e desmonte da rede e a supervisão de pânico continuam na sessão.
- **O que é comum sai de dentro do Fortinet.** O tipo do Profile (`profile.rs`), a confiança de certificado com raízes do sistema, digest fixado, Auto-trust e digest recusado (`tls.rs`) e o listener de loopback do login pelo navegador (`browser_login.rs`). A validação do que chega ao listener é de cada Engine.
- **Escopo do Engine Check Point: túnel SSL com login pelo provedor de identidade (IdP).** É o túnel do SNX: uma conexão TLS com quadros de controle e de dados, sem PPP, com login pelo canal de controle do gateway e espera no navegador, num listener local na porta fixa 7779. Ficam fora IPsec (IKEv1 e IKEv2), L2TP, login por senha, certificado, OTP ou desafio em vários passos, o portal Mobile Access e a verificação de postura.
- **Projetos AGPL e GPL só como referência de protocolo.** snx-rs (AGPL-3.0) e cpyvpn (GPLv3) servem para entender o protocolo Check Point. Não se copia, não se traduz, não se linka e não se roda nenhum deles como subprocesso. O protocolo é documentado no repositório a partir do que for entendido e observado, e o projeto continua sob MIT.

## Considered Options

- **Manter tipos concretos e ramificar a sessão por Engine**: cada Engine novo vira um `match` espalhado pela sessão, que continua conhecendo cookie, OTP e push.
- **Rodar o snx-rs como processo externo**: repete o problema do openfortivpn que o ADR 0002 resolveu (o Helper não vê a sessão depois que o processo sobe) e traria a AGPL para o bundle.
- **Portar código do snx-rs ou do cpyvpn**: traria a licença deles para o projeto. Descartado em favor de implementação limpa, como no Fortinet.
- **Uma trait mais larga, com passos do login expostos à sessão**: obrigaria a sessão a conhecer o desafio de cada protocolo, que é o que a trait existe para esconder.

## Consequences

- Um Engine novo é um módulo novo atrás da trait, mais a escolha dele pelo `engine` do Profile, sem edição na lógica da sessão.
- A prova da trait é a suíte da sessão do Helper, que fala o protocolo v2 diante de um gateway falso. A trait não ganha testes próprios.
- A distinção entre recusa do gateway e outra falha no login existe no Engine antes de aparecer no protocolo do Helper, onde vira `cause: login-failed`.
- Os ajustes de teste dos Engines (intervalo de sondagem e prazo do push; depois, a porta do listener do Check Point) passam pela sessão num tipo só, sem a sessão saber o que cada um significa para o protocolo.
- Se o gateway desligar o túnel SSL, o caminho é IPsec com IKEv2, que vira uma decisão própria e bem maior.
