# Canal seguro de credenciais entre as Centrais

Status: plano, nada implementado. Pedido do Leonardo em 13/10/2026 11:22 (via CENTRAL): as Centrais (a nossa e a da Six, no Mac do Ricardo) precisam trocar token da Meta, senha de painel e chave de API com frequência, com autorização dele, sem que o valor apareça em texto no grupo, no banco ou na sessão.

## Recomendação

Envelope selado de ponta a ponta, gerado e aberto pelo keyfence, que viaja pela ponte MCP como texto cifrado. Cada Central tem um par de chaves (X25519 para receber, Ed25519 para assinar). O remetente sela direto do cofre, sem ver o valor; a ponte carrega só o envelope e os metadados; o destinatário abre e grava no cofre dele com nome. O Leonardo aprova no painel antes de cada selagem. Tudo com `node:crypto`, zero dependência nova.

Não implantar o keyfence "dentro da ponte": o hook do keyfence vigia o que um agente digita e lê, não o servidor. Na ponte o valor em claro já passou por quem o enviou. O que a ponte ganha é uma regra de recusa (item 5).

## 1. Modelo de ameaça: onde o valor vaza hoje

Verificado no código e em prova desta máquina:

| Onde | Situação | Base |
|---|---|---|
| Banco da Central, WhatsApp | Mensagem guardada crua. Em 08/10 a prova de envio achou o valor em claro na linha do `central.db` (esperado pela regra do PLANO) | prova de runtime, `prova_envio.py` |
| Grupo de WhatsApp das Centrais | Texto fica nos celulares, nos backups do WhatsApp e no sync do `wacli`. Apagar a mensagem não alcança backup | desenho do canal; backup não verificado |
| `ponte_mensagens` | `mascararSegredos` troca padrões conhecidos (sk-, EAA, JWT, `senha:`) antes de gravar (`apps/conector/src/ponte.ts` linhas 118 a 150). Senha de painel sem rótulo passa | código lido |
| Transcrição de sessão | Todo texto que um agente lê vira linha em `~/.claude/projects/**/*.jsonl`. Em 08/10 achei a senha de app do Gmail só olhando a transcrição da sessão CENTRAL | prova de runtime |
| Webhook para a Six | POST assinado, mas o corpo chega em claro e é gravado do lado dela | `entrega-ponte.ts` lido; TLS e retenção do lado da Six não verificados |
| Protocolo atual | `docs/protocolo-entre-centrais.md`, regra 6: "credencial vai como arquivo e é apagada depois que a outra confirma". Arquivo no WhatsApp passa por banco, backup e sessão | doc lido |

O keyfence hoje não cobre esse caso: capta só o que o humano digita (`stripNotTyped` descarta mensagem de outra sessão, PR 17), `keyfence secret add` só aceita valor num terminal real, e não existe comando de cifrar para outra máquina nem de importar valor cifrado. Cofre local é AES-256-GCM com a chave no Keychain (`src/vault.js`).

## 2. Desenho

Primitivas (todas em `node:crypto`, X25519 conferido nesta máquina):

- Chave de recebimento X25519 e chave de assinatura Ed25519 por Central. Privadas no Keychain, mesmo mecanismo da chave do cofre (arquivo 0600 fora do repo onde não há Keychain). Públicas não são segredo e podem viajar pela ponte.
- Selar (ECIES): par X25519 efêmero, segredo compartilhado com a chave de recebimento do destinatário, HKDF-SHA256, AES-256-GCM. Os metadados (id, de, para, nome do segredo, validade, nonce) entram como dados autenticados (AAD), então trocar o destinatário ou estender a validade quebra a decifragem.
- Assinar: Ed25519 do remetente sobre o envelope inteiro. O destinatário confere a quem pertence antes de abrir.
- Formato: `kfseal1:` mais hex minúsculo. Medi a máscara da ponte sobre 5.000 envelopes sintéticos de 300 bytes: 0 alterados em hex e 0 em base64url. Hex minúsculo fica de reserva porque não casa com `EAA`, `AKIA` nem `sk-`. Um token Meta de 200 bytes vira cerca de 600 caracteres, abaixo do teto de 4.000 do campo `texto`.

Comandos novos no keyfence:

```
keyfence peer add six <chave-publica>     fixa a Central parceira (confirma a impressão digital)
keyfence peer list | rm
keyfence seal <alias> --para six --validade 24h --motivo "..."   lê do cofre, imprime só o envelope
keyfence unseal [arquivo|-] --como NOME   confere assinatura, validade e id único, grava no cofre
```

O agente nunca vê o valor: `seal` lê do cofre por dentro e `unseal` grava por dentro. Isso é uma exceção deliberada à regra "valor só em terminal real" do `secret add`, porque aqui o que entra é texto cifrado e assinado, nunca o valor em claro.

Fluxo: o Studio sela `meta/segsmart`, manda `ponte_enviar` com `fato: "segredo selado META_SEGSMART, validade 24h"` e o envelope em `texto`; a Six roda `keyfence unseal` e usa por nome (`$META_SEGSMART`).

Alternativas descartadas:

- age ou GPG: dependência binária que a Six teria que instalar (nem `age` nem `rage` existem no Studio; `gpg` existe, mas keyring e UX são piores), e `node:crypto` já traz as primitivas.
- Chave simétrica combinada entre as Centrais: uma chave de vida longa que, vazada, abre todo o histórico, e sem autenticar quem enviou.
- Link de uso único em serviço de terceiros: um cofre a mais para confiar, fora do nosso controle e do log.
- Keyfence "na ponte": o valor já saiu em claro de quem enviou; só serve como rede de recusa.

## Primeiro caso de uso: tokens novos do BM

Em 13/10/2026 o Leonardo revogou os tokens Meta que estavam no cofre (`META_ACCESS_TOKEN`, `META_TOKEN` e `META_SECRET` em `~/.config/keyfence/secrets.env`, e `META_ACCESS_TOKEN` em `~/segsclaw/.env`). Os valores ficam marcados como revogados, sem apagar, com o registro em `~/.config/keyfence/revogados.md`. Os tokens novos do BM da SegSmart e da FM Rocket chegam da Six por este canal e entram com nome novo, nunca sobre o nome antigo: `META_BM_SEGSMART_TOKEN` e `META_BM_FMROCKET_TOKEN`. Nome novo evita que uma sessão use sem querer o valor morto guardado sob o nome velho, e deixa o histórico de rotação intacto. É o teste de aceite real do MVP: se o token novo chegar sem aparecer no grupo, no banco nem na transcrição, o canal serve.

## 3. Aprovação, revogação e rotação

Aprovação do Leonardo, antes de cada envio: `seal` abre um pedido pendente (alias, destinatário, validade, motivo) e só emite o envelope depois do toque dele no painel, que consome um `aprovacao_id` de uso único. A Central já lista aprovações (`central` mostra aprovações pendentes); o encaixe exato é trabalho da sessão CENTRAL-DEV e não foi verificado.

- Validade curta por padrão (24 h). `unseal` recusa envelope vencido ou repetido (id único registrado).
- Revogação: o envelope vencido ou revogado não abre mais. `keyfence secret revoke` já existe para o cofre local.
- Limite honesto: depois de aberto, o destinatário tem o valor. Só a rotação na origem desfaz isso. Por isso o `seal` grava `compartilhado_com` e a data no registro do segredo, e o `maintain` passa a listar esse segredo em "para rotacionar" quando a validade acaba.

## 4. Como a Six adota sem depender de nós

- A especificação cabe numa página (formato, KDF, AAD, ordem dos campos) e vem com vetores de teste.
- Implementação de referência avulsa: um arquivo único com `node:crypto`, sem `npm install`, que a Six copia. Se ela já usa o keyfence, os mesmos comandos valem.
- Ela gera o próprio par, manda a chave pública pela ponte, e Leonardo e Ricardo conferem a impressão digital curta por voz ou por outro canal. Sem confiar na ponte para a primeira troca.
- O que a Six precisa decidir sozinha: onde guarda a privada no Mac do Ricardo (Keychain ou arquivo 0600).

## 5. Menor primeiro passo funcional e custo

MVP sem painel, aprovação manual (confirmação no terminal pelo Leonardo): `peer`, `seal`, `unseal`, spec e vetores de teste.

| Entrega | Horas |
|---|---|
| `peer`, `seal`, `unseal` com `node:crypto`, testes com vetores e adulteração (destinatário trocado, validade, repetição) | 6 a 8 |
| Script avulso e página de spec para a Six | 2 |
| Recusa na ponte: `ponte_enviar` devolve erro `SEGREDO_EM_CLARO` quando o `texto` parece segredo e não é envelope `kfseal1:` (hoje só mascara e segue) | 2 |
| Aprovação no painel da Central (CENTRAL-DEV) | 4 a 6 |
| Total MVP / completo | 8 a 10 / 16 a 18 |

Prova de aceite do MVP: enviar um token inventado do Studio a uma segunda instalação (HOME alternativo), abrir lá, e fazer `grep` do valor no `central.db`, nos logs do conector e na transcrição da sessão. Resultado esperado: zero ocorrências.

## Não verificado

- Retenção e backup do WhatsApp e do `wacli`.
- Se o log do conector grava corpo de mensagem (a auditoria grava id e erro).
- TLS e retenção do webhook do lado da Six; plataforma e Keychain do Mac do Ricardo.
- Como a tabela de aprovações da Central aceita um pedido de `seal` e um `aprovacao_id`.
- Se a Central apaga hoje o "arquivo de credencial" depois da confirmação, como manda a regra 6.
