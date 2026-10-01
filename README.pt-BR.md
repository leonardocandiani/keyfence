<!-- readme-padrao:header -->
<!-- Banner -->
<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:00d9ff&height=200&section=header&text=keyfence&fontSize=54&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Impede%20que%20segredos%20vazem%20das%20sess%C3%B5es%20de%20agentes%20de%20c%C3%B3digo%20e%20organiza%20tudo%20num%20cofre%20local&descAlignY=58&descSize=16" alt="keyfence" width="100%" />
</div>

<!-- Typing -->
<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=21&duration=2800&pause=900&color=00d9ff&center=true&vCenter=true&width=840&lines=Cole+o+token+no+chat+e+siga+trabalhando;Salvo+como+credencial%3A+servi%C3%A7o%2C+conta%2C+login%2C+senha;Acha+as+chaves+que+j%C3%A1+est%C3%A3o+no+disco+e+organiza;Barrado+no+curl%2C+no+commit%2C+no+MCP+e+no+c%C3%B3digo" alt="Cole o token no chat e siga trabalhando" />
</div>

<div align="center">

  <p><strong>Um hook do Claude Code e um cofre local: toda credencial que entra na sessão é guardada com nome e barrada em toda saída.</strong></p>

  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00d9ff?style=for-the-badge" alt="License: MIT" /></a>
    <a href="https://docs.claude.com/en/docs/claude-code"><img src="https://img.shields.io/badge/Made%20for-Claude%20Code-D97757?style=for-the-badge&logo=anthropic&logoColor=white" alt="Made for: Claude Code" /></a>
    <a href="https://github.com/leonardocandiani/keyfence/releases"><img src="https://img.shields.io/github/v/release/leonardocandiani/keyfence?display_name=tag&style=for-the-badge&color=00d9ff&labelColor=1a1a2e" alt="Release" /></a>
    <a href="https://github.com/leonardocandiani/keyfence/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/leonardocandiani/keyfence/test.yml?style=for-the-badge&labelColor=1a1a2e&label=CI" alt="CI" /></a>
    <img src="https://img.shields.io/badge/node-18%2B%20zero%20deps-1a1a2e?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="node: 18+ zero deps" />
    <a href="https://github.com/leonardocandiani/keyfence/pulls"><img src="https://img.shields.io/badge/PRs-welcome-1a1a2e?style=for-the-badge" alt="PRs: welcome" /></a>
  </p>

  <p><a href="README.md">Read in English</a></p>

  <p>
    <a href="#o-que-faz">O que faz</a> •
    <a href="#o-que-detecta">O que detecta</a> •
    <a href="#o-que-não-faz">O que não faz</a> •
    <a href="#configuração">Configuração</a> •
    <a href="#o-classificador-opcional">O classificador opcional</a> •
    <a href="#o-cofre">O cofre</a> •
    <a href="#mantendo-organizado">Mantendo organizado</a> •
    <a href="#licença">Licença</a>
  </p>
</div>

<br>

> **keyfence** marca toda credencial que entra numa sessão de agente e guarda como credencial: colada no prompt, impressa por um comando ou já parada num `.env`, ela ganha um registro no cofre local criptografado (`sis/robson`: login e senha), um nome que o agente usa (`$SIS_ROBSON_PASSWORD`) e um bloqueio em toda saída, seja um `curl`, um commit, uma ferramenta MCP ou uma config no código.

> Sem afiliação ou endosso da Anthropic. "Claude" e "Claude Code" são marcas da Anthropic.

## O que é

```yaml
produto:     hook do Claude Code e cofre local que guarda e organiza credenciais
plataforma:  macOS, Linux e Windows (Bash e PowerShell)
captura:     credencial colada de qualquer jeito vira registro: serviço, conta, login, senha
detecta:     53 formatos · valores com rótulo · links com ?key= · classificador por contexto
cofre:       AES-256-GCM, chave mestra no Keychain do macOS, nenhum comando imprime valor
organiza:    discover acha chaves no disco · tidy renomeia as antigas · maintain roda todo dia
saída:       barrado na rede, no commit, em ferramenta não local, no código e em arquivo do git
resultado:   a saída das ferramentas chega ao agente com o nome no lugar do valor
privacidade: o classificador só vê a forma do valor (aaa999), nunca o valor
instalação:  npm install -g github:leonardocandiani/keyfence · keyfence install
licença:     MIT
```

<!-- /readme-padrao:header -->

Agentes de código leem seus arquivos, rodam seus comandos e falam com a
rede. Uma credencial que entra na sessão, seja porque você colou, porque o
agente leu um `.env`, ou porque um comando a imprimiu, pode acabar num `curl`,
num commit, numa config com valor fixo no código ou numa mensagem enviada por
uma ferramenta MCP. O keyfence é um hook do Claude Code que vigia todo lugar
por onde um segredo pode entrar e todo lugar por onde pode sair.

```
npm install -g github:leonardocandiani/keyfence
keyfence install
```

Isso registra o hook em `~/.claude/settings.json` para os três eventos que ele
usa (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`). Passa a valer na próxima
chamada de ferramenta de toda sessão, incluindo as que já estão rodando.
`keyfence uninstall` remove e mantém um backup das suas configurações.

Requer Node 18 ou mais recente. Testado no Claude Code 2.1.280; a injeção e a
limpeza de saída dependem dos campos `updatedInput` e `updatedToolOutput` do
hook.

## O que faz

Cole um token no chat e continue trabalhando:

```
you:    here is the Meta token: EAAG...
agent:  (told: saved to .env as $META_ACCESS_TOKEN, use it by name)
agent:  curl https://graph.facebook.com/v21.0/me -H "Authorization: Bearer $META_ACCESS_TOKEN"
        keyfence loads .env into that command; the value never appears in it
output: {"token": "⟨META_ACCESS_TOKEN⟩", ...}
        any output that contains the value reaches the agent with the name instead
```

O token é salvo no instante em que você envia a mensagem, no `.env` do
repositório quando o git o ignora, senão num `~/.config/keyfence/secrets.env`
privado (ambos `0600`). Os valores são colocados entre aspas para o arquivo
recarregar intacto com `source`, mesmo com aspas ou `;` dentro.

Ele é salvo como uma **credencial**, não como um valor solto: qual serviço, de
quem é a conta, e qual valor é o login, a senha, o token ou a URL.

```
you:  login=robson.silva@empresa.com.br
      senha=********
      (in the SIS-api project)

keyfence: vault record  sis/robson  (login, password)
          .env          SIS_ROBSON_LOGIN, SIS_ROBSON_PASSWORD
```

| Você envia | Salvo como |
|---|---|
| um login e uma senha | um registro `service/account` com os dois; o serviço nomeado pelo contexto da mensagem, a conta a partir do login |
| uma senha nova para uma conta que o keyfence já tem | uma **rotação** desse registro; o login permanece, a versão antiga é mantida |
| o token de um provedor conhecido | o nome que o SDK dele lê: `META_ACCESS_TOKEN`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`... |
| `PAINEL_PASSWORD=...` | o nome que você escreveu |
| um link com `?key=...` | o host da API mais o tipo: `PLACAFIPE_API_KEY` |

**Nomeada pelo contexto, não por uma palavra solta.** Quando nada no próprio
valor a nomeia (nenhum formato de provedor, nenhum nome que você escreveu,
nenhum link), a credencial é salva na hora sob um código provisório, `kf/7f3a`
e `KF_7F3A_PASSWORD`, para que a sessão nunca espere e cem capturas não virem
cem `PASSWORD` ou `AQUI_PASSWORD`. Depois, em segundo plano, o classificador lê
a mensagem com todo valor mascarado e responde, para cada segredo e cada
palavra, se aquela palavra nomeia o serviço a que ela pertence. A credencial é
renomeada para a resposta no cofre, no arquivo de ambiente e na sessão, e o
agente recebe os novos nomes no próximo resultado de ferramenta:

```
you:   agora com o acesso aqui:
       ### Cpanel - lojaexemplo.com.br
       Usuário: lojaadm
       Senha: ********

at once:        kf/9a4a               KF_9A4A_LOGIN, KF_9A4A_PASSWORD
seconds later:  lojaexemplo/lojaadm   LOJAEXEMPLO_LOJAADM_LOGIN, LOJAEXEMPLO_LOJAADM_PASSWORD
```

Não existe uma lista de palavras para pular: toda palavra com cara de nome é
candidata e o contexto decide. Palavras com dígito e tudo o que a sessão
protege nunca vão ao classificador às claras. Medido ao vivo em mensagens
escritas do jeito que as pessoas mandam (`node test/naming-eval.js`): 12 de 12
nomeadas certo, três rodadas seguidas, "aqui" nunca escolhida. Sem o
classificador, o nome vem da estrutura da mensagem (um domínio nela) ou do
projeto, nunca de uma palavra solta. Uma palavra que é uma conta que o cofre
já conhece para aquele serviço ("nova senha do robson no sis") faz dela uma
rotação de `sis/robson`.

`keyfence maintain` faz o mesmo, uma vez, para credenciais que uma versão
antiga nomeou a partir de uma palavra solta, quando a mensagem ainda está nos
logs da sessão. Só nomes que o keyfence gerou são renomeados; um nome que você
escolheu nunca é tocado. Todo registro é marcado como exposto, já que veio
pelo chat, e `keyfence secret list` mostra isso.

Por baixo, o keyfence trabalha em três camadas.

**1. Ele mantém segredos fora da transcrição, antes de qualquer coisa.** Ler
um arquivo de cofre (`.env`, `~/.aws/credentials`, chaves SSH, `.npmrc`,
`.pgpass`, o arquivo de credenciais do Claude Code) é negado, seja pela
ferramenta Read, pela ferramenta Grep ou por `cat`, `grep`, `jq`, `sed` e
afins num shell, incluindo via `ssh host cat ...`. Usar o arquivo é permitido:
`source .env`, `set -a; . .env`, passá-lo pro programa que precisa dele.

**2. Ele lembra de todo segredo que vê, por hash.** Segredos colados no seu
prompt e segredos que aparecem na saída de uma ferramenta são registrados como
prefixos SHA-256 num arquivo por sessão, no diretório temporário do sistema.
O valor nunca é armazenado.

**3. Ele bloqueia a saída de segredos lembrados.** Antes de toda chamada de
ferramenta, o comando ou conteúdo é dividido em pedaços (incluindo pedaços
decodificados de base64) e recebe hash. Um segredo lembrado é negado quando
iria para:

- a rede: `curl`, `wget`, `ssh`, `scp`, `gh`, CLIs de nuvem, e one-liners como
  `node -e "fetch(...)"` ou `python3 -c "requests.post(...)"`
- um commit, tag ou push
- qualquer ferramenta que não seja local: ferramentas MCP, WebFetch,
  publicação de artifact, e ferramentas adicionadas em versões futuras
  (negado por padrão). Ferramentas cujo trabalho é armazenar um segredo, como
  definir uma variável de ambiente num provedor de hospedagem, são permitidas.
- um arquivo de código (`.js`, `.py`, `.sh`, `.yml`, `.json`...) ou qualquer
  arquivo que o git rastreia

Escrever num `.env` ou noutro arquivo ignorado pelo git passa. Independente de
estar marcado, um segredo de alta confiança escrito num arquivo rastreado pelo
git também é negado.

Cópias contam como o segredo. `export K=<key>` ou `echo <key> > /tmp/k` é
local e passa, mas a variável e o arquivo ficam marcados, então um
`curl -d "$K"` ou `curl -d @/tmp/k` posterior é negado como o literal seria.
Arquivos de ambiente e de credenciais são a exceção de propósito: `source .env`
seguido de uma chamada que usa a variável dele é o jeito certo de usar uma
chave. Enviar o próprio arquivo de cofre (`curl -d @.env`) é negado.

A saída da ferramenta é limpa antes do agente vê-la: um segredo lembrado, ou
qualquer um novo que o keyfence reconhece, é substituído pelo nome da variável
ou por `⟨keyfence:rule⟩`. Uma chave que um comando imprime por acidente nunca
chega ao modelo.

## O que detecta

```
keyfence rules
```

- **53 formatos de provedor**: Anthropic, OpenAI, OpenRouter, estilo DeepSeek
  `sk-`, Hugging Face, Replicate, Groq, xAI, Perplexity, AWS, Google (chave de
  API, segredo OAuth e token), armazenamento Azure, DigitalOcean, Tailscale,
  Doppler, Fly.io, Heroku, GitHub (clássico e de granularidade fina), GitLab,
  npm, PyPI, Stripe (chaves e segredos de webhook), Asaas, Mercado Pago, Slack
  (tokens e webhooks), Discord (tokens de bot e webhooks), bots do Telegram,
  Meta / WhatsApp Cloud API, Twilio, SendGrid, Mailgun, Resend, Postmark,
  Supabase (chaves de acesso e secretas), Notion, Linear, Shopify, Atlassian,
  Figma, Sentry, chaves privadas, JWTs, headers Bearer, e URLs com senha
  embutida.
- **Valores rotulados**: `token=...`, `"client_secret": "..."`, `senha: ...`,
  `export DB_PASSWORD=...`, em inglês, português e espanhol, filtrados para
  placeholders (`${VAR}`, `<your-token>`, `changeme`), código
  (`options.apiKey`, `getToken(`), identificadores, aliases (`billing/api`),
  seletores CSS e senhas padrão. Um valor hex minúsculo ou UUID conta quando
  um rótulo diz que é uma chave; sem rótulo é tratado como hash de commit.
- **Credenciais em links**: `?key=`, `?apikey=`, `&token=`, `?access_token=`,
  `?password=` e parâmetros de query parecidos em qualquer URL.
- **Strings de alta entropia** sem rótulo ou prefixo conhecido, só no seu
  próprio prompt. A saída de ferramenta é cheia de ids aleatórios, então essa
  camada não roda lá.
- **Classificador opcional** para prosa ("a senha do wifi é abc123"), veja
  abaixo.

JWTs `anon` do Supabase são ignorados: são públicos por design.

## O que não faz

Nenhuma proteção baseada em texto é completa, e esta diz onde ela é cega:

- **Imagens.** Uma chave num screenshot é invisível para ela.
- **Sua própria mensagem.** Um hook do Claude Code não pode reescrever o
  prompt, então a mensagem que carrega um token colado chega ao modelo uma
  vez, do jeito que você escreveu. O keyfence a salva e protege cada passo
  depois disso. Para exposição zero, use `promptMode: "block"`: a mensagem é
  recusada antes do modelo vê-la (o Claude Code ainda mantém o original no log
  local da sessão).
- **A resposta do agente.** Se o agente imprime um segredo na resposta dele,
  esse texto já está na tela; o hook só vê chamadas de ferramenta.
- **Evasão deliberada.** Cópias diretas para uma variável ou um arquivo são
  seguidas, mas um segredo dividido em partes e remontado em tempo de
  execução, ou copiado duas vezes (`K2=$K`), não vai bater. O keyfence impede
  acidentes e automação descuidada, não um adversário que controla o agente.
- **Para onde o segredo vai.** O keyfence não consegue distinguir
  `api.stripe.com` de um endpoint de coleta de dados. Uma chave carregada de
  `.env` para uma variável pode ser enviada para qualquer host; a proteção
  está no valor literal e nas cópias dele, não no destino.
- **Senhas curtas só de letras** que parecem um identificador (`fooBarBazQu`)
  são ignoradas de propósito, porque sinalizá-las sinalizaria seu código
  também. A suíte de testes mede isso em menos de 1% desses valores.
- **Uma senha sem nenhuma palavra ao redor.** "log in with leo and x7!kq92"
  não tem rótulo, formato conhecido nem palavra de acesso, então nada pega.
  Quando uma mensagem carrega uma credencial que o keyfence não consegue
  isolar, o agente é instruído a salvá-la em `.env` por conta própria e seguir
  em frente; você nunca precisa reenviá-la.
- **Aspas, `;` ou `,` nos primeiros 8 caracteres de uma senha** encerram o
  valor antes que a regra de rótulo consiga lê-lo. Sem o classificador nada
  pega isso; guarde esse valor no `.env` você mesmo.
- **Várias palavras candidatas para o classificador.** Quando o classificador
  sinaliza uma mensagem com mais de um possível segredo, todas ficam
  protegidas mas nenhuma é salva, porque chutar qual é a senha seria pior.
- **Formatos desconhecidos.** Uma credencial sem rótulo, sem prefixo conhecido
  e com baixa aleatoriedade não é detectada. A camada de alta entropia e o
  classificador reduzem isso; não fecham completamente.

## Configuração

Opcional, em `~/.config/keyfence/config.json` (ou o caminho em
`KEYFENCE_CONFIG`). Toda chave é opcional.

```json
{
  "promptMode": "capture",
  "capture": { "target": "project", "globalFile": "~/.config/keyfence/secrets.env", "inject": true },
  "redactOutput": true,
  "ttlHours": 12,
  "taintAmbiguousFromPrompt": true,
  "vault": { "extraPatterns": ["(^|/)my-service\\.plist$"] },
  "egress": {
    "allowTools": ["__(create|edit|update)_(project_)?env"],
    "blockNewSecretsInTrackedFiles": true
  },
  "jev": { "enabled": false }
}
```

`promptMode` é `capture` (salva e segue), `warn` (só protege) ou `block`
(recusa a mensagem). `keyfence config` mostra o que está em vigor.

## O classificador opcional

As regras resolvem os formatos que conhecem, em milissegundos. Tudo o mais
que pode ser uma credencial é julgado **palavra por palavra, pelo contexto**,
pelo [jev da TypeSafe](https://docs.typesafe.ai): "a senha do wifi é
casa2024", "login e senha da wavoip ... 88776655*", uma chave hex depois de
"a chave da fipe", um email que também é a senha. Nenhum formato fixo decide;
a frase decide.

O valor nunca sai da sua máquina: cada palavra candidata é substituída por um
id e seu formato (`⟨c2:aaaa9999⟩`) antes da requisição. Isso é garantido em
`src/jev.js` e coberto por testes que inspecionam todo corpo de requisição.

Ele roda **em segundo plano**, então sua mensagem nunca fica retida:

1. Na hora, as regras capturam o que reconhecem, e toda outra palavra
   candidata é protegida por hash (nada sai pela rede, por um commit ou por
   uma ferramenta nesse meio tempo).
2. Um processo separado pergunta ao classificador sobre cada palavra. Em 0,5
   ou acima a palavra é salva no `.env` com um nome; entre 0,2 e 0,5 não é
   salva mas continua protegida (incerto não é seguro); abaixo de 0,2 (um
   número de pedido, uma placa, um commit) ela é liberada.
3. O agente recebe o nome no próximo resultado de ferramenta.

Se o classificador está inacessível, toda palavra candidata continua
protegida e o agente é instruído a salvar a credencial por conta própria. Ele
só é chamado quando a mensagem menciona acesso ou uma palavra parece uma
credencial por si só: numa semana de uso real, de 11% a 29% das mensagens,
nenhuma delas retida.

Em 30 mensagens escritas do jeito que as pessoas mandam
(`node test/jev-eval.js`, ao vivo): 16 de 17 credenciais salvas com o nome
certo, 17 de 17 protegidas, e nenhum dos 14 parecidos (números de pedido,
commits, placas, CPF, telefone, UUIDs, códigos de rastreio) capturado. A que
não foi salva foi "use this: x7Kq..." sem nenhuma palavra ao redor, que
continua protegida.

Ative com `"jev": { "enabled": true }` e uma chave em `TYPESAFE_API_KEY` ou
`~/.config/typesafe/api-key`. Ajuste fino: `jev.pickThreshold` (0.5),
`jev.keepThreshold` (0.2), `jev.jobTimeoutMs` (15000).

## O cofre

Credenciais também podem viver no cofre próprio do keyfence em vez de
arquivos `.env`, usadas pelo nome e nunca mostradas:

```
keyfence secret add wavoip/test-device/sip --env test --field token \
  --op browser.fill --target call.otonistark.com.br --fill username=token --fill password=token
keyfence secret list
keyfence secret show wavoip/test-device/sip
keyfence secret rotate wavoip/test-device/sip
keyfence secret revoke wavoip/test-device/sip
```

- Valores são digitados num prompt oculto, num terminal de verdade. Não
  existe flag, argumento ou pipe que aceite um, e nenhum comando que imprima
  um: `show` termina com `value: never shown`. Agentes rodam ferramentas sem
  terminal, então só uma pessoa pode adicionar ou rotacionar um segredo.
- Cada valor é criptografado com AES-256-GCM, vinculado ao seu alias, campo e
  versão. A chave mestra vive no Keychain do macOS; em outros sistemas, num
  arquivo privado (`0600`, ou uma ACL só do dono no Windows) nomeado por
  `KEYFENCE_VAULT_KEY_FILE`.
- Todo segredo tem uma política: operações permitidas, hosts alvo, comandos e
  projetos, negado por padrão. Shells e interpretadores nunca podem receber
  um segredo.
- Todo valor do cofre é protegido em toda sessão desde o início, mesmo um que
  nunca apareceu num prompt: enviado para qualquer lugar é negado, e em
  qualquer saída vira `⟨wavoip/test-device/sip⟩`. Valores revogados e
  substituídos por rotação continuam protegidos, já que o provedor ainda pode
  aceitá-los.
- Ler os arquivos do cofre, sua chave no Keychain ou seu módulo a partir de
  um shell é negado ao agente.

Esta é a fase 1 de [o design do cofre](docs/design/vault.md). As operações
que usam um segredo sem revelá-lo (`request`, `run`, `fill`) vêm a seguir; até
lá o cofre armazena, protege e descreve.

## Mantendo organizado

Credenciais se acumulam. O keyfence as mantém em ordem sozinho:

```
keyfence tidy              # plano: quais nomes genéricos (PASSWORD, SENHA, SECRET_2...) ganham nomes reais
keyfence tidy --apply      # aplica, com backup 0600 do arquivo de ambiente
keyfence discover          # encontra credenciais já no disco: arquivos .env e exports do shell
keyfence discover --apply  # registra elas no cofre, com cada lugar onde cada uma vive
keyfence maintain          # plano para todo arquivo de ambiente que o keyfence já escreveu
keyfence maintain --install  # roda `maintain --apply` todo dia às 09:30 (launchd, headless)
```

- **Nomes genéricos antigos ganham nomes reais.** Um valor salvo há muito
  tempo como `PASSWORD` é buscado na mensagem de onde veio (nos logs de
  sessão do Claude Code, dentro do keyfence, nunca impresso), e a credencial
  é reconstruída: `PASSWORD` vira `SIS_ROBSON_PASSWORD`, e o login que foi
  descartado na época volta como `SIS_ROBSON_LOGIN`. Um valor que os
  detectores atuais não reconhecem como credencial (uma captura falsa antiga)
  é deixado como está.
- **Nada que lê um nome quebra.** Se algum arquivo rastreado do projeto lê o
  nome antigo, ele permanece e os nomes novos são adicionados ao lado dele.
- **Credenciais já no disco são encontradas.** `discover` lê os arquivos
  `.env` dos seus projetos e as linhas `export` dos seus arquivos de shell,
  reconhece uma credencial pelo formato ou pelo nome, e a registra uma vez,
  não importa quantos lugares a guardem. Uma chave em cinco projetos é um
  registro que lista os cinco. As fontes nunca são alteradas, um registro
  nunca é sobrescrito com outro valor, e um valor visto numa sessão passada é
  marcado para rotação. O `maintain` diário roda isso também, então projetos
  novos são pegos sozinhos.
- **Duplicatas se fundem.** O mesmo valor sob `sis/default` e `sis/robson`
  mantém o registro específico; qualquer outra duplicata só é reportada.
- **O que precisa de você é listado.** Segredos que passaram por um chat
  (rotacione-os) e segredos sem uso há 90 dias.

## Varrendo arquivos

O motor de detecção também é uma CLI:

```
keyfence scan .            # exit 1 when something is found
keyfence scan - < file     # stdin
keyfence scan src --json
```

Valores nunca são impressos, só o formato deles, então a saída é segura para
colar numa issue ou num chat. Para histórico de repositório e CI, scanners
dedicados como gitleaks ou trufflehog vão mais fundo; o keyfence foca na
sessão do agente.

## Desempenho

O hook é Node puro, sem dependências. O overhead medido por chamada de
ferramenta é de 6 a 9 ms acima da própria inicialização do Node. Ele varre no
máximo 2 MB de qualquer saída de ferramenta. O classificador, quando ativado,
adiciona a chamada de rede dele só a mensagens que mencionam acesso e carregam
uma palavra candidata.

## Falando com o agente

O hook já conta ao agente o que fez, mensagem por mensagem. Algumas linhas no
seu `CLAUDE.md` fazem ele se comportar bem desde o primeiro turno:

```markdown
## Credenciais (keyfence)
- Uma credencial colada no chat é salva pelo keyfence no .env, com um nome
  que ele me informa. Uso só esse nome ($META_ACCESS_TOKEN); o keyfence
  carrega o arquivo em qualquer comando que o referencia. Nunca repito,
  imprimo, registro em log ou faço commit do valor.
- ⟨NOME⟩ ou ⟨keyfence:rule⟩ numa saída é o valor escondido de propósito.
- Uma negação [keyfence] é uma leitura de cofre ou um valor literal saindo.
  Sigo a alternativa que ela dá; nunca contorno.
- Um nome provisório (KF_7F3A_PASSWORD) é renomeado pelo keyfence a partir do
  contexto da mensagem em poucos segundos; troco para o novo nome assim que
  ele chega.
- Se eu disser que enviei uma credencial e nenhum nome veio junto, peço para
  reenviarem como NOME=valor.
```

## Desenvolvimento

```
npm test
```

- `test/detect.test.js`: todo formato de provedor pego em cada uma de N
  rodadas aleatórias (padrão 50, `ROUNDS=300` para mais), 42 negativos
  tirados de código real, e a camada de alta entropia.
- `test/whole-value.test.js`: uma senha com qualquer caractere imprimível em
  qualquer posição, em 12 layouts de mensagem, é capturada inteira e
  recarrega pelo `bash` sem mudanças; os layouts que nenhum leitor conseguiu
  resolver são listados com o motivo.
- `test/hook.test.js`: 102 cenários ponta a ponta rodando o binário real do
  hook dentro de repositórios git descartáveis: leituras do cofre, captura
  (nomes, reuso, `_2`, aspas que recarregam intactas, o fallback global),
  injeção que realmente define a variável no bash, limpeza de saída de toda
  ocorrência, tentativas de evasão (base64, cópias em variáveis e arquivos,
  scripts fora do repo, WebFetch, mensagens de commit, ferramentas
  desconhecidas), mais latência.
- `test/classify.test.js`: o classificador em segundo plano ponta a ponta
  contra um fake local da API: proteção pendente, salvar, liberar, a zona
  incerta, a nota no próximo resultado de ferramenta, a privacidade de toda
  requisição, e o caminho de API fora do ar.
- `test/vault.test.js`: criptografia em repouso, integridade (adulteração, um
  texto cifrado movido para outro alias), rotação, revogação, recusas de
  política, o buffer limpo após o uso, a CLI nunca imprimindo um valor, e o
  hook protegendo valores do cofre e guardando o cofre.
- `test/credential.test.js`: registros de credencial: serviço, conta, qual
  valor é o login, nomes, ambiente, dois serviços numa mensagem.
- `test/naming.test.js`: nomeação sem rede: o fallback estrutural, o que pode
  ser enviado ao classificador, um registro provisório dividido entre dois
  serviços, e renomear capturas antigas sem tocar em nomes que você escolheu.
  `node test/naming-eval.js` mede as escolhas do classificador real, ao vivo.
- `test/tidy.test.js`: renomeação a partir da mensagem original, logins
  recuperados, nomes que código ainda lê, backups, fusão de duplicatas e a
  lista de rotação.
- `test/discover.test.js`: encontrar credenciais no disco, um registro por
  valor, todo lugar mantido, chaves públicas e exemplos ignorados, exposição,
  nunca sobrescrever um registro.
- `test/cli.test.js`: contrato da CLI.
- `test/jev.test.js`: o contrato de privacidade do classificador; uma
  checagem ao vivo roda quando `TYPESAFE_API_KEY` está definida.

Credenciais de teste são montadas em tempo de execução, então este
repositório não contém nenhum token literal para disparar proteção de push ou
scanners.

Adicionar um provedor: uma regra em `src/rules.js`, um gerador em
`test/gen.js`.

## Licença

MIT

<!-- readme-padrao:footer -->
<br>

---

<div align="center">
  <p><strong>Feito por <a href="https://github.com/leonardocandiani">Leonardo Candiani</a></strong> · Mais projetos em <a href="https://github.com/leonardocandiani?tab=repositories">github.com/leonardocandiani</a></p>
  <p>Leonardo Candiani constrói agentes de IA que conversam, decidem e fecham negócio. Cofundador da SixQuasar, operando Proteauto, SegSmart e IACall ponta a ponta.</p>
  <a href="https://leonardocandiani.com.br">
    <img src="https://img.shields.io/badge/-Website-0d1117?style=for-the-badge&logo=safari&logoColor=00d9ff" alt="Website" />
  </a>
  <a href="https://github.com/leonardocandiani">
    <img src="https://img.shields.io/badge/-GitHub-0d1117?style=for-the-badge&logo=github&logoColor=00d9ff" alt="GitHub" />
  </a>
  <a href="https://instagram.com/leonardocandiani">
    <img src="https://img.shields.io/badge/-Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white" alt="Instagram" />
  </a>
  <a href="https://youtube.com/@oleonardocandiani">
    <img src="https://img.shields.io/badge/-YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white" alt="YouTube" />
  </a>
</div>

<br>

<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d9ff,50:1a1a2e,100:0d1117&height=120&section=footer&text=Obrigado%20pela%20visita%21&fontSize=18&fontColor=ffffff&fontAlignY=72" alt="Obrigado pela visita!" width="100%" />
</div>
<!-- /readme-padrao:footer -->
