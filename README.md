<!-- readme-padrao:header -->
<!-- Banner -->
<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:00d9ff&height=200&section=header&text=keyfence&fontSize=54&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Keeps%20secrets%20from%20leaking%20out%20of%20AI%20coding%20agent%20sessions%2C%20and%20keeps%20them%20organized%20in%20a%20local%20vault&descAlignY=58&descSize=16" alt="keyfence" width="100%" />
</div>

<!-- Typing -->
<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=21&duration=2800&pause=900&color=00d9ff&center=true&vCenter=true&width=840&lines=Paste+a+token+in+the+chat+and+keep+working;Saved+as+a+credential%3A+service%2C+account%2C+login%2C+password;Finds+the+keys+already+on+your+disk+and+files+them;Blocked+from+curl%2C+commits%2C+MCP+and+tracked+files" alt="Paste a token in the chat and keep working" />
</div>

<div align="center">

  <p><strong>A Claude Code hook and local vault: it catches every credential that enters a session, files it by name, and stops it at every exit.</strong></p>

  <p>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00d9ff?style=for-the-badge" alt="License: MIT" /></a>
    <a href="https://docs.claude.com/en/docs/claude-code"><img src="https://img.shields.io/badge/Made%20for-Claude%20Code-D97757?style=for-the-badge&logo=anthropic&logoColor=white" alt="Made for: Claude Code" /></a>
    <a href="https://github.com/leonardocandiani/keyfence/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/leonardocandiani/keyfence/test.yml?style=for-the-badge&labelColor=1a1a2e&label=CI" alt="CI" /></a>
    <img src="https://img.shields.io/badge/node-18%2B%20zero%20deps-1a1a2e?style=for-the-badge&logo=nodedotjs&logoColor=white" alt="node: 18+ zero deps" />
    <a href="https://github.com/leonardocandiani/keyfence/pulls"><img src="https://img.shields.io/badge/PRs-welcome-1a1a2e?style=for-the-badge" alt="PRs: welcome" /></a>
  </p>

  <p>
    <a href="#what-it-does">What it does</a> •
    <a href="#what-it-detects">What it detects</a> •
    <a href="#what-it-cannot-do">What it cannot do</a> •
    <a href="#configuration">Configuration</a> •
    <a href="#the-optional-classifier">The optional classifier</a> •
    <a href="#the-vault">The vault</a> •
    <a href="#keeping-it-organized">Keeping it organized</a> •
    <a href="#license">License</a>
  </p>
</div>

<br>

> **keyfence** treats every credential that enters an agent session as tainted and files it as a credential: pasted in the prompt, printed by a command or already sitting in a `.env`, it gets a record in an encrypted local vault (`sis/robson`: login and password), a name the agent uses (`$SIS_ROBSON_PASSWORD`), and a hard stop at every exit, whether that exit is a `curl`, a commit, an MCP tool or a hardcoded config.

> Not affiliated with or endorsed by Anthropic. "Claude" and "Claude Code" are Anthropic trademarks.

## What it is

```yaml
product:  Claude Code hook plus a local vault that keeps credentials in and organized
capture:  a credential pasted in any form becomes a record: service, account, login, password
detects:  53 formats · labeled values · ?key= links · contextual classifier
vault:    AES-256-GCM, master key in the macOS Keychain, no command that prints a value
organize: discover finds keys on disk · tidy renames old ones · maintain runs daily
out:      denied to the network, commits, non-local tools, source files and git-tracked files
output:   tool output reaches the agent with the name in place of the value
privacy:  the classifier only ever sees the shape of a value (aaa999), never the value
install:  npm install -g github:leonardocandiani/keyfence · keyfence install
license:  MIT
```

<!-- /readme-padrao:header -->

Coding agents read your files, run your commands and talk to the network. A
credential that enters the session, because you pasted it, because the agent
read a `.env`, or because a command printed it, can end up in a `curl`, a commit,
a hardcoded config or a message sent through an MCP tool. keyfence is a Claude
Code hook that watches every place a secret can come in and every place it can
go out.

```
npm install -g github:leonardocandiani/keyfence
keyfence install
```

That registers the hook in `~/.claude/settings.json` for the three events it
uses (`UserPromptSubmit`, `PreToolUse`, `PostToolUse`). It takes effect on the
next tool call of every session, running ones included. `keyfence uninstall`
removes it and keeps a backup of your settings.

Requires Node 18 or later. Tested on Claude Code 2.1.280; injection and output
cleaning rely on the `updatedInput` and `updatedToolOutput` hook fields.

## What it does

Paste a token in the chat and keep working:

```
you:    here is the Meta token: EAAG...
agent:  (told: saved to .env as $META_ACCESS_TOKEN, use it by name)
agent:  curl https://graph.facebook.com/v21.0/me -H "Authorization: Bearer $META_ACCESS_TOKEN"
        keyfence loads .env into that command; the value never appears in it
output: {"token": "⟨META_ACCESS_TOKEN⟩", ...}
        any output that contains the value reaches the agent with the name instead
```

The token is saved the moment you send the message, to the repo's `.env` when
git ignores it, otherwise to a private `~/.config/keyfence/secrets.env` (both
`0600`). Values are quoted so the file loads back intact with `source`, even
with quotes or `;` inside.

It is saved as a **credential**, not a loose value: which service, whose
account, and which value is the login, the password, the token or the URL.

```
you:  login=robson.silva@empresa.com.br
      senha=********
      (in the SIS-api project)

keyfence: vault record  sis/robson  (login, password)
          .env          SIS_ROBSON_LOGIN, SIS_ROBSON_PASSWORD
```

| You send | Saved as |
|---|---|
| a login and a password | one record `service/account` with both; the service from the words ("senha da wavoip"), the link's host or the project, the account from the login |
| a new password for an account keyfence already has | a **rotation** of that record; the login stays, the old version is kept |
| a known provider's token | the name its SDK reads: `META_ACCESS_TOKEN`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`... |
| `PAINEL_PASSWORD=...` | the name you wrote |
| a link with `?key=...` | the API's host plus the kind: `PLACAFIPE_API_KEY` |

"senha do robson" and "senha da wavoip" read the same; keyfence tells a person
from a service by what the vault already holds. Every record is marked as
exposed, since it came through the chat, and `keyfence secret list` shows it.

Underneath, keyfence works in three layers.

**1. It keeps secrets out of the transcript in the first place.** Reading a
vault file (`.env`, `~/.aws/credentials`, SSH keys, `.npmrc`, `.pgpass`, the
Claude Code credentials file) is denied, whether through the Read tool, the Grep
tool or `cat`, `grep`, `jq`, `sed` and friends in a shell, including over
`ssh host cat ...`. Using the file is fine: `source .env`, `set -a; . .env`,
passing it to the program that needs it.

**2. It remembers every secret it sees, by hash.** Secrets pasted in your prompt
and secrets that show up in a tool's output are recorded as SHA-256 prefixes in
a per-session file in the OS temp dir. The value is never stored.

**3. It blocks remembered secrets from leaving.** Before every tool call, the
command or content is split into pieces (including base64-decoded ones) and
hashed. A remembered secret is denied when it would go to:

- the network: `curl`, `wget`, `ssh`, `scp`, `gh`, cloud CLIs, and one-liners
  like `node -e "fetch(...)"` or `python3 -c "requests.post(...)"`
- a commit, tag or push
- any tool that is not local: MCP tools, WebFetch, artifact publishing, and tools
  added in future versions (default deny). Tools whose job is storing a secret,
  like setting an environment variable in a hosting provider, are allowed.
- a source file (`.js`, `.py`, `.sh`, `.yml`, `.json`...) or any file git tracks

Writing it to `.env` or another git-ignored file passes. Independently of the
taint, a high-confidence secret written into a git-tracked file is denied too.

Copies count as the secret. `export K=<key>` or `echo <key> > /tmp/k` is local
and passes, but the variable and the file are remembered, so a later
`curl -d "$K"` or `curl -d @/tmp/k` is denied like the literal. Env and
credential files are the exception on purpose: `source .env` followed by a call
that uses its variable is how a key is meant to be used. Sending a vault file
itself (`curl -d @.env`) is denied.

Tool output is cleaned before the agent sees it: a remembered secret, or any
new one keyfence recognizes, is replaced by its variable name or
`⟨keyfence:rule⟩`. A key that a command prints by accident never reaches the
model.

## What it detects

```
keyfence rules
```

- **53 provider formats**: Anthropic, OpenAI, OpenRouter, DeepSeek-style `sk-`,
  Hugging Face, Replicate, Groq, xAI, Perplexity, AWS, Google (API key, OAuth
  secret and token), Azure storage, DigitalOcean, Tailscale, Doppler, Fly.io,
  Heroku, GitHub (classic and fine-grained), GitLab, npm, PyPI, Stripe (keys and
  webhook secrets), Asaas, Mercado Pago, Slack (tokens and webhooks), Discord
  (bot tokens and webhooks), Telegram bots, Meta / WhatsApp Cloud API, Twilio,
  SendGrid, Mailgun, Resend, Postmark, Supabase (access and secret keys), Notion,
  Linear, Shopify, Atlassian, Figma, Sentry, private keys, JWTs, Bearer headers,
  and URLs with embedded passwords.
- **Labeled values**: `token=...`, `"client_secret": "..."`, `senha: ...`,
  `export DB_PASSWORD=...`, in English, Portuguese and Spanish, filtered for
  placeholders (`${VAR}`, `<your-token>`, `changeme`), code (`options.apiKey`,
  `getToken(`), identifiers, aliases (`billing/api`), CSS selectors and default
  passwords. A lowercase hex or UUID value counts when a label says it is a key;
  without a label it is treated as a commit hash.
- **Credentials in links**: `?key=`, `?apikey=`, `&token=`, `?access_token=`,
  `?password=` and similar query parameters in any URL.
- **High-entropy strings** with no label or known prefix, from your own prompt
  only. Tool output is full of random ids, so this layer does not run there.
- **Optional classifier** for prose ("the wifi password is abc123"), see below.

Supabase `anon` JWTs are skipped: they are public by design.

## What it cannot do

No text-based guard is complete, and this one says where it is blind:

- **Images.** A key in a screenshot is invisible to it.
- **Your message itself.** A Claude Code hook cannot rewrite the prompt, so the
  message that carries a pasted token reaches the model once, as you wrote it.
  keyfence saves it and protects every step after that. For zero exposure, use
  `promptMode: "block"`: the message is refused before the model sees it (Claude
  Code still keeps the original in the local session log).
- **The agent's reply.** If the agent prints a secret in its answer, that text is
  already on screen; the hook only sees tool calls.
- **Deliberate evasion.** Direct copies into a variable or a file are followed,
  but a secret split into parts and reassembled at run time, or copied twice
  (`K2=$K`), will not match. keyfence stops accidents and careless automation,
  not an adversary who controls the agent.
- **Where the secret goes.** keyfence cannot tell `api.stripe.com` from a
  collection endpoint. A key loaded from `.env` into a variable can be sent to
  any host; the guard is on the literal value and its copies, not the
  destination.
- **Short letters-only passwords** that look like an identifier (`fooBarBazQu`)
  are skipped on purpose, because flagging them would flag your code. The test
  suite measures this at under 1% of such values.
- **A password with no word around it.** "log in with leo and x7!kq92" has no
  label, no known format and no access word, so nothing catches it. When a
  message does carry a credential keyfence cannot isolate, the agent is told to
  save it to `.env` itself and carry on; you are never asked to send it again.
- **Quotes, `;` or `,` in the first 8 characters of a password** end the value
  before the label rule can read it. Without the classifier nothing catches it;
  store such a value in `.env` yourself.
- **Several candidate words for the classifier.** When the classifier flags a
  message with more than one possible secret, all of them are protected but none
  is saved, because guessing which one is the password would be worse.
- **Unknown formats.** A credential with no label, no known prefix and low
  randomness is not detected. The high-entropy layer and the classifier narrow
  this; they do not close it.

## Configuration

Optional, at `~/.config/keyfence/config.json` (or the path in
`KEYFENCE_CONFIG`). Every key is optional.

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

`promptMode` is `capture` (save and go on), `warn` (only protect) or `block`
(refuse the message). `keyfence config` shows what is in effect.

## The optional classifier

Rules settle the formats they know, in milliseconds. Everything else that could
be a credential is judged **word by word, from its context**, by
[TypeSafe's jev](https://docs.typesafe.ai): "the wifi password is casa2024",
"login e senha da wavoip ... 88776655*", a hex key after "a chave da fipe", an
email that is also the password. No fixed format decides; the sentence does.

The value never leaves your machine: each candidate word is replaced by an id
and its shape (`⟨c2:aaaa9999⟩`) before the request. This is enforced in
`src/jev.js` and covered by tests that inspect every request body.

It runs **in the background**, so your message is never held:

1. At once, the rules capture what they recognize, and every other candidate
   word is protected by hash (nothing leaves through the network, a commit or a
   tool meanwhile).
2. A separate process asks the classifier about each word. At 0.5 or above the
   word is saved to `.env` with a name; from 0.2 to 0.5 it is not saved but stays
   protected (unclear is not safe); below 0.2 (an order number, a plate, a
   commit) it is released.
3. The agent gets the name with its next tool result.

If the classifier is unreachable, every candidate stays protected and the agent
is told to save the credential itself. It is called only when the message
mentions access or a word looks like a credential on its own: in one week of
real use, 11% to 29% of messages, none of them held.

On 30 messages written the way people send them (`node test/jev-eval.js`, live):
16 of 17 credentials saved with the right name, 17 of 17 protected, and none of
14 look-alikes (order ids, commits, plates, CPF, phone, UUIDs, tracking codes)
captured. The one not saved was "use this: x7Kq..." with no word around it,
which stays protected.

Enable it with `"jev": { "enabled": true }` and a key in `TYPESAFE_API_KEY` or
`~/.config/typesafe/api-key`. Tuning: `jev.pickThreshold` (0.5),
`jev.keepThreshold` (0.2), `jev.jobTimeoutMs` (15000).

## The vault

Credentials can also live in keyfence's own vault instead of `.env` files, used
by name and never shown:

```
keyfence secret add wavoip/test-device/sip --env test --field token \
  --op browser.fill --target call.otonistark.com.br --fill username=token --fill password=token
keyfence secret list
keyfence secret show wavoip/test-device/sip
keyfence secret rotate wavoip/test-device/sip
keyfence secret revoke wavoip/test-device/sip
```

- Values are typed at a hidden prompt on a real terminal. There is no flag,
  argument or pipe that takes one, and no command that prints one: `show` ends
  with `value: never shown`. Agents run tools without a terminal, so only a
  person can add or rotate a secret.
- Each value is encrypted with AES-256-GCM, bound to its alias, field and
  version. The master key lives in the macOS Keychain; elsewhere, in a `0600`
  file named by `KEYFENCE_VAULT_KEY_FILE`.
- Every secret has a policy: allowed operations, target hosts, commands and
  projects, default deny. Shells and interpreters can never receive a secret.
- Every vault value is protected in every session from the start, even one
  that never appeared in a prompt: sent anywhere it is denied, and in any output
  it becomes `⟨wavoip/test-device/sip⟩`. Revoked and rotated-out values stay
  protected, since the provider may still accept them.
- Reading the vault's files, its Keychain key or its module from a shell is
  denied to the agent.

This is phase 1 of [the vault design](docs/design/vault.md). The operations that
use a secret without revealing it (`request`, `run`, `fill`) come next; until
then the vault stores, protects and describes.

## Keeping it organized

Credentials pile up. keyfence keeps them in order on its own:

```
keyfence tidy              # plan: which generic names (PASSWORD, SENHA, SECRET_2...) get real ones
keyfence tidy --apply      # do it, with a 0600 backup of the env file
keyfence discover          # find credentials already on disk: .env files and shell exports
keyfence discover --apply  # register them in the vault, with every place each one lives
keyfence maintain          # plan for every env file keyfence ever wrote to
keyfence maintain --install  # run `maintain --apply` every day at 09:30 (launchd, headless)
```

- **Old generic names get real ones.** A value saved long ago as `PASSWORD` is
  looked up in the message it came from (in the Claude Code session logs, inside
  keyfence, never printed), and the credential is rebuilt: `PASSWORD` becomes
  `SIS_ROBSON_PASSWORD`, and the login that was dropped back then comes back as
  `SIS_ROBSON_LOGIN`. A value that today's detection does not see as a
  credential (an old false capture) is left alone.
- **Nothing that reads a name breaks.** If any tracked file of the project reads
  the old name, it stays and the new names are added next to it.
- **Credentials already on disk are found.** `discover` reads the `.env` files
  of your projects and the `export` lines of your shell files, recognizes a
  credential by its format or by its name, and registers it once, however many
  places hold it. A key in five projects is one record that lists all five.
  Sources are never changed, a record is never overwritten with another value,
  and a value seen in a past session is marked for rotation. The daily
  `maintain` runs it too, so new projects are picked up on their own.
- **Duplicates merge.** The same value under `sis/default` and `sis/robson` keeps
  the specific record; any other duplicate is only reported.
- **What needs you is listed.** Secrets that went through a chat (rotate them)
  and secrets unused for 90 days.

## Scanning files

The detection engine is also a CLI:

```
keyfence scan .            # exit 1 when something is found
keyfence scan - < file     # stdin
keyfence scan src --json
```

Values are never printed, only their shape, so the output is safe to paste into
an issue or a chat. For repository history and CI, dedicated scanners such as
gitleaks or trufflehog go deeper; keyfence focuses on the agent session.

## Performance

The hook is plain Node with no dependencies. Measured overhead per tool call is
6 to 9 ms above Node's own startup. It scans at most 2 MB of any tool output.
The classifier, when enabled, adds its network call only to messages that
mention access and carry a candidate word.

## Telling the agent

The hook already tells the agent what it did, message by message. A few lines in
your `CLAUDE.md` make it behave well from the first turn:

```markdown
## Credentials (keyfence)
- A credential I paste is saved by keyfence to .env under a name it tells you.
  Use only that name ($META_ACCESS_TOKEN); keyfence loads the file into any
  command that references it. Never repeat, print, log or commit the value.
- ⟨NAME⟩ or ⟨keyfence:rule⟩ in an output is the value hidden on purpose.
- A [keyfence] denial means a vault read or a literal value leaving. Follow the
  alternative it gives; never work around it.
- If I say I sent a credential and no name came with it, ask me to resend it as
  NAME=value.
```

## Development

```
npm test
```

- `test/detect.test.js`: every provider format caught in every one of N random
  rounds (default 50, `ROUNDS=300` for more), 42 negatives taken from real code,
  and the high-entropy layer.
- `test/hook.test.js`: 99 end-to-end scenarios running the real hook binary
  inside throwaway git repos: vault reads, capture (names, reuse, `_2`, quotes
  that load back intact, the global fallback), injection that really sets the
  variable in bash, output cleaning of every occurrence, evasion attempts
  (base64, copies into variables and files, scripts outside the repo, WebFetch,
  commit messages, unknown tools), plus latency.
- `test/classify.test.js`: the background classifier end to end against a local
  fake of the API: pending protection, save, release, the unclear zone, the note
  on the next tool result, the privacy of every request, and the API-down path.
- `test/vault.test.js`: encryption at rest, integrity (tampering, a ciphertext
  moved to another alias), rotation, revocation, policy refusals, the buffer
  wiped after use, the CLI never printing a value, and the hook protecting vault
  values and guarding the vault.
- `test/credential.test.js`: credential records: service, account, which value
  is the login, names, environment, two services in one message.
- `test/tidy.test.js`: renaming from the original message, recovered logins,
  names code still reads, backups, duplicate merging and the rotation list.
- `test/discover.test.js`: finding credentials on disk, one record per value,
  every place kept, public keys and examples skipped, exposure, never
  overwriting a record.
- `test/cli.test.js`: CLI contract.
- `test/jev.test.js`: the classifier's privacy contract; a live check runs when
  `TYPESAFE_API_KEY` is set.

Test credentials are assembled at run time, so this repository contains no
literal token for push protection or scanners to trip on.

Adding a provider: a rule in `src/rules.js`, a generator in `test/gen.js`.

## License

MIT

<!-- readme-padrao:footer -->
<br>

---

<div align="center">
  <p><strong>Built by <a href="https://github.com/leonardocandiani">Leonardo Candiani</a></strong> · More projects at <a href="https://github.com/leonardocandiani?tab=repositories">github.com/leonardocandiani</a></p>
  <p>Leonardo Candiani builds AI agents that talk, decide and close deals. Cofounder of SixQuasar, operating Proteauto, SegSmart and IACall end to end.</p>
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
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d9ff,50:1a1a2e,100:0d1117&height=120&section=footer&text=Thanks%20for%20stopping%20by&fontSize=18&fontColor=ffffff&fontAlignY=72" alt="Thanks for stopping by" width="100%" />
</div>
<!-- /readme-padrao:footer -->
