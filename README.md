<!-- readme-padrao:header -->
<!-- Banner -->
<div align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d1117,50:1a1a2e,100:00d9ff&height=200&section=header&text=keyfence&fontSize=54&fontColor=ffffff&animation=fadeIn&fontAlignY=36&desc=Keeps%20secrets%20from%20leaking%20out%20of%20AI%20coding%20agent%20sessions&descAlignY=58&descSize=16" alt="keyfence" width="100%" />
</div>

<!-- Typing -->
<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=600&size=21&duration=2800&pause=900&color=00d9ff&center=true&vCenter=true&width=840&lines=Keeps+secrets+inside+your+coding+agent+session;Remembers+every+key+it+sees%2C+by+hash+only;Blocks+it+from+curl%2C+commits%2C+MCP+and+tracked+files;53+provider+formats%2C+zero+dependencies%2C+7+ms+per+call" alt="Keeps secrets inside your coding agent session" />
</div>

<div align="center">

  <p><strong>A Claude Code hook that watches every place a secret can come in and every place it can go out.</strong></p>

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
    <a href="#scanning-files">Scanning files</a> •
    <a href="#performance">Performance</a> •
    <a href="#license">License</a>
  </p>
</div>

<br>

> **keyfence** treats every credential that enters an agent session as tainted: pasted in the prompt, printed by a command, or read from a file, it is remembered by hash and denied at the exit, whether that exit is a `curl`, a commit, an MCP tool or a hardcoded config.

> Not affiliated with or endorsed by Anthropic. "Claude" and "Claude Code" are Anthropic trademarks.

## What it is

```yaml
product: Claude Code hook that stops credentials from leaving an agent session
in:      secrets pasted in the prompt or printed by any tool are remembered as SHA-256 prefixes, never values
out:     denied to the network, commits, non-local tools, source files and git-tracked files
vault:   reading .env, SSH keys or credential files is denied; counting and listing names still works
detects: 53 provider formats · labeled values in EN/PT/ES · high-entropy strings · optional classifier
privacy: the optional jev classifier only ever sees the shape of a value (aaa999), never the value
speed:   plain Node, no dependencies, about 7 ms per tool call
install: npm install -g keyfence · keyfence install
license: MIT
```

<!-- /readme-padrao:header -->

Coding agents read your files, run your commands and talk to the network. A
credential that enters the session, because you pasted it, because the agent
read a `.env`, or because a command printed it, can end up in a `curl`, a commit,
a hardcoded config or a message sent through an MCP tool. keyfence is a Claude
Code hook that watches every place a secret can come in and every place it can
go out.

```
npm install -g keyfence
keyfence install
```

That registers the hook in `~/.claude/settings.json`. It takes effect on the
next tool call of every session, running ones included.

## What it does

keyfence works in three layers.

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

When a secret is pasted, the agent is also told to treat it as one: never echo
it, store it in an ignored file, reference it by variable name.

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
  `getToken(`), identifiers and default passwords.
- **High-entropy strings** with no label or known prefix, from your own prompt
  only. Tool output is full of random ids, so this layer does not run there.
- **Optional classifier** for prose ("the wifi password is abc123"), see below.

Supabase `anon` JWTs are skipped: they are public by design.

## What it cannot do

No text-based guard is complete, and this one says where it is blind:

- **Images.** A key in a screenshot is invisible to it.
- **Your message itself.** A Claude Code hook cannot rewrite the prompt, so a
  pasted secret is in the local transcript the moment you press Enter. keyfence
  protects where it goes next. Use `promptMode: "block"` to refuse such prompts
  instead.
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
- **Unknown formats.** A credential with no label, no known prefix and low
  randomness is not detected. The high-entropy layer and the classifier narrow
  this; they do not close it.

## Configuration

Optional, at `~/.config/keyfence/config.json` (or the path in
`KEYFENCE_CONFIG`). Every key is optional.

```json
{
  "promptMode": "warn",
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

`keyfence config` shows what is in effect.

## The optional classifier

Rules cannot tell "the wifi password is abc123" from "rename abc123 to wifi".
keyfence can ask [TypeSafe's jev](https://docs.typesafe.ai) model, and it does so
without ever sending the value: every word that could be a credential is replaced
by its shape (`abc123` becomes `⟨aaa999⟩`) before the text leaves your machine.
The model judges intent from the words around it. This is enforced in
`src/jev.js` and covered by `test/jev.test.js`, which inspects the exact request
body.

It only runs when the prompt mentions access (password, token, key, login...)
and contains a candidate word, has a 4 second timeout, and fails open. On a
calibration set of 20 realistic prompts, disclosures scored 0.22 to 0.59 and
ordinary talk 0.04 to 0.12, so the default threshold is 0.18. Median latency was
474 ms. Enable it with `"jev": { "enabled": true }` and a key in
`TYPESAFE_API_KEY` or `~/.config/typesafe/api-key`.

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

## Development

```
npm test
```

- `test/detect.test.js`: every provider format caught in every one of N random
  rounds (default 50, `ROUNDS=300` for more), 41 negatives taken from real code,
  and the high-entropy layer.
- `test/hook.test.js`: 59 end-to-end scenarios running the real hook binary
  inside a throwaway git repo, including evasion attempts (base64, scripts
  outside the repo, WebFetch, commit messages, unknown tools), plus latency.
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
