'use strict';
// Claude Code hook. One entry point, three events:
//
//   UserPromptSubmit  secrets pasted by the user are tainted (hash only) and, in
//                     "capture" mode, saved to the git-ignored .env under a name
//                     the agent uses from then on; "block" mode refuses the prompt.
//   PreToolUse        (0) a Bash command that references a captured variable gets
//                     its env file loaded first, so the value never appears in it;
//   PreToolUse        (1) reading a vault file (.env, credentials, ssh keys) is
//                     denied, because the content would land in the transcript;
//                     (2) a tainted secret leaving the machine is denied: network
//                     commands, inline interpreters calling HTTP, MCP tools, and
//                     writes to git-tracked files.
//   PostToolUse       secrets that show up in a tool's output are tainted too and
//                     replaced by their name before the agent sees the output.
//
// State lives in the OS temp dir, one file per session, holding SHA-256 prefixes,
// never values. Any internal error exits 0 without output: a broken guard must
// not stall the agent.

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { scan, shape } = require('./detect');
const config = require('./config');

const MAX_SCAN = 2 * 1024 * 1024;
const NETWORK = /\b(curl|wget|http|https|xh|nc|ncat|socat|telnet|ftp|sftp|scp|rsync|ssh|gh\s|git\s+(?:commit|push|tag|notes|send-email)|aws\s|az\s|gcloud\s|doctl\s|vercel\s|flyctl\s|nc\s)\b|\b(node|bun|deno|python3?|ruby|php|perl)\b[^|;&]*\b(fetch|requests?|urllib|httpx|aiohttp|axios|got|undici|http\.request|https\.request|net\/http|file_get_contents|XMLHttpRequest|LWP|socket)\b/i;
const READER = /\b(cat|bat|less|more|head|tail|grep|egrep|fgrep|rg|ag|sed|awk|jq|yq|strings|xxd|hexdump|od|plutil|defaults\s+read|base64|nl|tac|python3?\s+-c|node\s+-e|ruby\s+-e|perl\s+-[en])\b/;

// Tools that stay on this machine. Anything else (WebFetch, WebSearch, MCP,
// artifact publishing, tools added in future versions) is treated as leaving it.
const LOCAL_TOOLS = new Set(['Bash', 'Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'NotebookRead', 'Glob', 'Grep',
  'LS', 'Agent', 'Task', 'TodoWrite', 'TaskCreate', 'TaskUpdate', 'TaskList', 'TaskGet', 'TaskStop', 'TaskOutput',
  'Skill', 'ToolSearch', 'AskUserQuestion', 'EnterPlanMode', 'ExitPlanMode', 'Monitor', 'LSP', 'KillShell', 'BashOutput']);
// Writing a secret into source code is a leak waiting to happen, tracked or not:
// the script gets run, copied, pasted. Secrets belong in env files or stores.
const CODE_FILE = /\.(sh|bash|zsh|fish|js|mjs|cjs|ts|tsx|jsx|py|rb|php|pl|go|rs|java|kt|swift|cs|lua|ps1|bat|cmd|html|vue|svelte|yml|yaml|toml|json|md|txt|ipynb)$/i;

// Read forms that never print a value: counting, listing names, testing presence.
// `grep -c KEY .env` is fine; `grep KEY .env` prints the line.
const SAFE_READ = [
  /\bgrep\b(?=[^|;&]*\s-[a-zA-Z]*[clqL])/, // grep -c / -l / -q / -L
  /\bjq\b[^|;&]*['"]\s*(?:keys|keys_unsorted|length|type|has\([^)]*\))\s*['"]/, // jq 'keys'
  /\bcut\b(?=[^|;&]*-d\s*['"]?=)(?=[^|;&]*-f\s*1\b)/, // cut -d= -f1
  /\bawk\b(?=[^|;&]*-F\s*['"]?=)[^|;&]*\{\s*print\s+\$1\s*\}/, // awk -F= '{print $1}'
];

// A tainted value copied into a shell variable or a scratch file is still the
// secret: `export K=<key>` then `curl -d "$K"` must fail like the literal does.
// Env and credential files are the sanctioned store and are not marked, since
// loading a key from .env to call its own API is the intended use.
const ASSIGN = /^\s*(?:export\s+|declare\s+(?:-\w+\s+)*|local\s+|readonly\s+|typeset\s+)?([A-Za-z_][A-Za-z0-9_]*)=/;
const REDIRECT = /(?:\d?>>?|\btee\s+(?:-a\s+)?)\s*([^\s;|&<>'"`]+)/g;
// Forms that hand a file's content to a network command: curl -d @f, < f, -T f.
const SENDS_FILE = /(?:@|<\s*|-T\s+|--upload-file\s+)([^\s;|&<>'"`]+)/g;

const hash = (v) => crypto.createHash('sha256').update(String(v)).digest('hex').slice(0, 32);

// ---------------------------------------------------------------------------
// state

function statePath(sessionId) {
  const id = String(sessionId || 'no-session').replace(/[^A-Za-z0-9_-]/g, '').slice(0, 80);
  return path.join(os.tmpdir(), `keyfence-${id}.json`);
}

function readState(file, ttlMs) {
  try {
    const now = Date.now();
    const list = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(list) ? list.filter((x) => now - (x.ts || 0) < ttlMs) : [];
  } catch {
    return [];
  }
}

function taint(sessionId, items, source, ttlMs) {
  const file = statePath(sessionId);
  const list = readState(file, ttlMs);
  const seen = new Set(list.map((x) => x.h));
  let added = 0;
  for (const it of items) {
    const h = hash(it.value);
    if (seen.has(h)) continue;
    list.push({ h, rule: it.rule, src: source, ts: Date.now() });
    seen.add(h);
    added++;
  }
  writeState(file, list);
  return added;
}

// Write to a temp file and rename: the background classifier writes this file too.
function writeState(file, list) {
  try {
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(list), { mode: 0o600 });
    fs.renameSync(tmp, file);
  } catch { /* best effort */ }
}

// Every substring that could be a secret, split the ways a value gets glued to
// its surroundings: quotes, separators, escapes, `KEY=value`, `Bearer value`.
function pieces(text) {
  const raw = String(text).slice(0, MAX_SCAN).match(/[^\s'"`,;()[\]{}<>\\]{8,}/g) || [];
  const out = new Set();
  for (const t of raw) {
    out.add(t);
    for (const p of t.split(/[=:@]/)) if (p.length >= 8) out.add(p);
    // base64 / base64url of a secret: decode and add the decoded pieces too
    if (t.length >= 16 && /^[A-Za-z0-9+/_-]+={0,2}$/.test(t)) {
      try {
        const dec = Buffer.from(t.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
        if (/^[\x20-\x7e]+$/.test(dec)) for (const q of dec.split(/[\s'"`,;:=@]+/)) if (q.length >= 8) out.add(q);
      } catch { /* not base64 */ }
    }
    if (out.size > 20000) break;
  }
  return out;
}

function findTainted(text, list) {
  if (!list.length || !text) return null;
  const byHash = new Map(list.filter((x) => x.h).map((x) => [x.h, x.rule]));
  for (const p of pieces(text)) {
    const rule = byHash.get(hash(p));
    if (rule) return { rule, shape: shape(p) };
  }
  return null;
}

function mark(sessionId, items, ttlMs) {
  const file = statePath(sessionId);
  const list = readState(file, ttlMs);
  const seen = new Set(list.map((x) => `${x.d}:${x.n}`));
  for (const it of items) {
    if (seen.has(`${it.d}:${it.n}`)) continue;
    list.push({ ...it, ts: Date.now() });
    seen.add(`${it.d}:${it.n}`);
  }
  writeState(file, list);
}

// Messages for the agent produced outside a hook call (the background
// classifier); delivered with the next prompt or tool result, then dropped.
function pushNotice(sessionId, text, ttlMs) {
  mark(sessionId, [{ d: 'notice', n: `${Date.now()}-${process.pid}`, text }], ttlMs);
}

function takeNotices(sessionId, ttlMs) {
  const file = statePath(sessionId);
  const list = readState(file, ttlMs);
  const notices = list.filter((x) => x.d === 'notice');
  if (notices.length) writeState(file, list.filter((x) => x.d !== 'notice'));
  return notices.map((x) => x.text);
}

// Variables and files a local command or write is about to fill with a tainted value.
function copiesOf(tool, input, file, list, cfg) {
  const isStore = (p) => cfg._vault.some((re) => re.test(p));
  const out = [];
  if (tool === 'Bash') {
    const cmd = String(input.command || '');
    for (const seg of cmd.split(/\|\||&&|[;\n]/)) {
      const hit = findTainted(seg, list);
      const m = hit && ASSIGN.exec(seg);
      if (m) out.push({ d: 'var', n: m[1], rule: hit.rule });
    }
    const hit = findTainted(cmd, list);
    if (hit) {
      for (const [, t] of cmd.matchAll(REDIRECT)) {
        if (!t.startsWith('&') && t !== '/dev/null' && !isStore(t)) out.push({ d: 'file', n: t, rule: hit.rule });
      }
    }
  } else if (file && !isStore(file)) {
    const hit = findTainted(toolText(tool, input), list);
    if (hit) out.push({ d: 'file', n: file, rule: hit.rule });
  }
  return out;
}

const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function mentionsFile(text, p) {
  if (text.includes(p)) return true;
  const base = p.split('/').pop();
  return base.length >= 4 && new RegExp(`(^|[\\s@<'"=/])${reEscape(base)}(?=$|[\\s'"\`);|&])`).test(text);
}

// A network command that uses a marked copy, or hands a vault file to the network.
function copyLeaving(text, list, cfg) {
  for (const x of list) {
    if (x.d === 'var' && new RegExp(`\\$\\{?${x.n}\\b`).test(text)) return `${x.rule}, copied into $${x.n}`;
    if (x.d === 'file' && mentionsFile(text, x.n)) return `${x.rule}, copied into ${x.n}`;
  }
  for (const [, t] of stripHeredocs(text).matchAll(SENDS_FILE)) {
    if (cfg._vault.some((re) => re.test(t))) return `the content of ${t}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// output

function out(obj) {
  process.stdout.write(JSON.stringify(obj));
}

let pendingHit = false;
function deny(reason) {
  const extra = pendingHit ? ' This value came from the user\'s latest message and keyfence is still checking it (a few seconds): '
    + 'continue with other work and use the name keyfence gives with your next tool result.' : '';
  out({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: `[keyfence] ${reason}${extra}` } });
  return true;
}

function note(event, text) {
  out({ hookSpecificOutput: { hookEventName: event, additionalContext: `[keyfence] ${text}` } });
}

// ---------------------------------------------------------------------------
// events

// Capture mode: save the values to the env file and return the note that tells
// the agent their names, or null when nothing could be saved.
function captureText(d, prompt, keep, cfg, ttl) {
  if (!keep.length) return null;
  try {
    const { save } = require('./capture');
    const r = save(keep, prompt, d.cwd, cfg);
    mark(d.session_id, r.saved.map((x) => ({ d: 'store', n: x.name, file: r.file, h: hash(x.value), rule: x.rule })), ttl);
    const names = r.saved.map((x) => `$${x.name} (${x.rule}${x.reused ? ', already saved' : ''})`).join(', ');
    const where = r.project ? `the project's git-ignored ${r.file}` : `${r.file} (outside the repo)`;
    return `The user's message contains a real credential. keyfence saved it to ${where} as ${names}. ` +
      'Work with it by name from now on: reference the variable in commands (keyfence loads it into any Bash command that uses it) or load the file in code. ' +
      'Never repeat the value in replies, code, comments, logs or commit messages.';
  } catch {
    return null;
  }
}

// Nothing could isolate the value: the agent saves it, the user never re-sends.
function fallbackText(kinds) {
  return `The user's message contains a credential (${kinds}) that keyfence protected but could not isolate. Save it yourself now: ` +
    "write NAME=value into the project's git-ignored .env with the Write tool (never in a command, reply or log), pick a clear NAME " +
    '(service plus kind, like FIPE_API_KEY), tell the user the name and keep working with $NAME. Do not ask the user to send it again.';
}

const WARN_TEXT = (kinds) => `This message contains a real credential (${kinds}). Treat it as a secret: never repeat the value in replies, comments, logs or commit messages; ` +
  'store it only in a git-ignored file or a secret store and reference it by variable name; do not send it to any external service unless the user asks for that in this turn.';

// Words the rules did not settle go to the classifier in the background. They are
// tainted at once as "pending", so nothing leaves while the answer is on its way.
function startClassifier(d, prompt, settled, cfg, ttl) {
  if (!cfg.jev.enabled) return 0;
  const { candidatesOf, apiKey, worthAsking } = require('./jev');
  if (!apiKey(cfg)) return 0;
  const cands = candidatesOf(prompt, settled.map((f) => f.value));
  if (!worthAsking(prompt, cands)) return 0;
  taint(d.session_id, cands.map((value) => ({ value, rule: 'pending' })), 'provisional', ttl);
  try {
    const job = path.join(os.tmpdir(), `keyfence-job-${String(d.session_id).replace(/[^A-Za-z0-9_-]/g, '')}-${Date.now()}.json`);
    fs.writeFileSync(job, JSON.stringify({ sid: d.session_id, cwd: d.cwd, prompt, cands }), { mode: 0o600 });
    const { spawn } = require('child_process');
    spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'keyfence-hook.js'), '--classify', job], { detached: true, stdio: 'ignore', env: process.env }).unref();
  } catch {
    return 0;
  }
  return cands.length;
}

async function onPrompt(d, cfg) {
  const prompt = String(d.prompt || '').slice(0, MAX_SCAN);
  // Background-task notifications arrive as prompts; they carry ids and paths, not secrets.
  if (/^\s*<task-notification>/.test(prompt)) return;
  const ttl = cfg.ttlHours * 3600e3;
  const { findings, ambiguous } = scan(prompt, { ambiguous: cfg.taintAmbiguousFromPrompt });
  const items = [...findings, ...ambiguous];
  if (items.length) taint(d.session_id, items, 'prompt', ttl);
  if (cfg.promptMode === 'block' && items.length) {
    const kinds = [...new Set(items.map((i) => i.rule))].join(', ');
    out({ decision: 'block', reason: `[keyfence] This message contains a credential (${kinds}). Send it again without the value: point to the file that holds it, or store it first and reference the variable name.` });
    return;
  }
  const pending = startClassifier(d, prompt, findings, cfg, ttl);
  const parts = [...takeNotices(d.session_id, ttl), ...promptNotes(d, prompt, findings, items, pending, cfg, ttl)];
  if (parts.length) note('UserPromptSubmit', parts.join(' '));
}

// What the agent is told about this prompt: saved names, or how to handle what
// could not be saved, plus the words still being checked.
function promptNotes(d, prompt, findings, items, pending, cfg, ttl) {
  const parts = [];
  const kinds = [...new Set(items.map((i) => i.rule))].join(', ');
  if (items.length && cfg.promptMode !== 'capture') parts.push(WARN_TEXT(kinds));
  if (items.length && cfg.promptMode === 'capture') {
    const saved = captureText(d, prompt, findings, cfg, ttl);
    if (saved || !pending) parts.push(saved || fallbackText(kinds));
  }
  if (pending) {
    parts.push(`keyfence is checking ${pending} more word(s) of this message in the background (a few seconds); they are protected meanwhile. ` +
      'Do not copy values from this message into commands, files or replies; if one is a credential, its name arrives with your next tool result.');
  }
  return parts;
}

// A heredoc body is data being written, not a command being run. Documentation
// that mentions a vault file must not count as reading it.
function stripHeredocs(cmd) {
  return cmd.replace(/<<-?\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n[\s\S]*?\n\s*\2\s*(?=\n|$)/g, '<<heredoc');
}

function vaultTarget(tool, input, cfg) {
  const hit = (p) => cfg._vault.some((re) => re.test(p));
  if (tool === 'Read' || tool === 'NotebookRead' || tool === 'Grep') {
    const p = String(input.file_path || input.notebook_path || input.path || '');
    return hit(p) ? p : null;
  }
  if (tool !== 'Bash') return null;
  // Judge each segment on its own: `grep -c K .env && cat .env` must still fail.
  for (const seg of stripHeredocs(String(input.command || '')).split(/\|\||&&|[|;&\n]/)) {
    if (!READER.test(seg) || SAFE_READ.some((re) => re.test(seg))) continue;
    for (const tok of seg.split(/[\s<>()'"`]+/)) if (tok && hit(tok)) return tok;
  }
  return null;
}

function gitTracks(file) {
  try {
    execFileSync('git', ['check-ignore', '-q', file], { cwd: path.dirname(file), timeout: 2000, stdio: 'ignore' });
    return false; // ignored
  } catch (e) {
    return e.status === 1; // 1 = not ignored inside a repo; 128 = not a repo
  }
}

function toolText(tool, input) {
  if (tool === 'Bash') return String(input.command || '');
  if (!LOCAL_TOOLS.has(tool)) return JSON.stringify(input);
  return [input.content, input.new_string, input.edits && JSON.stringify(input.edits), input.new_source].filter(Boolean).join('\n');
}

function judge(d, cfg) {
  const tool = String(d.tool_name || '');
  const input = d.tool_input || {};

  const vault = vaultTarget(tool, input, cfg);
  if (vault) {
    return deny(`Reading ${vault} would print its secrets into the transcript. Use the file without printing it ` +
      '(source it, pass it to the program that needs it), or use a form that never outputs a value: `grep -c NAME file`, `cut -d= -f1 file`, `jq \'keys\' file`.');
  }

  const text = toolText(tool, input);
  const ttl = cfg.ttlHours * 3600e3;
  const list = readState(statePath(d.session_id), ttl);
  const hit = findTainted(text, list);
  pendingHit = Boolean(hit && hit.rule === 'pending');
  const file = String(input.file_path || input.notebook_path || '');

  if (hit) {
    if (!LOCAL_TOOLS.has(tool)) {
      if (cfg._allowTools.some((re) => re.test(tool))) return;
      return deny(`A secret seen in this session (${hit.rule}, ${hit.shape}) would be sent through ${tool}, which leaves the machine.`);
    }
    if (tool === 'Bash' && NETWORK.test(text)) {
      return deny(`A secret seen in this session (${hit.rule}, ${hit.shape}) is in a command that talks to the network. ` +
        'Load it from the file that already stores it (for example `source .env`) and reference that variable; copying the value into a new variable or file is blocked the same way.');
    }
    if (file && CODE_FILE.test(file) && !/(^|\/)\.env/.test(file)) {
      return deny(`A secret seen in this session (${hit.rule}, ${hit.shape}) would be hardcoded into ${file}. Read it from an environment variable or a secret store instead.`);
    }
    if (file && gitTracks(file)) {
      return deny(`A secret seen in this session (${hit.rule}, ${hit.shape}) would be written to ${file}, which git tracks. Put it in a git-ignored file and reference the variable.`);
    }
    const copies = copiesOf(tool, input, file, list, cfg);
    if (copies.length) mark(d.session_id, copies, ttl);
    return;
  }

  if (tool === 'Bash' && NETWORK.test(text)) {
    const via = copyLeaving(text, list, cfg);
    if (via) {
      return deny(`A secret seen in this session (${via}) would be sent by a command that talks to the network. ` +
        'Load it from the file that already stores it (for example `source .env`) and reference that variable instead.');
    }
  }

  if (cfg.egress.blockNewSecretsInTrackedFiles && file && text && !/\.(example|sample|template)$/.test(file)) {
    const f = scan(text).findings.find((x) => x.confidence === 'high');
    if (f && gitTracks(file)) {
      return deny(`This write puts a ${f.name} (${shape(f.value)}) into ${file}, which git tracks. Read it from an environment variable or a git-ignored file instead.`);
    }
  }
}

// A Bash command that uses a captured variable gets the env file loaded first,
// so the agent writes `$META_ACCESS_TOKEN` and never handles the value.
function inject(d, cfg) {
  if (!cfg.capture.inject || d.tool_name !== 'Bash') return;
  const input = d.tool_input || {};
  const cmd = String(input.command || '');
  const list = readState(statePath(d.session_id), cfg.ttlHours * 3600e3);
  const files = [];
  for (const x of list) {
    if (x.d !== 'store' || !new RegExp(`\\$\\{?${x.n}\\b`).test(cmd)) continue;
    const loads = new RegExp(`(?:^|[;&|\\s])(?:source|\\.)\\s+['"]?[^\\s;&|'"]*${reEscape(path.basename(x.file))}['"]?(?=$|[\\s;&|])`);
    if (!loads.test(cmd) && !files.includes(x.file)) files.push(x.file);
  }
  if (!files.length) return;
  const q = (f) => `'${f.replace(/'/g, "'\\''")}'`;
  const prefix = `set -a; ${files.map((f) => `. ${q(f)}`).join('; ')}; set +a; `;
  out({ hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput: { ...input, command: prefix + cmd } } });
}

function onPreTool(d, cfg) {
  if (judge(d, cfg)) return;
  inject(d, cfg);
}

// Every string in a tool response, with each value in `hide` replaced.
function scrub(v, hide) {
  if (typeof v === 'string') {
    let t = v;
    for (const [val, label] of hide) t = t.split(val).join(label);
    return t;
  }
  if (Array.isArray(v)) return v.map((x) => scrub(x, hide));
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, scrub(x, hide)]));
  return v;
}

function onPostTool(d, cfg) {
  const r = d.tool_response;
  const text = typeof r === 'string' ? r : JSON.stringify(r || '');
  if (!text) return;
  const ttl = cfg.ttlHours * 3600e3;
  const { findings } = scan(text.slice(0, MAX_SCAN));
  const added = findings.length ? taint(d.session_id, findings, `tool:${d.tool_name}`, ttl) : 0;

  // Values to hide: new findings, plus any piece whose hash is remembered.
  const hide = new Map();
  if (cfg.redactOutput) {
    const list = readState(statePath(d.session_id), ttl);
    const names = new Map(list.filter((x) => x.d === 'store').map((x) => [x.h, x.n]));
    const rules = new Map(list.filter((x) => x.h && !x.d && x.rule !== 'pending').map((x) => [x.h, x.rule]));
    const label = (v, rule) => { const h = hash(v); return names.has(h) ? `⟨${names.get(h)}⟩` : `⟨keyfence:${rules.get(h) || rule}⟩`; };
    for (const f of findings) hide.set(f.value, label(f.value, f.rule));
    if (rules.size) {
      for (const p of pieces(text)) if (!hide.has(p) && rules.has(hash(p)) && text.includes(p)) hide.set(p, label(p));
    }
  }
  const kinds = [...new Set(findings.map((f) => f.rule))].join(', ');
  const parts = takeNotices(d.session_id, ttl);
  if (hide.size) {
    parts.unshift(`The output of ${d.tool_name} contained a credential; keyfence replaced it with ${[...new Set(hide.values())].join(', ')} before you saw it. Refer to it by that name; do not try to print it another way.`);
    out({ hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: scrub(r, hide), additionalContext: `[keyfence] ${parts.join(' ')}` } });
    return;
  }
  if (added) {
    parts.unshift(`The output of ${d.tool_name} contained a credential (${kinds}). It is now in this transcript: do not repeat it, and tell the user it may need rotation. ` +
      'It is protected from being sent out or written to tracked files from now on.');
  }
  if (parts.length) note('PostToolUse', parts.join(' '));
}

async function main() {
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  let d;
  try {
    d = JSON.parse(raw || '{}');
  } catch {
    return;
  }
  const cfg = config.load();
  const ev = d.hook_event_name;
  if (ev === 'UserPromptSubmit') await onPrompt(d, cfg);
  else if (ev === 'PreToolUse') onPreTool(d, cfg);
  else if (ev === 'PostToolUse') onPostTool(d, cfg);
}

module.exports = { main, pieces, hash, statePath, vaultTarget, readState, writeState, taint, mark, pushNotice, captureText, fallbackText, WARN_TEXT };
