'use strict';
// `keyfence tidy`: give old captures good names. Older versions saved values as
// PASSWORD, SENHA, SECRET, PASSWORD_2... with no hint of whose they are. The
// message each value came from is still in the Claude Code session logs, so the
// value is looked up there (inside this process, never printed) and the
// credential is rebuilt with today's rules: service, account, login, url.
//
// A generic name is renamed only when nothing in the project reads it; if code
// does, the old line stays and the new names are added next to it. The env file
// is backed up (0600) before any change, and each record goes to the vault.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scan } = require('./detect');
const { build } = require('./credential');
const { parseEnv } = require('./capture');

const GENERIC = /^(?:PASSWORD|SENHA|SECRET|SEGREDO|TOKEN|API_KEY|KEY|CHAVE|PIN|CREDENTIAL|CREDENCIAL|JWT)(?:_\d+)?$/;
const SINCE_DAYS = 120;
const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/;

function sessionLogs() {
  const root = process.env.KEYFENCE_LOGS_DIR || path.join(os.homedir(), '.claude', 'projects');
  const since = Date.now() - SINCE_DAYS * 86400e3;
  const out = [];
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch { return out; }
  for (const dir of dirs) {
    let files = [];
    try { files = fs.readdirSync(path.join(root, dir)).filter((f) => f.endsWith('.jsonl')); } catch { continue; }
    for (const f of files) {
      const p = path.join(root, dir, f);
      try { if (fs.statSync(p).mtimeMs >= since) out.push(p); } catch { /* gone */ }
    }
  }
  return out;
}

function userMessage(line) {
  let o;
  try { o = JSON.parse(line); } catch { return null; }
  const ok = o && o.type === 'user' && !o.isMeta && o.message && typeof o.message.content === 'string';
  return ok ? { text: o.message.content, cwd: o.cwd } : null;
}

// User messages where today's detection recognizes each value as a credential,
// messages from the env file's own project first. A value that is only a word in
// some message (an old false capture) finds nothing and is left alone.
function messagesWith(values, root) {
  const found = new Map();
  const escaped = values.map((v) => JSON.stringify(v).slice(1, -1));
  for (const file of sessionLogs()) {
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
      if (!escaped.some((e) => line.includes(e))) continue;
      const msg = userMessage(line);
      if (!msg) continue;
      const seen = new Set(scan(msg.text).findings.map((f) => f.value));
      for (const v of values) if (seen.has(v) && better(msg, found.get(v), root)) found.set(v, msg);
    }
  }
  return found;
}

// A message from the env file's own project beats one from anywhere else.
const inProject = (msg, root) => Boolean(msg && msg.cwd && msg.cwd.startsWith(root));
const better = (msg, prev, root) => !prev || (inProject(msg, root) && !inProject(prev, root));

function recordFor(value, msg, fallbackCwd) {
  return build(msg.text, scan(msg.text).findings, msg.cwd || fallbackCwd).find((r) => Object.values(r.fields).includes(value)) || null;
}

// Does code in the project read this variable? Only real environment access
// counts (process.env.NAME, os.environ['NAME'], getenv("NAME"), ${NAME}...):
// the word in a doc, a comment or a string is not a reader.
function envAccess(name) {
  // POSIX ERE (git grep -E): no \\b, so the word end is spelled out.
  const end = '([^A-Za-z0-9_]|$)';
  const q = `['"]${name}['"]`;
  return [`process\\.env\\.${name}${end}`, `process\\.env\\[${q}\\]`, `os\\.environ(\\.get)?[[(]${q}`, `getenv\\(${q}`,
    `ENV\\[${q}\\]`, `(^|[^A-Za-z0-9_])env\\(${q}`, `import\\.meta\\.env\\.${name}${end}`, `Deno\\.env\\.get\\(${q}`, `\\$\\{?${name}${end}`].join('|');
}

function referenced(name, root) {
  try {
    execFileSync('git', ['grep', '-q', '-E', envAccess(name), '--', ':!*.env', ':!.env*', ':!*.md', ':!docs/**'], { cwd: root, stdio: 'ignore', timeout: 5000 });
    return true;
  } catch (e) {
    return e.status !== 1; // 1 = no match; not a repo or an error: be careful, treat as used
  }
}

function plan(file) {
  const env = parseEnv(fs.readFileSync(file, 'utf8'));
  const generic = [...env].filter(([k]) => GENERIC.test(k));
  const root = path.dirname(file);
  const origin = messagesWith(generic.map(([, v]) => v), root);
  const p = { file, changes: [], unmatched: [], add: [], drop: new Set(), records: new Map() };
  for (const [oldName, value] of generic) {
    const rec = origin.has(value) ? recordFor(value, origin.get(value), root) : null;
    if (!rec) { p.unmatched.push(oldName); continue; }
    p.records.set(rec.alias, rec);
    const names = Object.entries(rec.fields).map(([role]) => rec.envNames[role]);
    for (const [role, v] of Object.entries(rec.fields)) {
      const n = rec.envNames[role];
      if (!env.has(n) && !p.add.some((a) => a.n === n)) p.add.push({ n, v });
    }
    const keep = referenced(oldName, root);
    if (!keep) p.drop.add(oldName);
    p.changes.push({ old: oldName, names, alias: rec.alias, action: keep ? 'kept, code reads it' : 'renamed' });
  }
  return p;
}

const quote = (v) => (/^[A-Za-z0-9_\-+/=.:@~%,]+$/.test(v) ? v : `'${v.replace(/'/g, "'\\''")}'`);

async function applyPlan(p) {
  if (!p.add.length && !p.drop.size) return null;
  const backup = `${p.file}.bak-keyfence-${Date.now()}`;
  fs.copyFileSync(p.file, backup);
  fs.chmodSync(backup, 0o600);
  const lines = fs.readFileSync(p.file, 'utf8').split('\n').filter((l) => { const m = ENV_LINE.exec(l); return !(m && p.drop.has(m[1])); });
  const added = p.add.map(({ n, v }) => `${n}=${quote(v)}\n`).join('');
  fs.writeFileSync(p.file, lines.join('\n').replace(/\n*$/, '\n') + added, { mode: 0o600 });
  for (const rec of p.records.values()) {
    try { await require('./vault').upsert(rec.alias, rec.fields, { environment: rec.environment, exposed: true }); } catch { /* vault unavailable: the env file is still fixed */ }
  }
  return backup;
}

const nameMap = (p) => Object.fromEntries([...p.records.values()].flatMap((rec) =>
  Object.keys(rec.fields).map((role) => [rec.envNames[role], { alias: rec.alias, role, environment: rec.environment }])));

/** Plan the renames for an env file; with apply, perform them. Never returns a value. */
async function tidyFile(file, { apply = false } = {}) {
  const p = plan(file);
  const backup = apply ? await applyPlan(p) : null;
  if (apply) require('./capture').remember(file, nameMap(p)); // tidied once, maintained from then on
  return { file, changes: p.changes, unmatched: p.unmatched, backup };
}

module.exports = { tidyFile, plan, nameMap, GENERIC };
