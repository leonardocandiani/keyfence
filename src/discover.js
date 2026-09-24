'use strict';
// `keyfence discover`: find the credentials already scattered on this machine
// (project .env files, `export` lines in shell rc files) and register each one
// as a vault credential, with every place it lives. Sources are only read, never
// changed; values are never printed. A value that shows up in a past Claude Code
// session is marked exposed, so it lands on the rotation list.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan, looksSecret } = require('./detect');
const { parseEnv, NAMES } = require('./capture');
const { projectName, slug } = require('./credential');

const SKIP = new Set(['node_modules', '.git', 'Library', '.Trash', '.cache', 'dist', 'build', '.next', 'vendor', 'venv', '.venv',
  '__pycache__', 'Pods', 'DerivedData', '.npm', '.cargo', '.rustup', 'go', '.local', '.docker', 'Applications', 'Movies', 'Music', 'Pictures']);
const ENV_FILE = /^\.env(?:\.(?!example$|sample$|template$|dist$|bak)[A-Za-z0-9_.-]+)?$/;
const RC_FILES = ['.zshrc', '.zprofile', '.zshenv', '.bashrc', '.bash_profile', '.profile'];
const SECRET_NAME = /(?:^|_)(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|AUTH|CREDENTIALS?|PRIVATE|DSN)(?:_|$)|DATABASE_URL|WEBHOOK_URL/;
const PUBLIC_NAME = /^(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_)|PUBLISHABLE|ANON_KEY|PUBLIC_KEY/;
const BY_SDK_NAME = new Map(Object.entries(NAMES).map(([rule, name]) => [name, slug(rule.split('-')[0])]));

function envFiles(dir, depth, out = []) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isFile() && ENV_FILE.test(e.name) && !e.name.includes('.bak-keyfence')) out.push(path.join(dir, e.name));
    else if (e.isDirectory() && depth > 0 && !SKIP.has(e.name) && !e.name.startsWith('.')) envFiles(path.join(dir, e.name), depth - 1, out);
  }
  return out;
}

function rcExports(home) {
  const out = [];
  for (const f of RC_FILES.map((n) => path.join(home, n))) {
    let src = '';
    try { src = fs.readFileSync(f, 'utf8'); } catch { continue; }
    const vars = parseEnv(src.split('\n').filter((l) => /^\s*export\s+[A-Za-z_]/.test(l)).join('\n'));
    for (const [name, value] of vars) out.push({ file: f, name, value });
  }
  return out;
}

// A credential by its value (a known format) or by its name plus a value that
// is not a placeholder; public keys meant for browsers are left out.
function isCredential(name, value) {
  if (!value || PUBLIC_NAME.test(name) || /^\$|^\$\{/.test(value)) return false;
  if (scan(`${name}=${value}`).findings.some((f) => f.value === value)) return true;
  return SECRET_NAME.test(name) && looksSecret(value, name.toLowerCase());
}

function serviceOf(name, file) {
  if (BY_SDK_NAME.has(name)) return BY_SDK_NAME.get(name);
  const m = /^([A-Z0-9]+(?:_[A-Z0-9]+)*?)_(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|TOKEN|PASSWORD|SECRET_KEY|SECRET|KEY|DSN|WEBHOOK_URL)$/.exec(name);
  return m ? slug(m[1]) : projectName(path.dirname(file)) || 'misc';
}

const roleOf = (name) => (/PASS|PWD/.test(name) ? 'password' : /TOKEN/.test(name) ? 'token' : /URL|DSN/.test(name) ? 'url'
  : /SECRET|PRIVATE/.test(name) ? 'secret' : 'api_key');
const envOf = (file) => (/\.env\.(?:prod|production)$/.test(file) ? 'prod' : /\.env\.(?:test|staging|homolog)/.test(file) ? 'test' : 'dev');

// Every credential found, grouped: one value = one record; one service with
// several values gets one record per project.
function inventory(roots, depth, home) {
  const found = [];
  for (const file of roots.flatMap((r) => envFiles(r, depth))) {
    let env;
    try { env = parseEnv(fs.readFileSync(file, 'utf8')); } catch { continue; }
    for (const [name, value] of env) if (isCredential(name, value)) found.push({ file, name, value });
  }
  for (const x of rcExports(home)) if (isCredential(x.name, x.value)) found.push(x);
  return group(found);
}

// Values the vault already holds keep their record: the place is added to it.
// With the same value under several aliases, the specific one (sis/robson) wins
// over a service/default leftover.
function knownAliases() {
  const vault = require('./vault');
  const { salt, list } = vault.fingerprints();
  const byPrint = new Map();
  for (const x of list) {
    const prev = byPrint.get(x.fp);
    if (!prev || (prev.alias.endsWith('/default') && !x.alias.endsWith('/default'))) byPrint.set(x.fp, { alias: x.alias, role: x.field });
  }
  return (value) => byPrint.get(vault.fingerprint(salt, Buffer.from(value))) || null;
}

function attachKnown(records, k, x) {
  const rec = records.find((r) => r.alias === k.alias && r.value === x.value);
  if (rec) rec.places.push(x);
  else records.push({ alias: k.alias, role: k.role, value: x.value, environment: envOf(x.file), places: [x] });
}

function group(found) {
  const known = knownAliases();
  const byService = new Map();
  const records = [];
  for (const x of found) {
    const k = known(x.value);
    if (k) { attachKnown(records, k, x); continue; }
    const svc = serviceOf(x.name, x.file);
    if (!byService.has(svc)) byService.set(svc, new Map());
    const byValue = byService.get(svc);
    if (!byValue.has(x.value)) byValue.set(x.value, []);
    byValue.get(x.value).push(x);
  }
  // An alias the vault already uses for another value is taken: discover only
  // creates records or adds places, it never overwrites a credential.
  const taken = new Set(require('./vault').list().map((x) => x.alias));
  for (const [svc, byValue] of byService) {
    const used = new Set([...taken].filter((a) => a.startsWith(`${svc}/`)).map((a) => a.slice(svc.length + 1)));
    for (const [value, places] of byValue) {
      let account = byValue.size === 1 ? 'default' : projectName(path.dirname(places[0].file)) || 'default';
      for (let n = 2; used.has(account); n++) account = `${account.replace(/-\d+$/, '')}-${n}`;
      used.add(account);
      records.push({ alias: `${svc}/${account}`, role: roleOf(places[0].name), value, environment: envOf(places[0].file), places });
    }
  }
  return records;
}

// Values that appear in recent Claude Code session logs went through a chat.
function exposedValues(values) {
  const root = process.env.KEYFENCE_LOGS_DIR || path.join(os.homedir(), '.claude', 'projects');
  const since = Date.now() - 120 * 86400e3;
  const seen = new Set();
  const needles = values.map((v) => [v, JSON.stringify(v).slice(1, -1)]);
  let dirs = [];
  try { dirs = fs.readdirSync(root); } catch { return seen; }
  for (const d of dirs) {
    let files = [];
    try { files = fs.readdirSync(path.join(root, d)).filter((f) => f.endsWith('.jsonl')).map((f) => path.join(root, d, f)); } catch { continue; }
    for (const f of files.filter((x) => { try { return fs.statSync(x).mtimeMs > since; } catch { return false; } })) {
      const text = fs.readFileSync(f, 'utf8');
      for (const [v, e] of needles) if (!seen.has(v) && text.includes(e)) seen.add(v);
    }
  }
  return seen;
}

const tildeOf = (p) => p.replace(os.homedir(), '~');

// Env files join the daily maintenance; a variable already mapped (by capture
// or tidy) keeps its mapping. Shell rc files are only read.
function registerPlaces(r, remember) {
  const { readRegistry } = require('./capture');
  const names = readRegistry().names;
  for (const p of r.places) {
    if (RC_FILES.includes(path.basename(p.file)) || (names[p.file] && names[p.file][p.name])) continue;
    remember(p.file, { [p.name]: { alias: r.alias, role: r.role, environment: r.environment } });
  }
}

/**
 * Find credentials under `roots` and, with apply, register them.
 * @returns {{records: {alias, role, places: string[], exposed, action}[], files: number}}
 */
async function discover({ roots, depth = 5, apply = false, home = os.homedir() }) {
  const recs = inventory(roots, depth, home);
  const exposed = exposedValues(recs.map((r) => r.value));
  const vault = require('./vault');
  const { remember } = require('./capture');
  const out = [];
  for (const r of recs) {
    const sources = r.places.map((p) => `${tildeOf(p.file)}:${p.name}`);
    let action = vault.show(r.alias) ? 'known' : 'new';
    if (apply) {
      try { action = (await vault.upsert(r.alias, { [r.role]: r.value }, { environment: r.environment, exposed: exposed.has(r.value), sources })).action; } catch (e) { action = `vault unavailable (${e.message.slice(0, 30)})`; }
      registerPlaces(r, remember);
    }
    out.push({ alias: r.alias, role: r.role, places: sources, exposed: exposed.has(r.value), action });
  }
  return { records: out, files: new Set(recs.flatMap((r) => r.places.map((p) => p.file))).size };
}

module.exports = { discover, isCredential, inventory };
