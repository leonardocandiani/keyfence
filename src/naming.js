'use strict';
// Naming a credential from what the message says about it.
//
// A capture that no provider format, user-written name or URL settles gets a
// provisional code at once (kf/7f3a, KF_7F3A_PASSWORD): unique, never a guess,
// so a hundred captures never end up as a hundred `aqui` or `senha`. Then, in
// the background, the classifier reads the message (values masked) and answers,
// for each secret and each word, whether that word names the service, system or
// site the secret is for. The credential is renamed to the answer everywhere:
// vault, env file, registry and the session, and the agent is told.
//
// There is no list of words to skip: every name-shaped word is a candidate and
// the context decides. Without the classifier the name comes from the message's
// structure (a domain in it) or the project, never from a loose word.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { makePrivate, renameRetry } = require('./fsmode');
const { edgeOf } = require('./detect');
const { slug, upper, structuralName } = require('./credential');

const provisionalId = () => crypto.randomBytes(2).toString('hex');
const isProvisional = (alias) => /^kf\/[0-9a-f]{4}$/.test(alias);
const PROVISIONAL_NAME = /^KF_[0-9A-F]{4}_/;

// URL syntax, not names: the scheme, www and top-level domains.
const URL_PART = /^(?:https?|www|com|net|org|io|co|dev|app|ai|me|us|uk|gov|edu|info|br|html?|php)$/i;
const NAME_SHAPE = /^\p{L}[\p{L}\p{N}]*(?:[-_]\p{L}[\p{L}\p{N}]*)*$/u;

// A word and its parts that could be a name: lojaexemplo.com.br/cpanel gives
// lojaexemplo and cpanel. These go to the classifier in clear, so a word with a
// digit never does: names rarely carry one, secrets, ids and order numbers do.
const nameParts = (w, local) => [...new Set([w, ...w.split(/[./:@?#=&]+/)])]
  .filter((p) => p.length >= 2 && p.length <= 30 && !URL_PART.test(p) && NAME_SHAPE.test(p) && (local || !/\p{N}/u.test(p)));

// Every word that could be a name, closest to a secret first.
function nameCandidates(text, hidden, max = 16, local = false) {
  const anchors = hidden.map((v) => text.indexOf(v)).filter((i) => i >= 0);
  const dist = (i) => (anchors.length ? Math.min(...anchors.map((a) => Math.abs(a - i))) : i);
  const found = new Map();
  let offset = 0;
  for (const line of String(text).split('\n')) {
    for (const m of line.matchAll(/\S+/g)) {
      const w = edgeOf(line.slice(0, m.index), m[0], line.slice(m.index + m[0].length));
      if (hidden.some((v) => w.includes(v) || v.includes(w))) continue;
      for (const part of nameParts(w, local)) {
        const key = part.toLowerCase();
        const d = dist(offset + m.index);
        if (!found.has(key) || found.get(key).d > d) found.set(key, { word: part, d });
      }
    }
    offset += line.length + 1;
  }
  return [...found.values()].sort((a, b) => a.d - b.d).slice(0, max).map((x) => x.word);
}

const NAME_Q = 'Is the word "WORD" in `message` the name of the service, system, site, product or company that the secret ⟨ID⟩ '
  + 'gives access to? A word that only points at it or describes it (here, this, access, password, login, user, account) is not its name.';

/**
 * Which service each secret is for. `secrets` are values from `text`; `hidden`
 * adds values that must not leave the machine either (the login). Returns
 * [{value, service, by}], `by` saying how it was decided.
 */
async function decide(text, secrets, hidden, cfg, cwd, sid) {
  const all = [...secrets, ...hidden.filter((h) => !secrets.includes(h))];
  const guarded = protectedIn(sid, cfg);
  const words = nameCandidates(text, all, Math.max(6, Math.floor(40 / Math.max(1, secrets.length))))
    .filter((w) => !guarded(w));
  let answers = null;
  if (cfg.jev.enabled && words.length) {
    const { askNoul, maskIds } = require('./jev');
    const questions = {};
    secrets.forEach((_, i) => words.forEach((w, j) => { questions[`s${i + 1}w${j + 1}`] = NAME_Q.replace('WORD', w).replace('ID', `c${i + 1}`); }));
    answers = await askNoul(maskIds(text.slice(0, 8000), all), questions, cfg);
  }
  const known = knownAliases();
  // Matching known accounts happens here, so every word may take part, even one
  // inside a secret (robson in robson9999), which never goes to the classifier.
  const local = nameCandidates(text, [], 500, true);
  return secrets.map((value, i) => {
    const at = text.indexOf(value);
    let service = structuralName(text, cwd, at);
    let by = answers ? 'structure: no word in the message names it' : 'structure: classifier unavailable';
    const ranked = answers ? words.map((w, j) => ({ w, p: answers[`s${i + 1}w${j + 1}`] })).sort((a, b) => b.p - a.p) : [];
    // The name is the word that stands out: sure on its own, or well ahead of every other word.
    const [first, second] = ranked;
    if (first && (first.p >= cfg.jev.pickThreshold || (first.p >= 0.3 && first.p >= 3 * ((second && second.p) || 0)))) {
      [service, by] = [slug(first.w), 'context'];
    }
    return { value, service, account: accountIn(local, service, known), by, ranked: ranked.slice(0, 3) };
  });
}

// An account the vault already knows for that service, named in the message:
// "nova senha do robson no sis" is sis/robson when sis/robson exists.
function accountIn(words, service, known) {
  const accounts = new Set(known.filter((a) => a.startsWith(`${service}/`)).map((a) => a.split('/')[1]));
  const hit = words.map((w) => slug(w)).find((w) => accounts.has(w) && w !== 'default');
  return hit || '';
}

// Any word the session protects (pending, unclear, a secret) never goes out, by
// hash, whichever path tainted it.
function protectedIn(sid, cfg) {
  if (!sid) return () => false;
  const { statePath, readState, hash } = require('./hook');
  const hashes = new Set(readState(statePath(sid), cfg.ttlHours * 3600e3).map((x) => x.h));
  return (w) => hashes.has(hash(w));
}

function knownAliases() {
  try { return require('./vault').list().map((x) => x.alias); } catch { return []; }
}

// --- renaming a provisional credential ----------------------------------------------

// Does code in the session's repo already read the provisional name? Then the old
// line stays next to the new one. Outside a repo nothing can read it yet.
function readByCode(name, cwd) {
  try {
    execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, stdio: 'ignore', timeout: 2000 });
  } catch {
    return false;
  }
  return require('./tidy').referenced(name, cwd);
}

// Rename variables in an env file, keeping each value exactly as written. A new
// name that already holds the same value just absorbs the old one; one that holds
// another value gets a suffix.
function renameInEnv(file, map, keep) {
  const src = fs.readFileSync(file, 'utf8');
  const env = require('./capture').parseEnv(src);
  const final = {};
  const lines = src.split('\n').flatMap((line) => {
    const m = /^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=.*)$/.exec(line);
    if (!m || !map[m[2]]) return [line];
    let to = map[m[2]];
    for (let i = 2; env.has(to) && env.get(to) !== env.get(m[2]); i++) to = `${map[m[2]]}_${i}`;
    final[m[2]] = to;
    const renamed = env.has(to) ? [] : [`${m[1]}${to}${m[3]}`];
    env.set(to, env.get(m[2]));
    return keep.has(m[2]) ? [line, ...renamed] : renamed;
  });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, lines.join('\n'), { mode: 0o600 });
  renameRetry(tmp, file);
  makePrivate(file);
  return final;
}

// Where each field of a provisional record goes: the service its secret was
// named for (login and url follow the password), the account, the new env name.
function renamePlan(rec, named) {
  const byValue = new Map(named.map((n) => [n.value, n]));
  const secretRoles = Object.keys(rec.fields).filter((r) => byValue.has(rec.fields[r]));
  const lead = byValue.get(rec.fields[secretRoles.find((r) => /^(?:password|pin)/.test(r)) || secretRoles[0]]) || {};
  const plan = { targets: {}, envMap: {}, mappings: {} };
  for (const [role, value] of Object.entries(rec.fields)) {
    const service = (byValue.get(value) || lead).service;
    const account = /^(?:password|pin|login|url)/.test(role) ? rec.account || lead.account : '';
    const alias = `${service}/${account || 'default'}`;
    (plan.targets[alias] = plan.targets[alias] || {})[role] = role;
    plan.mappings[role] = { alias, role, environment: rec.environment, named: true };
    // Only the provisional names: a value the capture found already saved under
    // one of the user's own names keeps that name.
    if (PROVISIONAL_NAME.test(rec.names[role])) plan.envMap[rec.names[role]] = [upper(service), account && upper(account), role.toUpperCase()].filter(Boolean).join('_');
  }
  return plan;
}

/**
 * Give a provisional record its names. `rec` is what the capture wrote:
 * {alias, file, environment, account, fields: {role: value}, names: {role: envName}}.
 * `named` is decide()'s answer. Returns {final, note}.
 */
async function rename(sid, rec, named, cwd, ttl) {
  const { targets, envMap, mappings } = renamePlan(rec, named);
  try { await require('./vault').move(rec.alias, targets); } catch { /* vault unavailable: the env file still gets the names */ }
  // The provisional lines stay until the daily maintenance: a command the agent
  // runs while the rename happens still finds its variable.
  const final = renameInEnv(rec.file, envMap, new Set(Object.keys(envMap)));
  const byNew = Object.fromEntries(Object.entries(rec.names).map(([role, old]) => [final[old] || old, mappings[role]]));
  require('./capture').remember(rec.file, byNew, Object.keys(final));
  renameInSession(sid, final, ttl);
  const list = Object.entries(final).map(([o, n]) => `$${o} is now $${n}`).join(', ');
  return { final, note: `keyfence named the credential from the user's message by its context: ${list} (vault: ${Object.keys(targets).join(', ')}). `
    + 'Use the new names from now on; the provisional ones keep working until the daily maintenance removes them.' };
}

// The session keeps loading the env file for commands that use the new names.
function renameInSession(sid, final, ttl) {
  const { statePath, readState, mark } = require('./hook');
  const stored = readState(statePath(sid), ttl).filter((x) => x.d === 'store' && final[x.n]);
  mark(sid, stored.map((x) => ({ d: 'store', n: final[x.n], file: x.file, h: x.h, rule: x.rule })), ttl);
}

// --- background job ------------------------------------------------------------------

/** Start naming in the background; the prompt hook never waits for it. */
function startNaming(sid, cwd, prompt, recs, logins) {
  if (!recs.length) return false;
  try {
    const os = require('os');
    const job = path.join(os.tmpdir(), `keyfence-name-${String(sid).replace(/[^A-Za-z0-9_-]/g, '')}-${Date.now()}.json`);
    fs.writeFileSync(job, JSON.stringify({ sid, cwd, prompt, recs, logins }), { mode: 0o600 });
    const { spawn } = require('child_process');
    spawn(process.execPath, [path.join(__dirname, '..', 'bin', 'keyfence-hook.js'), '--name', job], { detached: true, stdio: 'ignore', env: process.env }).unref();
    return true;
  } catch {
    return false;
  }
}

async function runJob(jobFile) {
  let job;
  try {
    job = JSON.parse(fs.readFileSync(jobFile, 'utf8'));
  } finally {
    try { fs.unlinkSync(jobFile); } catch { /* already gone */ }
  }
  const cfg = require('./config').load();
  const notes = [];
  for (const rec of job.recs) {
    const secrets = Object.entries(rec.fields).filter(([r]) => !/^(?:login|url)/.test(r)).map(([, v]) => v);
    const named = await decide(job.prompt, secrets, [rec.fields.login, ...(job.logins || [])].filter(Boolean), cfg, job.cwd, job.sid);
    notes.push((await rename(job.sid, rec, named, job.cwd, cfg.ttlHours * 3600e3)).note);
  }
  if (notes.length) require('./hook').pushNotice(job.sid, notes.join(' '), cfg.ttlHours * 3600e3);
}

// Provisional lines whose value already lives under a real name in the same
// file are removed, unless code in that project reads the provisional name.
function cleanProvisional({ apply = false } = {}) {
  const cap = require('./capture');
  const out = [];
  for (const file of cap.registered().filter((f) => fs.existsSync(f))) {
    const env = cap.parseEnv(fs.readFileSync(file, 'utf8'));
    const real = new Set([...env].filter(([n]) => !PROVISIONAL_NAME.test(n)).map(([, v]) => v));
    const drop = [...env].filter(([n, v]) => PROVISIONAL_NAME.test(n) && real.has(v) && !readByCode(n, path.dirname(file))).map(([n]) => n);
    if (!drop.length) continue;
    if (apply) dropLines(file, new Set(drop));
    out.push({ file, names: drop });
  }
  return out;
}

function dropLines(file, names) {
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter((l) => { const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(l); return !(m && names.has(m[1])); });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, lines.join('\n'), { mode: 0o600 });
  renameRetry(tmp, file);
  makePrivate(file);
}

// --- credentials named by older versions ----------------------------------------------

// Credentials an older version named from a loose word (aqui/..., senha/...) get
// the name their message's context gives, once each. Names a person wrote or a
// provider format set stay; a credential whose message is gone stays as is. Every
// variable looked at is marked `named`, so the classifier is asked only once.
async function nameOld({ apply = false, cfg = require('./config').load() } = {}) {
  const cap = require('./capture');
  const byAlias = oldAliases(cap);
  const secretVals = (vars) => vars.filter((v) => !/^(?:login|url)/.test(v.role)).map((v) => v.value);
  const origin = require('./tidy').messagesWith([...byAlias.values()].flatMap(secretVals), '', { pieces: true });
  const out = [];
  for (const [alias, vars] of byAlias) {
    const secrets = secretVals(vars);
    const msg = secrets.length ? origin.get(secrets[0]) : null;
    const r = msg ? await planOld(alias, vars, secrets, { ...msg, whole: wholeOf(secrets, origin) }, cfg) : { alias, action: 'kept: its message is no longer in the logs' };
    if (apply) await applyOld(r, vars, cap);
    out.push(r);
  }
  return out;
}

// The name keyfence itself gave a variable of that credential: SIS_ROBSON_PASSWORD
// for sis/robson. Only these are renamed; a name the user chose (a project's own
// DB_PASS, registered by discover) is never touched.
const generatedName = (alias, role) => {
  const [service, account] = alias.split('/');
  return [upper(service), account !== 'default' && upper(account), role.toUpperCase()].filter(Boolean).join('_');
};

// A variable keyfence named from a loose word and has not looked at since. Older
// registries hold entries without alias or role: nothing to rename there.
const worthNaming = (name, m, env, sdk) => Boolean(m && m.alias && m.role) && !m.named && env.has(name) && !sdk.has(name)
  && !isProvisional(m.alias) && name === generatedName(m.alias, m.role);

// Registered variables not yet named by context, grouped by credential, with
// values read from their env files (never printed).
function oldAliases(cap) {
  const sdk = new Set(Object.values(cap.NAMES));
  const byAlias = new Map();
  for (const [file, map] of Object.entries(cap.readRegistry().names)) {
    if (!fs.existsSync(file)) continue;
    const env = cap.parseEnv(fs.readFileSync(file, 'utf8'));
    for (const [name, m] of Object.entries(map)) {
      if (!worthNaming(name, m, env, sdk)) continue;
      if (!byAlias.has(m.alias)) byAlias.set(m.alias, []);
      byAlias.get(m.alias).push({ file, name, role: m.role, value: env.get(name), environment: m.environment });
    }
  }
  return byAlias;
}

// A name the user wrote next to the value, or a provider's format, was right from the start.
function namedAtSource(msg, secrets) {
  const { scan } = require('./detect');
  const { build } = require('./credential');
  const items = scan(msg.text, { message: true }).findings.filter((f) => secrets.includes(f.value));
  const recs = build(msg.text, items.length ? items : secrets.map((value) => ({ value, rule: 'classifier', start: msg.text.indexOf(value) })), msg.cwd);
  return recs.length > 0 && recs.every((x) => x.sure);
}

// Every saved secret of a credential is a piece of the same secret in its
// message: that secret, whole, is the real value.
function wholeOf(secrets, origin) {
  const wholes = new Set(secrets.map((v) => (origin.get(v) || {}).whole));
  return wholes.size === 1 && [...wholes][0] ? [...wholes][0] : null;
}

// The saved secrets are pieces of `whole`: the first one's role gets it back.
function repairOf(vars, secrets, whole) {
  if (!whole) return null;
  const pieces = vars.filter((v) => secrets.includes(v.value));
  return { value: whole, role: pieces[0].role, pieces };
}

async function planOld(alias, vars, secrets, msg, cfg) {
  const repair = repairOf(vars, secrets, msg.whole);
  if (!repair && namedAtSource(msg, secrets)) return { alias, action: 'kept: named by the user or the provider' };
  const logins = vars.filter((v) => v.role === 'login').map((v) => v.value);
  const [n] = await decide(msg.text, repair ? [repair.value] : secrets, logins, cfg, msg.cwd);
  const current = alias.split('/')[1];
  const account = current !== 'default' ? current : n.account;
  // A name that exists is changed only when the context names the service.
  const to = n.by === 'context' ? `${n.service}/${account || 'default'}` : alias;
  return { alias, to, account, repair, action: outcome(to === alias, repair, n) };
}

function outcome(same, repair, n) {
  const named = same ? (n.by === 'context' ? 'the context agrees' : 'the context did not name it') : `renamed (${n.by})`;
  return repair ? `repaired: the saved value was a piece of the one in the message; ${named}` : same ? `kept: ${named}` : named;
}

async function applyOld(r, vars, cap) {
  const mark = (file, names, extra = {}) => cap.remember(file, Object.fromEntries(names.map((v) => [v.name, { alias: r.to || r.alias, role: v.role, environment: v.environment, named: true, ...extra }])));
  const files = [...new Set(vars.map((v) => v.file))];
  if (r.repair) { await repairOld(r, vars, cap); return; }
  if (!r.to || r.to === r.alias) { files.forEach((f) => mark(f, vars.filter((v) => v.file === f))); return; }
  const roles = [...new Set(vars.map((v) => v.role))];
  try { await require('./vault').move(r.alias, { [r.to]: Object.fromEntries(roles.map((x) => [x, x])) }); } catch { /* vault unavailable: the env files still get the names */ }
  const base = [upper(r.to.split('/')[0]), r.account && upper(r.account)].filter(Boolean).join('_');
  for (const f of files) {
    const here = vars.filter((v) => v.file === f);
    const map = Object.fromEntries(here.map((v) => [v.name, `${base}_${v.role.toUpperCase()}`]));
    const root = path.dirname(f);
    const keep = new Set(here.map((v) => v.name).filter((n) => readByCode(n, root)));
    const final = renameInEnv(f, map, keep);
    cap.remember(f, Object.fromEntries(here.map((v) => [final[v.name] || v.name, { alias: r.to, role: v.role, environment: v.environment, named: true }])),
      Object.keys(final).filter((n) => !keep.has(n)));
    r.names = [...(r.names || []), ...Object.entries(final).map(([o, n]) => `${o} -> ${n}`)];
  }
}

// A credential saved in pieces gets its whole value back: the vault record is
// replaced, the first piece's line carries the whole value under the new name,
// the other pieces' lines go (unless code reads them).
async function repairOld(r, vars, cap) {
  const pieces = new Set(r.repair.pieces.map((v) => v.name));
  const keepVars = vars.filter((v) => !pieces.has(v.name));
  const fields = { [r.repair.role]: r.repair.value, ...Object.fromEntries(keepVars.map((v) => [v.role, v.value])) };
  const environment = vars[0].environment || 'dev';
  const vault = require('./vault');
  try { vault.remove(r.alias); await vault.upsert(r.to, fields, { environment, exposed: true }); } catch { /* vault unavailable: the env files are still fixed */ }
  const base = [upper(r.to.split('/')[0]), r.account && upper(r.account)].filter(Boolean).join('_');
  const nameOf = (role) => `${base}_${role.toUpperCase()}`;
  for (const f of [...new Set(vars.map((v) => v.file))]) {
    const here = vars.filter((v) => v.file === f);
    const drop = here.filter((v) => (pieces.has(v.name) || v.name !== nameOf(v.role)) && !readByCode(v.name, path.dirname(f)));
    dropLines(f, new Set(drop.map((v) => v.name)));
    const env = cap.parseEnv(fs.readFileSync(f, 'utf8'));
    const lines = Object.entries(fields).filter(([role]) => here.some((v) => v.role === role || pieces.has(v.name)))
      .filter(([role]) => !env.has(nameOf(role))).map(([role, value]) => `${nameOf(role)}=${quoteShell(value)}`);
    if (lines.length) fs.appendFileSync(f, `${fs.readFileSync(f, 'utf8').endsWith('\n') ? '' : '\n'}${lines.join('\n')}\n`, { mode: 0o600 });
    cap.remember(f, Object.fromEntries(Object.keys(fields).map((role) => [nameOf(role), { alias: r.to, role, environment, named: true }])), drop.map((v) => v.name));
    r.names = [...(r.names || []), ...Object.keys(fields).map((role) => nameOf(role))];
  }
}

const quoteShell = (v) => (/^[A-Za-z0-9_\-+/=.:@~%,]+$/.test(v) ? v : `'${v.replace(/'/g, "'\\''")}'`);

// What build() takes from decide(): each value's service and known account.
const asOptions = (named) => ({ services: new Map(named.map((n) => [n.value, n.service])), accounts: new Map(named.map((n) => [n.value, n.account])) });

module.exports = { asOptions, nameOld, cleanProvisional, provisionalId, isProvisional, nameCandidates, decide, rename, renameInEnv, startNaming, runJob };
