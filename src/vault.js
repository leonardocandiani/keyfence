'use strict';
// Local credential vault. Values are encrypted at rest with AES-256-GCM; the
// alias, field and version are bound as associated data, so a ciphertext cannot
// be moved to another secret. The master key lives in the macOS Keychain (or, off
// macOS and in tests, in a 0600 key file named by KEYFENCE_VAULT_KEY_FILE).
//
// There is no function here that returns a value to a caller outside keyfence:
// `use()` hands decrypted fields to an operation callback and wipes them after.
// Metadata (alias, environment, fields, policy, dates, status) is readable; values
// are not.

const fs = require('fs');
const os = require('os');
const { makePrivate, renameRetry } = require('./fsmode');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const { validatePolicy } = require('./policy');

const SERVICE = 'keyfence-vault';
const ALIAS = /^[a-z0-9][a-z0-9_-]*(?:\/[a-z0-9][a-z0-9_-]*){1,5}$/;
const ENVIRONMENTS = ['dev', 'test', 'prod'];

const vaultDir = () => process.env.KEYFENCE_VAULT_DIR || path.join(os.homedir(), '.config', 'keyfence', 'vault');
const vaultFile = () => path.join(vaultDir(), 'vault.json');
const fingerprintFile = () => path.join(vaultDir(), 'fingerprints.json');

// --- master key ---------------------------------------------------------------

function keychainKey(create) {
  try {
    const hex = execFileSync('security', ['find-generic-password', '-s', SERVICE, '-a', os.userInfo().username, '-w'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  } catch { /* not there yet */ }
  if (!create) return null;
  const key = crypto.randomBytes(32);
  // The value goes through stdin (`security -i`), never through argv.
  execFileSync('security', ['-i'], { input: `add-generic-password -U -s ${SERVICE} -a ${os.userInfo().username} -w ${key.toString('hex')}\n`, stdio: ['pipe', 'ignore', 'ignore'] });
  return key;
}

function fileKey(file, create) {
  try {
    const hex = fs.readFileSync(file, 'utf8').trim();
    if (/^[0-9a-f]{64}$/.test(hex)) return Buffer.from(hex, 'hex');
  } catch { /* not there yet */ }
  if (!create) return null;
  const key = crypto.randomBytes(32);
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, key.toString('hex'), { mode: 0o600 });
  makePrivate(file);
  return key;
}

function masterKey(create = false) {
  const file = process.env.KEYFENCE_VAULT_KEY_FILE;
  if (file) return fileKey(file, create);
  if (process.platform === 'darwin') return keychainKey(create);
  throw new Error('no key store: set KEYFENCE_VAULT_KEY_FILE to a 0600 file outside the repo');
}

// --- storage ---------------------------------------------------------------------

function load() {
  try {
    const v = JSON.parse(fs.readFileSync(vaultFile(), 'utf8'));
    if (v && v.format === 1) return v;
  } catch { /* empty vault */ }
  return { format: 1, salt: crypto.randomBytes(16).toString('hex'), secrets: {} };
}

function save(v) {
  fs.mkdirSync(vaultDir(), { recursive: true, mode: 0o700 });
  makePrivate(vaultDir(), { dir: true });
  const tmp = `${vaultFile()}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(v, null, 2), { mode: 0o600 });
  renameRetry(tmp, vaultFile());
  publishFingerprints(v);
}

const aad = (alias, field, version) => Buffer.from(`keyfence:${alias}:${field}:${version}`);

function seal(key, alias, field, version, value) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aad(alias, field, version));
  const ct = Buffer.concat([c.update(value), c.final()]);
  return { iv: iv.toString('base64'), tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64') };
}

function open(key, alias, field, version, box) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64'));
  d.setAAD(aad(alias, field, version));
  d.setAuthTag(Buffer.from(box.tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(box.ct, 'base64')), d.final()]);
}

// The hook marks vault values in every session without ever decrypting them:
// it compares salted SHA-256 prefixes of what it sees against this list.
// Revoked secrets stay listed: revoking in keyfence does not revoke at the
// provider, so the value is still worth protecting.
const fingerprint = (salt, value) => crypto.createHash('sha256').update(salt).update(value).digest('hex').slice(0, 32);

function publishFingerprints(v) {
  const list = [];
  for (const [alias, s] of Object.entries(v.secrets)) {
    // The previous version too: a rotated-out key often stays valid for a while.
    for (const set of [s.fingerprints, s.previous && s.previous.fingerprints]) {
      for (const [field, fp] of Object.entries(set || {})) list.push({ fp, alias, field });
    }
  }
  const tmp = `${fingerprintFile()}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ salt: v.salt, list }), { mode: 0o600 });
  renameRetry(tmp, fingerprintFile());
}

// --- lifecycle -----------------------------------------------------------------------

function checkAlias(alias) {
  if (!ALIAS.test(alias)) throw new Error(`invalid alias "${alias}": use lowercase segments separated by /, like wavoip/test-device/sip`);
}

function sealFields(key, v, alias, version, fields) {
  const boxes = {};
  const fps = {};
  for (const [name, value] of Object.entries(fields)) {
    const buf = Buffer.isBuffer(value) ? value : Buffer.from(String(value));
    if (!buf.length) throw new Error(`field "${name}" is empty`);
    boxes[name] = seal(key, alias, name, version, buf);
    fps[name] = fingerprint(v.salt, buf);
    buf.fill(0);
  }
  return { boxes, fps };
}

/** Add a secret. `fields` is {name: Buffer|string}; values are wiped after sealing. */
function add(alias, fields, meta = {}) {
  checkAlias(alias);
  const env = meta.environment || 'dev';
  if (!ENVIRONMENTS.includes(env)) throw new Error(`environment must be one of ${ENVIRONMENTS.join(', ')}`);
  const policy = validatePolicy(meta.policy || {}, Object.keys(fields));
  const v = load();
  if (v.secrets[alias]) throw new Error(`${alias} already exists: use rotate to change its value`);
  const key = masterKey(true);
  const { boxes, fps } = sealFields(key, v, alias, 1, fields);
  const now = new Date().toISOString();
  v.secrets[alias] = { environment: env, status: 'active', version: 1, fields: boxes, fingerprints: fps, previous: null,
    exposed: Boolean(meta.exposed), policy, created: now, rotated: null, lastUsed: null, sources: [...new Set(meta.sources || [])] };
  save(v);
  return describe(alias, v.secrets[alias]);
}

/** New version for the same fields; the previous version is kept until purged. */
function rotate(alias, fields, { exposed = false } = {}) {
  const v = load();
  const s = v.secrets[alias];
  if (!s) throw new Error(`no secret ${alias}`);
  const missing = Object.keys(s.fields).filter((f) => !(f in fields));
  if (missing.length) throw new Error(`rotate needs every field: missing ${missing.join(', ')}`);
  const key = masterKey(false);
  if (!key) throw new Error('vault key not found');
  const version = s.version + 1;
  const { boxes, fps } = sealFields(key, v, alias, version, fields);
  s.previous = { version: s.version, fields: s.fields, fingerprints: s.fingerprints };
  Object.assign(s, { version, fields: boxes, fingerprints: fps, status: 'active', exposed, rotated: new Date().toISOString() });
  save(v);
  return describe(alias, s);
}

/**
 * Keep a credential current without a person in the loop (capture). New alias:
 * add. Same values: nothing. Different values: rotate, merging the fields
 * already stored with the new ones, so a new password keeps the saved login.
 */
async function upsert(alias, fields, meta = {}) {
  const v = load();
  const s = v.secrets[alias];
  if (!s) return { action: 'added', ...add(alias, fields, meta) };
  const same = Object.entries(fields).every(([k, val]) => s.fingerprints[k] === fingerprint(v.salt, Buffer.from(String(val))));
  if (same) return { action: noteSources(alias, meta) ? 'sources updated' : 'unchanged', ...describe(alias, load().secrets[alias]) };
  const merged = s.status === 'active' ? await use(alias, (plain) => Object.fromEntries(Object.entries(plain).map(([k, b]) => [k, Buffer.from(b)]))) : {};
  for (const [k, val] of Object.entries(fields)) merged[k] = Buffer.from(String(val));
  if (Object.keys(s.fields).some((k) => !(k in merged))) {
    remove(alias);
    return { action: 'replaced', ...add(alias, merged, { ...meta, policy: s.policy }) };
  }
  rotate(alias, merged, { exposed: Boolean(meta.exposed) });
  noteSources(alias, meta);
  return { action: 'rotated', ...describe(alias, load().secrets[alias]) };
}

// Where a credential lives (env files, rc files): metadata, merged, never values.
// Also records an exposure found later. Returns true when something changed.
function noteSources(alias, meta) {
  const v = load();
  const s = v.secrets[alias];
  const add = (meta.sources || []).filter((x) => !(s.sources || []).includes(x));
  const expose = Boolean(meta.exposed) && !s.exposed;
  if (!add.length && !expose) return false;
  s.sources = [...(s.sources || []), ...add];
  if (expose) s.exposed = true;
  save(v);
  return true;
}

function setStatus(alias, status) {
  const v = load();
  if (!v.secrets[alias]) throw new Error(`no secret ${alias}`);
  v.secrets[alias].status = status;
  save(v);
  return describe(alias, v.secrets[alias]);
}

const revoke = (alias) => setStatus(alias, 'revoked');
const reactivate = (alias) => setStatus(alias, 'active');

function remove(alias) {
  const v = load();
  if (!v.secrets[alias]) return false;
  delete v.secrets[alias];
  save(v);
  return true;
}

function setPolicy(alias, policy) {
  const v = load();
  const s = v.secrets[alias];
  if (!s) throw new Error(`no secret ${alias}`);
  s.policy = validatePolicy(policy, Object.keys(s.fields));
  save(v);
  return describe(alias, s);
}

/**
 * Give a credential its real name: move its fields to other aliases, each field
 * under a (possibly new) field name, then drop the old alias. `targets` is
 * {alias: {oldField: newField}}; one credential can split in two when a message
 * carried credentials of two services. A target that already exists is merged
 * like a capture (upsert). Values are decrypted and sealed again here, under
 * the new alias; none leaves this module.
 */
async function move(from, targets) {
  const s = load().secrets[from];
  if (!s) throw new Error(`no secret ${from}`);
  Object.keys(targets).forEach(checkAlias);
  const plain = await use(from, (p) => Object.fromEntries(Object.entries(p).map(([k, b]) => [k, Buffer.from(b)])));
  const meta = { environment: s.environment, exposed: s.exposed, policy: s.policy, sources: s.sources };
  const out = [];
  try {
    for (const [alias, fields] of Object.entries(targets)) {
      const picked = Object.fromEntries(Object.entries(fields).filter(([f]) => plain[f]).map(([f, to]) => [to, Buffer.from(plain[f])]));
      if (Object.keys(picked).length) out.push({ alias, action: (await upsert(alias, picked, meta)).action });
    }
  } finally {
    for (const b of Object.values(plain)) b.fill(0);
  }
  if (!Object.keys(targets).includes(from)) remove(from);
  return out;
}

// --- reading: metadata only ----------------------------------------------------------

function describe(alias, s) {
  return { alias, environment: s.environment, status: s.status, version: s.version, fields: Object.keys(s.fields),
    exposed: s.exposed, policy: s.policy, created: s.created, rotated: s.rotated, lastUsed: s.lastUsed, sources: s.sources || [] };
}

function list(prefix = '') {
  return Object.entries(load().secrets).filter(([a]) => a.startsWith(prefix)).map(([a, s]) => describe(a, s))
    .sort((x, y) => x.alias.localeCompare(y.alias));
}

function show(alias) {
  const s = load().secrets[alias];
  return s ? describe(alias, s) : null;
}

// --- use: the only path to a value, for keyfence's own operations ------------------------

/**
 * Decrypt the fields of an active secret, hand them to `op` and wipe them after.
 * Policy is checked by the caller (the broker) before this runs.
 */
async function use(alias, op) {
  const v = load();
  const s = v.secrets[alias];
  if (!s) throw new Error(`no secret ${alias}`);
  if (s.status !== 'active') throw new Error(`${alias} is ${s.status}`);
  const key = masterKey(false);
  if (!key) throw new Error('vault key not found');
  const plain = {};
  try {
    for (const [name, box] of Object.entries(s.fields)) plain[name] = open(key, alias, name, s.version, box);
    return await op(plain);
  } finally {
    for (const b of Object.values(plain)) b.fill(0);
    key.fill(0);
    s.lastUsed = new Date().toISOString();
    save(v);
  }
}

// Groups of aliases that hold the same value (current versions only).
function duplicates() {
  const byPrint = new Map();
  for (const [alias, s] of Object.entries(load().secrets)) {
    for (const fp of Object.values(s.fingerprints || {})) {
      if (!byPrint.has(fp)) byPrint.set(fp, new Set());
      byPrint.get(fp).add(alias);
    }
  }
  const seen = new Set();
  return [...byPrint.values()].filter((g) => g.size > 1).map((g) => [...g].sort())
    .filter((g) => { const k = g.join(','); if (seen.has(k)) return false; seen.add(k); return true; });
}

function fingerprints() {
  try {
    return JSON.parse(fs.readFileSync(fingerprintFile(), 'utf8'));
  } catch {
    return { salt: '', list: [] };
  }
}

module.exports = { add, upsert, move, rotate, duplicates, revoke, reactivate, remove, setPolicy, list, show, use, fingerprints, fingerprint, vaultDir, ALIAS, ENVIRONMENTS };
