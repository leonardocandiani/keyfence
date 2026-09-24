'use strict';
// `keyfence maintain`: keep credentials organized without anyone remembering to.
// Tidies every env file keyfence wrote to, merges obvious duplicates in the
// vault, and lists what needs a person: secrets that went through a chat (rotate
// them) and secrets unused for a long time. `--install` runs it daily through
// launchd, headless.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const vault = require('./vault');
const { tidyFile } = require('./tidy');
const { registered } = require('./capture');

const DAY = 86400e3;
const STALE_DAYS = 90;
const LABEL = 'com.keyfence.maintain';
const ageDays = (iso) => (iso ? (Date.now() - Date.parse(iso)) / DAY : Infinity);

// The same value under a specific account and under service/default: the
// default one is the leftover. Anything else is only reported.
async function mergeDuplicates(apply) {
  const merged = [];
  const unclear = [];
  for (const group of vault.duplicates()) {
    const specific = group.filter((a) => !a.endsWith('/default'));
    const leftovers = group.filter((a) => a.endsWith('/default'));
    if (!specific.length || !leftovers.length) { unclear.push(group.join(' = ')); continue; }
    if (apply) leftovers.forEach((a) => vault.remove(a));
    merged.push({ kept: specific.join(','), removed: leftovers.join(',') });
  }
  return { merged, unclear };
}

// Bring the vault up to date with the env files: a credential missing from the
// vault is added, a value changed in the file becomes a rotation. Runs where the
// vault key is reachable (the daily job), so a capture made where it was not
// (an SSH session, a locked Keychain) catches up on its own.
async function syncVault(apply) {
  const wanted = wantedRecords();
  const synced = [];
  for (const [alias, rec] of wanted) {
    if (rec.conflict) { synced.push({ alias, action: 'conflict: different values in different files, left as is' }); continue; }
    if (!apply) { synced.push({ alias, action: vault.show(alias) ? 'checked' : 'would be added' }); continue; }
    try { synced.push({ alias, action: (await vault.upsert(alias, rec.fields, { environment: rec.environment })).action }); } catch (e) { synced.push({ alias, action: `vault unavailable (${e.message.slice(0, 40)})` }); }
  }
  return synced;
}

// What the registered env files say each credential holds, across all files. The
// same field with different values in two files is a conflict for a person.
function wantedRecords() {
  const { readRegistry, parseEnv } = require('./capture');
  const wanted = new Map();
  for (const [file, map] of Object.entries(readRegistry().names)) {
    if (!fs.existsSync(file)) continue;
    const env = parseEnv(fs.readFileSync(file, 'utf8'));
    for (const [name, m] of Object.entries(map)) {
      if (!env.has(name)) continue;
      if (!wanted.has(m.alias)) wanted.set(m.alias, { fields: {}, environment: m.environment, conflict: false });
      const rec = wanted.get(m.alias);
      if (rec.fields[m.role] !== undefined && rec.fields[m.role] !== env.get(name)) rec.conflict = true;
      rec.fields[m.role] = env.get(name);
    }
  }
  return wanted;
}

const expandHome = (p, home) => p.replace(/^~(?=\/|$)/, home);

async function maintain({ apply = false, roots = null, home = os.homedir() } = {}) {
  const { discover } = require('./discover');
  const cfg = require('./config').load().discover;
  const where = roots || cfg.roots.map((r) => expandHome(r, home)).filter((r) => fs.existsSync(r));
  const found = await discover({ roots: where, depth: cfg.depth, home, apply });
  const tidied = [];
  for (const f of registered().filter((x) => fs.existsSync(x))) tidied.push(await tidyFile(f, { apply }));
  const synced = await syncVault(apply);
  const dup = await mergeDuplicates(apply);
  const list = vault.list();
  return {
    discovered: found.records.filter((r) => r.action === 'new' || r.action === 'added'),
    tidied,
    synced,
    merged: dup.merged,
    unclear: dup.unclear,
    exposed: list.filter((s) => s.status === 'active' && s.exposed).map((s) => s.alias),
    stale: list.filter((s) => s.status === 'active' && ageDays(s.lastUsed || s.created) > STALE_DAYS).map((s) => s.alias),
  };
}

// --- daily schedule (launchd, headless) ------------------------------------------

const plistPath = () => path.join(os.homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
const xml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;');

function install() {
  if (process.platform !== 'darwin') throw new Error('the daily schedule uses launchd (macOS); elsewhere run `keyfence maintain --apply` from cron');
  const log = path.join(os.homedir(), '.config', 'keyfence', 'maintain.log');
  const args = [process.execPath, path.resolve(__dirname, '..', 'bin', 'keyfence.js'), 'maintain', '--apply'];
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key><array>${args.map((a) => `<string>${xml(a)}</string>`).join('')}</array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>30</integer></dict>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string></dict>
  <key>StandardOutPath</key><string>${xml(log)}</string>
  <key>StandardErrorPath</key><string>${xml(log)}</string>
  <key>ProcessType</key><string>Background</string>
</dict></plist>
`;
  fs.mkdirSync(path.dirname(plistPath()), { recursive: true });
  fs.writeFileSync(plistPath(), plist);
  const domain = `gui/${process.getuid()}`;
  try { execFileSync('launchctl', ['bootout', `${domain}/${LABEL}`], { stdio: 'ignore' }); } catch { /* not loaded */ }
  execFileSync('launchctl', ['bootstrap', domain, plistPath()], { stdio: 'ignore' });
  return { plist: plistPath(), log, schedule: 'daily at 09:30' };
}

function uninstall() {
  try { execFileSync('launchctl', ['bootout', `gui/${process.getuid()}/${LABEL}`], { stdio: 'ignore' }); } catch { /* not loaded */ }
  const had = fs.existsSync(plistPath());
  if (had) fs.unlinkSync(plistPath());
  return had;
}

module.exports = { maintain, install, uninstall, LABEL };
