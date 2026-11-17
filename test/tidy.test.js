'use strict';
// `keyfence tidy` and `keyfence maintain`, with fake session logs, vault and
// registry: old generic names get real ones from the message they came from.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-tidy-'));
process.env.KEYFENCE_VAULT_DIR = path.join(tmp, 'vault');
process.env.KEYFENCE_VAULT_KEY_FILE = path.join(tmp, 'vault-key');
process.env.KEYFENCE_LOGS_DIR = path.join(tmp, 'logs');
process.env.KEYFENCE_REGISTRY = path.join(tmp, 'registry.json');
const { tidyFile } = require('../src/tidy');
const { maintain } = require('../src/maintain');
const { remember } = require('../src/capture');
const vault = require('../src/vault');

const cases = [];
const check = (name, got, want) => cases.push({ name, got, want, ok: got === want });
// Distinct digits: a run like `Zq7x00000` falls under the entropy floor of the code-mode scan that
// tidy uses to rebuild the record, and the rename is (correctly) skipped. 0.28% of random values per use.
const digits = (n) => [...'0123456789'].sort(() => Math.random() - 0.5).slice(0, n).join('');
const repo = (name) => { const d = path.join(tmp, name); fs.mkdirSync(d); execFileSync('git', ['init', '-q'], { cwd: d }); return d; };
function log(cwd, text) {
  const dir = path.join(process.env.KEYFENCE_LOGS_DIR, 'p');
  fs.mkdirSync(dir, { recursive: true });
  fs.appendFileSync(path.join(dir, 's.jsonl'), `${JSON.stringify({ type: 'user', cwd, message: { role: 'user', content: text }, timestamp: new Date().toISOString() })}\n`);
}

(async () => {
  const sis = repo('SIS-api');
  const pw = `robson${digits(4)}`;
  log(sis, `login=robson.silva@empresa.com.br\nsenha=${pw}\nteste aí com esse também`);
  log(sis, 'a palavra aqui é só uma palavra');
  const envFile = path.join(sis, '.env');
  fs.writeFileSync(envFile, `APP_URL=https://x.io\nPASSWORD=${pw}\nPASSWORD_2=palavraqualquer\n`);

  const dry = await tidyFile(envFile);
  check('dry run plans the rename', dry.changes.map((c) => `${c.old}->${c.alias}`).join(','), 'PASSWORD->sis/robson');
  check('dry run touches nothing', fs.readFileSync(envFile, 'utf8').includes('PASSWORD='), true);
  check('an old false capture is left alone', dry.unmatched.join(','), 'PASSWORD_2');

  const done = await tidyFile(envFile, { apply: true });
  const after = fs.readFileSync(envFile, 'utf8');
  check('the password gets its real name', after.includes(`SIS_ROBSON_PASSWORD=${pw}`), true);
  check('the login lost at capture time is recovered', after.includes('SIS_ROBSON_LOGIN=robson.silva@empresa.com.br'), true);
  check('the generic name is gone', /^PASSWORD=/m.test(after), false);
  check('other lines are untouched', after.includes('APP_URL=https://x.io') && after.includes('PASSWORD_2=palavraqualquer'), true);
  check('a private backup is kept (0600, or owner-only ACL on Windows)', Boolean(done.backup) && require('../src/fsmode').isPrivate(done.backup), true);
  check('the record is in the vault', (vault.show('sis/robson') || { fields: [] }).fields.sort().join(','), 'login,password');
  check('running again changes nothing', (await tidyFile(envFile, { apply: true })).changes.length, 0);

  // code that reads the old name keeps it
  const used = repo('painel-api');
  const pw2 = `Kq9z${digits(5)}`;
  log(used, `login=leo@painel.com senha=${pw2}`);
  fs.writeFileSync(path.join(used, 'app.js'), 'const pw = process.env.PASSWORD;\n');
  execFileSync('git', ['add', 'app.js'], { cwd: used });
  const usedEnv = path.join(used, '.env');
  fs.writeFileSync(usedEnv, `PASSWORD=${pw2}\n`);
  await tidyFile(usedEnv, { apply: true });
  const usedAfter = fs.readFileSync(usedEnv, 'utf8');
  check('a name the code reads is kept', /^PASSWORD=/m.test(usedAfter), true);
  check('...and the good names are added next to it', usedAfter.includes(`PAINEL_LEO_PASSWORD=${pw2}`), true);

  // the word in a doc is not a reader
  const doc = repo('docs-only-api');
  const pw3 = `Zq7x${digits(5)}`;
  log(doc, `login=ana@docs.com senha=${pw3}`);
  fs.mkdirSync(path.join(doc, 'docs'));
  fs.writeFileSync(path.join(doc, 'docs', 'setup.md'), 'Set PASSWORD in your environment.\n');
  fs.writeFileSync(path.join(doc, 'notes.js'), "const label = 'PASSWORD'; // a string, not an env read\n");
  execFileSync('git', ['add', '.'], { cwd: doc });
  const docEnv = path.join(doc, '.env');
  fs.writeFileSync(docEnv, `PASSWORD=${pw3}\n`);
  await tidyFile(docEnv, { apply: true });
  check('a mention in docs or a string does not keep the old name', /^PASSWORD=/m.test(fs.readFileSync(docEnv, 'utf8')), false);

  // maintain: registered files, duplicates, rotation list
  remember(envFile);
  vault.add('sis/default', { password: Buffer.from(pw) });
  const m = await maintain({ apply: true, roots: [tmp], home: tmp });
  check('maintain merges service/default into the specific record', m.merged.map((x) => `${x.kept}<-${x.removed}`).join(','), 'sis/robson<-sis/default');
  check('the leftover is gone from the vault', vault.show('sis/default'), null);
  check('what went through a chat is listed for rotation', m.exposed.includes('sis/robson'), true);

  // the vault catches up with the env files on its own
  vault.remove('sis/robson');
  const caught = await maintain({ apply: true, roots: [tmp], home: tmp });
  check('maintain re-adds a record missing from the vault', caught.synced.some((x) => x.alias === 'sis/robson' && x.action === 'added'), true);
  check('...with the login and the password', (vault.show('sis/robson') || { fields: [] }).fields.sort().join(','), 'login,password');
  check('a second run finds everything in step', (await maintain({ apply: true, roots: [tmp], home: tmp })).synced.every((x) => x.action === 'unchanged'), true);

  // a registered file the disk will not give back (an iCloud file evicted from the Mac answers EDEADLK, `-11`, to a
  // background job; a directory stands in for it here) is left out and listed, and the run goes on for the others
  const evicted = path.join(repo('icloud'), '.env');
  fs.writeFileSync(evicted, `API_KEY=${digits(9)}abcdefgh\n`);
  remember(evicted, { API_KEY: { alias: 'icloud/default', role: 'password' } });
  fs.rmSync(evicted);
  fs.mkdirSync(evicted);
  let part = null;
  try { part = await maintain({ apply: true, roots: [tmp], home: tmp }); } catch (e) { check('maintain goes on past a registered file it cannot read', e.message, 'no error'); }
  check('maintain goes on past a registered file it cannot read', part ? 'ran' : 'stopped', 'ran');
  check('...and lists the file it left out', part ? part.unreadable.map((u) => u.file).join(',') : 'none', evicted);
  check('...while the rest is still in step', part ? part.synced.every((x) => x.action === 'unchanged') : false, true);

  // a failed maintenance tells whoever the config names, with the error in the message
  const aviso = path.join(tmp, 'aviso.txt');
  const cfgFile = path.join(tmp, 'config-aviso.json');
  fs.writeFileSync(cfgFile, JSON.stringify({ maintain: { onFailure: [process.execPath, '-e', 'require("fs").writeFileSync(process.argv[1], process.argv[2])', aviso, 'keyfence maintain failed: {error}'] } }));
  const { notifyFailure } = require('../src/maintain');
  check('no onFailure in the config: nothing runs', notifyFailure(new Error('boom')), false);
  process.env.KEYFENCE_CONFIG = cfgFile;
  check('onFailure runs the command', notifyFailure(new Error('boom: read failed')), true);
  check('...with the error in the message', fs.existsSync(aviso) ? fs.readFileSync(aviso, 'utf8') : 'not written', 'keyfence maintain failed: boom: read failed');
  fs.writeFileSync(cfgFile, JSON.stringify({ maintain: { onFailure: ['/nonexistent/aviso-command'] } }));
  check('a notice command that fails does not hide the original error', notifyFailure(new Error('boom')), false);
  delete process.env.KEYFENCE_CONFIG;

  // a value printed by a `!` command is not a typed message, and never the whole secret
  const { messagesWith } = require('../src/tidy');
  const chave = Array.from({ length: 32 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
  log(tmp, `<bash-stdout>PAINEL_ADMIN_CHAVE=${chave}</bash-stdout><bash-stderr></bash-stderr>`);
  check('command output is not the message a value came from', messagesWith([chave], '', { pieces: true }).has(chave), false);
  log(tmp, `<bash-input>grep -c PAINEL ~/.env</bash-input>`);
  log(tmp, `a chave do painel admin é ${chave}`);
  const typed = messagesWith([chave], '', { pieces: true }).get(chave);
  check('the same value typed by the user is found', Boolean(typed), true);
  check('...as itself, not inside the command output', typed ? typed.whole === undefined : 'none', true);

  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
  console.log(`tidy: ${cases.length - failed.length}/${cases.length} ok`);
  process.exit(failed.length ? 1 : 0);
})();
