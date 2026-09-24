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
const digits = (n) => Array.from({ length: n }, () => Math.floor(Math.random() * 10)).join('');
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
  check('a 0600 backup is kept', Boolean(done.backup) && (fs.statSync(done.backup).mode & 0o777).toString(8), '600');
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

  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
  console.log(`tidy: ${cases.length - failed.length}/${cases.length} ok`);
  process.exit(failed.length ? 1 : 0);
})();
