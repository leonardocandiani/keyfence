'use strict';
// `keyfence discover`: credentials already on disk become vault records that
// remember every place they live. Everything runs in a throwaway home.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { positives, r } = require('./gen');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-discover-'));
process.env.KEYFENCE_VAULT_DIR = path.join(home, '.kf', 'vault');
process.env.KEYFENCE_VAULT_KEY_FILE = path.join(home, '.kf', 'key');
process.env.KEYFENCE_LOGS_DIR = path.join(home, '.kf', 'logs');
process.env.KEYFENCE_REGISTRY = path.join(home, '.kf', 'registry.json');
const { discover, isCredential } = require('../src/discover');
const vault = require('../src/vault');

const cases = [];
const check = (name, got, want) => cases.push({ name, got, want, ok: got === want });
const gen = (id) => positives.find((p) => p[0] === id)[1]();
const project = (name, files) => {
  const d = path.join(home, 'code', name);
  fs.mkdirSync(d, { recursive: true });
  execFileSync('git', ['init', '-q'], { cwd: d });
  for (const [f, body] of Object.entries(files)) fs.writeFileSync(path.join(d, f), body);
  return d;
};

(async () => {
  const openai = gen('openai');
  const stripeA = gen('stripe');
  const stripeB = gen('stripe');
  const dbPw = `Db9${r(10)}!`;
  project('crm-api', { '.env': `OPENAI_API_KEY=${openai}\nSTRIPE_SECRET_KEY=${stripeA}\nDB_PASSWORD=${dbPw}\nNEXT_PUBLIC_SITE=https://x.io\nPORT=3000\n`, '.env.example': 'OPENAI_API_KEY=sk-your-key\n' });
  project('site', { '.env.local': `OPENAI_API_KEY=${openai}\nSTRIPE_SECRET_KEY=${stripeB}\n` });
  project('zap', { '.env': `UAZAPI_TOKEN=${r(30)}\nUAZAPI_ADMIN_TOKEN=${r(30)}\n` });
  fs.mkdirSync(path.join(home, 'code', 'crm-api', 'node_modules', 'pkg'), { recursive: true });
  fs.writeFileSync(path.join(home, 'code', 'crm-api', 'node_modules', 'pkg', '.env'), `OPENAI_API_KEY=${gen('openai')}\n`);
  fs.writeFileSync(path.join(home, '.zshrc'), `export PATH=/usr/bin\nexport GITHUB_TOKEN=${gen('github')}\n`);
  fs.mkdirSync(path.join(process.env.KEYFENCE_LOGS_DIR, 'p'), { recursive: true });
  fs.writeFileSync(path.join(process.env.KEYFENCE_LOGS_DIR, 'p', 's.jsonl'), `${JSON.stringify({ type: 'user', message: { role: 'user', content: `usa essa ${stripeA}` } })}\n`);

  const dry = await discover({ roots: [path.join(home, 'code')], home });
  const by = Object.fromEntries(dry.records.map((x) => [x.alias, x]));
  check('the same key in two projects is one record', by['openai/default'] && by['openai/default'].places.length, 2);
  check('two different keys of one service get one record per project', ['stripe/crm', 'stripe/site'].every((a) => by[a]), true);
  check('a generic name belongs to its project: DB_PASSWORD -> crm/default', by['crm/default'] && by['crm/default'].fields.join(','), 'db_password');
  check('shell rc exports are found', Boolean(by['github/default']), true);
  check('two keys of one service in one project are one record with two fields', by['uazapi/default'] && by['uazapi/default'].fields.sort().join(','), 'admin_token,token');
  check('public keys, ports and examples are left out', dry.records.some((x) => x.places.some((p) => /NEXT_PUBLIC|PORT|example/.test(p))), false);
  check('node_modules is not searched', dry.records.some((x) => x.places.some((p) => p.includes('node_modules'))), false);
  check('a key seen in a past session is marked exposed', by['stripe/crm'] && by['stripe/crm'].exposed, true);
  check('the dry run writes nothing', vault.list().length, 0);
  check('no value ever appears in the result', JSON.stringify(dry).includes(openai) || JSON.stringify(dry).includes(dbPw), false);

  await discover({ roots: [path.join(home, 'code')], home, apply: true });
  const rec = vault.show('openai/default');
  check('apply registers the records', vault.list().length, dry.records.length);
  check('a record remembers every place it lives', rec && rec.sources.length, 2);
  check('sources were not changed', fs.readFileSync(path.join(home, 'code', 'site', '.env.local'), 'utf8').includes(openai), true);
  let held = '';
  await vault.use('openai/default', (f) => { held = f.api_key.toString(); });
  check('the vault holds the real value', held, openai);
  check('running again adds nothing', (await discover({ roots: [path.join(home, 'code')], home, apply: true })).records.every((x) => x.action === 'unchanged'), true);
  const other = `Ot9${r(10)}!`;
  project('crm-web', { '.env': `DB_PASSWORD=${other}\n` });
  await discover({ roots: [path.join(home, 'code')], home, apply: true });
  let dbHeld = '';
  await vault.use('crm/default', (f) => { dbHeld = f.db_password.toString(); });
  check('a taken alias is never overwritten by another value', dbHeld, dbPw);
  check('...the new value gets its own record', vault.list().some((x) => x.alias.startsWith('crm/') && x.alias !== 'crm/default'), true);
  check('isCredential ignores a template reference', isCredential('API_KEY', '${OTHER_KEY}'), false);

  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
  console.log(`discover: ${cases.length - failed.length}/${cases.length} ok`);
  process.exit(failed.length ? 1 : 0);
})();
