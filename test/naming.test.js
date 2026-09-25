'use strict';
// Naming without the network: the structural fallback, what may be sent to the
// classifier, splitting a provisional record, and renaming credentials an older
// version named from a loose word. The classifier's own choices are measured
// live in test/naming-eval.js. Values are generated at run time.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { r } = require('./gen');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-naming-'));
process.env.KEYFENCE_VAULT_DIR = path.join(tmp, 'vault');
process.env['KEYFENCE_VAULT_' + 'KEY_FILE'] = path.join(tmp, 'vault-key');
process.env.KEYFENCE_REGISTRY = path.join(tmp, 'registry.json');
process.env.KEYFENCE_LOGS_DIR = path.join(tmp, 'logs');
process.env.KEYFENCE_CONFIG = path.join(tmp, 'config.json');
fs.writeFileSync(process.env.KEYFENCE_CONFIG, JSON.stringify({ jev: { enabled: false } }));

const naming = require('../src/naming');
const vault = require('../src/vault');
const cap = require('../src/capture');
const cfg = require('../src/config').load();

const cases = [];
const check = (name, got, want) => cases.push({ name, got: String(got), want: String(want), ok: String(got) === String(want) });
const repo = (name) => { const d = path.join(tmp, name); fs.mkdirSync(d); execFileSync('git', ['init', '-q'], { cwd: d }); fs.writeFileSync(path.join(d, '.gitignore'), '.env\n'); return d; };
const pw = () => `${r(4)}#${r(3, '0123456789')}]${r(4)}`;
const envNames = (f) => fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => l.split('=')[0]).join(' ');

(async () => {
  const painel = repo('painel-api');

  // --- without the classifier: structure, never a loose word ----------------------
  const t1 = `token aqui: ${pw()}`;
  const [n1] = await naming.decide(t1, [t1.split(': ')[1]], [], cfg, painel);
  check('no classifier: a message naming nothing gets the project, not "aqui"', n1.service, 'painel');
  const v2 = pw();
  const [n2] = await naming.decide(`acesso aqui: lojaexemplo.com.br/cpanel senha ${v2}`, [v2], [], cfg, painel);
  check('no classifier: a domain in the message wins over the project', n2.service, 'lojaexemplo');
  const v3 = pw();
  const [n3] = await naming.decide(`o README.md fala da senha ${v3}`, [v3], [], cfg, painel);
  check('no classifier: a file name is not a domain', n3.service, 'painel');

  // --- what may leave the machine ---------------------------------------------------
  const secret = `robson${r(5, '0123456789')}`;
  const words = naming.nameCandidates(`nova senha do robson no sis: ${secret} pedido PED${r(6, '0123456789')}`, [secret]);
  check('candidates: never a piece of a secret', words.some((w) => secret.includes(w) || w.includes(secret)), false);
  check('candidates: never a word with a digit (ids, order numbers)', words.some((w) => /\d/.test(w)), false);
  check('candidates: the service word is one of them', words.includes('sis'), true);

  // --- a provisional record split between two services -----------------------------
  const app = repo('app');
  const envFile = path.join(app, '.env');
  const [pwA, tokB] = [pw(), `EAA${r(30)}`];
  fs.writeFileSync(envFile, `KEEP_ME=1\nKF_AB12_PASSWORD='${pwA}'\nKF_AB12_LOGIN=joao\nKF_AB12_TOKEN=${tokB}\n`);
  vault.add('kf/ab12', { password: pwA, login: 'joao', token: tokB });
  const rec = { alias: 'kf/ab12', file: envFile, environment: 'dev', account: 'joao', fields: { password: pwA, login: 'joao', token: tokB },
    names: { password: 'KF_AB12_PASSWORD', login: 'KF_AB12_LOGIN', token: 'KF_AB12_TOKEN' } };
  await naming.rename('s-split', rec, [{ value: pwA, service: 'cpanel', account: '' }, { value: tokB, service: 'meta', account: '' }], app, 3600e3);
  check('split: each secret goes to its own service, login follows the password', vault.list().map((x) => `${x.alias}[${x.fields.slice().sort()}]`).join(' '), 'cpanel/joao[login,password] meta/default[token]');
  check('split: new names added, provisional ones kept for commands already running', envNames(envFile), 'KEEP_ME KF_AB12_PASSWORD CPANEL_JOAO_PASSWORD KF_AB12_LOGIN CPANEL_JOAO_LOGIN KF_AB12_TOKEN META_TOKEN');
  cap.remember(envFile);
  check('maintain: plan lists the provisional lines', naming.cleanProvisional().map((x) => x.names.join(' ')).join(' '), 'KF_AB12_PASSWORD KF_AB12_LOGIN KF_AB12_TOKEN');
  naming.cleanProvisional({ apply: true });
  check('maintain: provisional lines removed, the rest untouched', envNames(envFile), 'KEEP_ME CPANEL_JOAO_PASSWORD CPANEL_JOAO_LOGIN META_TOKEN');
  check('split: the value comes back exactly', cap.parseEnv(fs.readFileSync(envFile, 'utf8')).get('CPANEL_JOAO_PASSWORD') === pwA, true);

  // --- credentials an older version named from a loose word -----------------------
  const sis = repo('sis-api');
  const sisEnv = path.join(sis, '.env');
  const [old1, old2] = [pw(), pw()];
  const old3 = pw();
  fs.writeFileSync(sisEnv, `AQUI_ADM_PASSWORD='${old1}'\nAQUI_ADM_LOGIN=adm\nPAINEL_PASSWORD='${old2}'\nDB_PASS='${old3}'\n`);
  cap.remember(sisEnv, {
    AQUI_ADM_PASSWORD: { alias: 'aqui/adm', role: 'password', environment: 'dev' },
    AQUI_ADM_LOGIN: { alias: 'aqui/adm', role: 'login', environment: 'dev' },
    PAINEL_PASSWORD: { alias: 'painel/default', role: 'password', environment: 'dev' },
    DB_PASS: { alias: 'sis/default', role: 'password', environment: 'dev' }, // the project's own name, registered by discover
  });
  vault.add('aqui/adm', { password: old1, login: 'adm' });
  const logDir = path.join(process.env.KEYFENCE_LOGS_DIR, 'p');
  fs.mkdirSync(logDir, { recursive: true });
  const log = (text) => fs.appendFileSync(path.join(logDir, 's.jsonl'), `${JSON.stringify({ type: 'user', cwd: sis, message: { role: 'user', content: text } })}\n`);
  log(`com o acesso aqui, usando o keyfence:\n\n### Painel - sisfrota.com.br\n\nUsuário: adm\nSenha: ${old1}`);
  log(`PAINEL_PASSWORD=${old2}`);
  log(`a senha do banco é ${old3}`);
  const plan = await naming.nameOld({ apply: false, cfg });
  check('old names: plan renames the loose word to the context', plan.filter((x) => x.to).map((x) => `${x.alias}->${x.to}`).join(' '), 'aqui/adm->sisfrota/adm');
  check('old names: a name the user wrote stays', (plan.find((x) => x.alias === 'painel/default') || {}).action, 'kept: named by the user or the provider');
  await naming.nameOld({ apply: true, cfg });
  check('old names: env file renamed, the project\'s own DB_PASS untouched', envNames(sisEnv), 'SISFROTA_ADM_PASSWORD SISFROTA_ADM_LOGIN PAINEL_PASSWORD DB_PASS');
  check('old names: vault moved', vault.list().map((x) => x.alias).filter((a) => /adm/.test(a)).join(' '), 'sisfrota/adm');
  check('old names: value intact', cap.parseEnv(fs.readFileSync(sisEnv, 'utf8')).get('SISFROTA_ADM_PASSWORD') === old1, true);
  check('old names: asked once, nothing left to look at next time', (await naming.nameOld({ apply: false, cfg })).length, 0);

  fs.rmSync(tmp, { recursive: true, force: true });
  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
  console.log(`naming: ${cases.length - failed.length}/${cases.length} ok`);
  process.exitCode = failed.length ? 1 : 0;
})();
