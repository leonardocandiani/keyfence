'use strict';
// Credential records: which service, whose account, which value is what, and
// the names they get. Values are generated at run time.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { build } = require('../src/credential');
const { scan } = require('../src/detect');
const { positives, r } = require('./gen');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-cred-'));
const repo = (name) => { const d = path.join(tmp, name); fs.mkdirSync(d); execFileSync('git', ['init', '-q'], { cwd: d }); return d; };
const sisRepo = repo('SIS-api');
const callRepo = repo('call');
const gen = (id) => positives.find((p) => p[0] === id)[1]();

const cases = [];
const check = (name, got, want) => cases.push({ name, got, want, ok: got === want });
const recs = (text, cwd, extra = []) => build(text, [...scan(text).findings, ...extra], cwd);
const names = (rec) => rec && Object.entries(rec.envNames).map(([k, v]) => `${k}=${v}`).sort().join(' ');

const weak = `robson${r(4, '0123456789')}`;
const sis = recs(`login=robson.silva@empresa.com.br\nsenha=${weak}\nteste aí com esse também`, sisRepo);
check('SIS: one record, service from the project, account from the login', sis.length === 1 && sis[0].alias, 'sis/robson');
check('SIS: login and password together, named after service and account', names(sis[0]), 'login=SIS_ROBSON_LOGIN password=SIS_ROBSON_PASSWORD');
check('SIS: the login value is the one sent', sis[0] && sis[0].fields.login, 'robson.silva@empresa.com.br');

const pin = `${r(8, '0123456789')}*`;
const wv = build(`login e senha da wavoip pra tu usar\n\nmkt@empresa.com.br\n${pin}`, [{ value: pin, rule: 'classifier', start: 60 }], callRepo);
check('loose lines: service from the words, account from the email', wv[0] && wv[0].alias, 'wavoip/mkt');
check('loose lines: names', names(wv[0]), 'login=WAVOIP_MKT_LOGIN password=WAVOIP_MKT_PASSWORD');

const hex = r(32, '0123456789abcdef');
const url = recs(`testa https://api.placafipe.com.br/v1/placa/ABC1D23?key=${hex}`, sisRepo);
check('key in a link: service from the host', url[0] && url[0].alias, 'placafipe/default');
check('key in a link: named after the host', names(url[0]), 'api_key=PLACAFIPE_API_KEY');

const own = recs(`PAINEL_PASSWORD=Kq9${r(6)}!`, callRepo);
check('a name the user wrote is kept', names(own[0]), 'password=PAINEL_PASSWORD');
check('a name the user wrote also names the service', own[0] && own[0].alias, 'painel/default');
const fipe = recs(`fipe-api-key=${r(32, '0123456789abcdef')}`, sisRepo);
check('fipe-api-key= files under fipe, not under the project', fipe[0] && fipe[0].alias, 'fipe/default');
check('...and keeps its name', names(fipe[0]), 'api_key=FIPE_API_KEY');

const meta = recs(`segue o token da meta: ${gen('meta')}`, sisRepo);
check('a provider token keeps its SDK name', names(meta[0]), 'token=META_ACCESS_TOKEN');

check('"produção" marks the environment', (recs(`senha=Kq9${r(6)}! do sis em produção`, sisRepo)[0] || {}).environment, 'prod');
check('no environment word means dev', sis[0] && sis[0].environment, 'dev');

const two = recs(`senha: Kq9${r(6)}! e o token da fipe é ${gen('github')}`, sisRepo);
check('two credentials of different services stay apart', two.map((x) => x.alias).sort().join(' '), 'github/default sis/default');

const failed = cases.filter((c) => !c.ok);
for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
console.log(`credential: ${cases.length - failed.length}/${cases.length} ok`);
process.exit(failed.length ? 1 : 0);
