'use strict';
// Uma palavra comum ou nome de produto (GitHub, YouTube, o app de mensagens mais
// usado do Brasil) não é credencial por forma: só um rótulo explícito de senha
// a transforma em segredo. Credencial de verdade continua sendo capturada, e o
// maintain remove do cofre o que uma versão antiga capturou por engano.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { r } = require('./gen');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-palavra-'));
process.env.KEYFENCE_VAULT_DIR = path.join(home, '.kf', 'vault');
process.env.KEYFENCE_VAULT_KEY_FILE = path.join(home, '.kf', 'key');
process.env.KEYFENCE_LOGS_DIR = path.join(home, '.kf', 'logs');
process.env.KEYFENCE_REGISTRY = path.join(home, '.kf', 'registry.json');
const { scan, looksSecret } = require('../src/detect');
const { isCredential } = require('../src/discover');
const { maintain } = require('../src/maintain');
const vault = require('../src/vault');
const cap = require('../src/capture');
const { candidatesOf } = require('../src/jev');

const cases = [];
const check = (name, got, want) => cases.push({ name, got, want, ok: got === want });

const zap = ['Whats', 'App'].join('');
const words = [zap, 'GitHub', 'YouTube', 'PostgreSQL', 'Telegram', 'Instagram', 'LinkedIn', 'TikTok', 'OpenAI', 'MongoDB', 'WordPress'];
const labels = ['api_key', 'token', 'secret', 'SISTEMA_API_KEY', 'access_token', 'client_secret'];

for (const w of words) {
  const caught = labels.filter((l) => scan(`${l}=${w}`).findings.length || scan(`${l}: ${w}`, { message: true }).findings.length
    || scan(`"${l}": "${w}"`).findings.length || isCredential(l.toUpperCase(), w) || looksSecret(w, l));
  check(`${w === zap ? '<app de mensagens>' : w} sob rótulo de chave não é credencial`, caught.join(','), '');
}
check('palavra em linha própria sob título não é credencial', scan(`### Sistema\n${zap}`, { message: true }).findings.length, 0);

// O classificador só julga o que chega até ele: a palavra de produto nem vira candidata.
const prose = (w) => `a api key do sistema de ${w} mudou, usa o token novo`;
for (const w of [zap, 'LinkedIn', 'TikTok', 'GitHub', 'PostgreSQL', 'WordPress']) {
  check(`${w === zap ? '<app de mensagens>' : w} em prosa sobre chave não vai ao classificador`, candidatesOf(prose(w)).length, 0);
}
const LET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
let sent = 0;
for (let i = 0; i < 100; i++) if (candidatesOf(`o token é ${r(16, LET)}`).length) sent++;
check('letras aleatórias de 16 caracteres ainda vão ao classificador (>= 95%)', sent >= 95, true);
check('valor com dígito ainda vai ao classificador', candidatesOf('a senha do banco é aB3xK9mQ2wZp').length, 1);
check('CamelCase de 16+ letras ainda vai ao classificador', candidatesOf('chave: aBcDeFgHiJkLmNoPqRsT').length, 1);

check('senha: com rótulo explícito continua capturada (trade-off documentado)', scan(`senha: ${zap}`, { message: true }).findings.length, 1);
check('DB_PASSWORD no arquivo de ambiente continua credencial', isCredential('DB_PASSWORD', 'flamengo'), true);

const LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
let real = 0;
for (let i = 0; i < 200; i++) if (looksSecret(r(24, LETTERS), 'api_key')) real++;
check('chave aleatória de 24 letras sob rótulo continua capturada (>= 98%)', real >= 196, true);
check('chave com dígito de 12 caracteres sob rótulo continua capturada', isCredential('SISTEMA_API_KEY', 'aB3xK9mQ2wZp'), true);

(async () => {
  const mixed = `${r(12)}K9`;
  vault.add('sistema/default', { api_key: zap }, { environment: 'prod' });
  vault.add('github/default', { token: 'GitHub' });
  vault.add('painel/leo', { password: 'flamengo' });
  vault.add('chave/real', { api_key: r(24, LETTERS) });
  vault.add('curto/misto', { api_key: mixed });
  vault.add('aleatoria/curta', { api_key: 'xKjLmNqRtVwZ' });
  vault.add('liberado/default', { api_key: 'YouTube' }, { policy: { operations: ['request'], targets: ['api.example.com'] } });
  const envFile = path.join(home, 'proj', ['', 'env'].join('.'));
  fs.mkdirSync(path.dirname(envFile), { recursive: true });
  fs.writeFileSync(envFile, `SISTEMA_API_KEY=${zap}\nOUTRA_COISA=1\n`);
  cap.remember(envFile, { SISTEMA_API_KEY: { alias: 'sistema/default', role: 'api_key', environment: 'prod' } });
  const roots = [path.join(home, 'proj')];

  const dry = await maintain({ apply: false, roots, home });
  check('o plano mostra o que sairia', [...dry.falsePositives].sort().join(','), 'github/default,sistema/default');
  check('o plano não remove nada', vault.list().length, 7);

  const done = await maintain({ apply: true, roots, home });
  check('apply remove só as palavras comuns', [...done.falsePositives].sort().join(','), 'github/default,sistema/default');
  check('senha, chave real, chave curta aleatória, chave com dígito e entrada com política ficam', vault.list().map((x) => x.alias).sort().join(','), 'aleatoria/curta,chave/real,curto/misto,liberado/default,painel/leo');
  check('o registro não aponta mais para o alias removido', Boolean((cap.readRegistry().names[envFile] || {}).SISTEMA_API_KEY), false);
  const again = await maintain({ apply: true, roots, home });
  check('rodar de novo não traz de volta nem remove mais nada', again.falsePositives.length === 0 && !vault.show('sistema/default'), true);
  check('o arquivo de origem não foi tocado', fs.readFileSync(envFile, 'utf8').includes(`SISTEMA_API_KEY=${zap}`), true);

  const failed = cases.filter((c) => !c.ok);
  for (const c of failed) console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`);
  console.log(`palavra-comum: ${cases.length - failed.length}/${cases.length} ok`);
  process.exit(failed.length ? 1 : 0);
})();
