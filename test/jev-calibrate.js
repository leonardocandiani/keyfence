'use strict';
// Calibrates the jev threshold on realistic prompts. Needs TYPESAFE_API_KEY.
// Prints each probability and the threshold that separates the two groups.
const { classify } = require('../src/jev');
const { r } = require('./gen');

const pw = () => r(6, 'abcdefghjk') + r(3, '0123456789');
const tok = () => r(26);

const disclose = [
  () => `anota aí, a senha do servidor é ${pw()}`,
  () => `o login do painel é leo e a senha ${pw()}`,
  () => `usa esse token pra testar: ${tok()}`,
  () => `acesso do banco: usuário admin, senha ${pw()}`,
  () => `the password for the staging db is ${pw()}`,
  () => `here's my api key ${tok()} put it in the env`,
  () => `chave de acesso da api: ${tok()}`,
  () => `senha do wifi ${pw()}`,
  () => `pin do cartão corporativo ${r(4, '0123456789')}${r(2, 'ab')}`,
  () => `credencial nova do fornecedor ${tok()}`,
];
const benign = [
  () => 'o deploy da versão v2beta7 falhou no passo de login, vê o log',
  () => 'troca a senha do usuário de teste pelo fluxo de reset, não pelo banco',
  () => 'o token expira em 3600s, revisa a lógica de refresh no auth.ts',
  () => 'cria a tela de login com campo de senha e botão mostrar senha',
  () => 'the api key rotation job failed on node02, check pr 1843',
  () => 'roda os testes do módulo auth2 e me diz se o h264 decoder quebrou',
  () => 'qual a melhor forma de guardar chave de api no keychain do mac?',
  () => 'o commit 3f9a1c2 mexeu no middleware de acesso, reverte',
  () => 'lembra de pedir a senha nova pro Ricardo antes do go-live',
  () => 'confere se o campo token_type vem como Bearer na resposta',
];

(async () => {
  const cfg = { jev: { enabled: true, endpoint: 'https://api.typesafe.ai/v1/systemone', apiKeyEnv: 'TYPESAFE_API_KEY', model: 'jev-latest', timeoutMs: 10000, threshold: 0.5 } };
  const run = async (gens) => {
    const out = [];
    for (const g of gens) {
      const t = Date.now();
      const v = await classify(g(), cfg);
      out.push({ p: v ? v.probability : null, ms: Date.now() - t });
    }
    return out;
  };
  const d = await run(disclose);
  const b = await run(benign);
  const fmt = (a) => a.map((x) => (x.p === null ? 'skip' : x.p.toFixed(2))).join(' ');
  console.log(`disclose: ${fmt(d)}`);
  console.log(`benign:   ${fmt(b)}`);
  const dp = d.map((x) => x.p).filter((x) => x !== null);
  const bp = b.map((x) => x.p).filter((x) => x !== null);
  let best = null;
  for (let t = 0.05; t <= 0.95; t += 0.05) {
    const tp = dp.filter((p) => p >= t).length;
    const fp = bp.filter((p) => p >= t).length;
    const score = tp - 2 * fp; // a false positive costs more: it blocks work
    if (!best || score > best.score) best = { t: +t.toFixed(2), tp, fp, score };
  }
  const ms = [...d, ...b].map((x) => x.ms).sort((x, y) => x - y);
  console.log(`best threshold ${best.t}: catches ${best.tp}/${dp.length} disclosures, ${best.fp}/${bp.length} false positives`);
  console.log(`latency median ${ms[Math.floor(ms.length / 2)]} ms, max ${ms[ms.length - 1]} ms`);
})();
