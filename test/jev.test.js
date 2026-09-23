'use strict';
// The classifier's privacy contract: no candidate value ever leaves the machine.
// Mocked fetch captures the exact request body; the live part (only when
// TYPESAFE_API_KEY is set) checks the classifier actually tells disclosure from
// ordinary talk using shapes alone.

const { mask, classify, isCandidate } = require('../src/jev');
const { r } = require('./gen');

const cfg = { jev: { enabled: true, endpoint: 'https://example.invalid', apiKeyEnv: 'KEYFENCE_TEST_KEY', model: 'jev-latest', timeoutMs: 2500, threshold: 0.18 } };
const realFetch = global.fetch;
const cases = [];
const check = (name, ok) => cases.push({ name, ok });

// Context words are never sent as candidates: labels, emails, URLs, design tokens.
for (const w of ['usuario:', 'senha=', 'leo@empresa.com', 'https://painel.io/x', '--color-primary-500', 'primary-500']) {
  check(`not a candidate: ${w}`, !isCandidate(w));
}
check('a mixed password is a candidate', isCandidate('Kq9zPm2x!'));
check('digits with a symbol is a candidate', isCandidate('88776655*'));
for (const w of ['proteção', 'configuração', 'usuário', 'atualização']) check(`an accented word is not a candidate: ${w}`, !isCandidate(w));
check('an accented password with digits still is', isCandidate('ação2024!x'));
check('a file path is not a candidate', !isCandidate('/private/tmp/task-1.output'));

(async () => {
  // --- masking ---------------------------------------------------------------
  const pw = r(6, 'abcdefghij') + r(3, '0123456789');
  const k = r(28);
  const text = `a senha do banco é ${pw} e o token do painel é ${k}`;
  const m = mask(text);
  check('mask hides password', !m.masked.includes(pw));
  check('mask hides token', !m.masked.includes(k));
  check('mask keeps the words around', m.masked.includes('senha do banco'));
  check('mask returns both candidates', m.candidates.includes(pw) && m.candidates.includes(k));

  // --- request body never carries a value -----------------------------------
  let body = '';
  global.fetch = async (_url, opts) => {
    body = opts.body;
    return { ok: true, json: async () => ({ answers: { shares_secret: { noul: 0.93 } } }) };
  };
  process.env.KEYFENCE_TEST_KEY = 'test';
  const v = await classify(text, cfg);
  check('classifier verdict parsed', v && v.isSecret === true);
  check('request body has no password', !body.includes(pw));
  check('request body has no token', !body.includes(k));
  check('no cue word -> no call', (await classify('rode os testes de novo por favor abc123def', cfg)) === null);

  // --- network failure fails open --------------------------------------------
  global.fetch = async () => { throw new Error('down'); };
  check('network failure returns null', (await classify(text, cfg)) === null);

  // --- live (optional) --------------------------------------------------------
  let live = 'skipped (TYPESAFE_API_KEY not set)';
  if (process.env.TYPESAFE_API_KEY) {
    global.fetch = realFetch;
    const liveCfg = { jev: { ...cfg.jev, timeoutMs: 8000, endpoint: 'https://api.typesafe.ai/v1/systemone', apiKeyEnv: 'TYPESAFE_API_KEY' } };
    const disclose = await classify(`anota aí, a senha do servidor é ${r(7, 'abcdefgh')}${r(3, '0123456789')}`, liveCfg);
    const benign = await classify(`o deploy da versão v2beta7 falhou no passo de login, vê o log`, liveCfg);
    const p1 = disclose ? disclose.probability : null;
    const p2 = benign ? benign.probability : null;
    live = `disclosure p=${p1} | ordinary p=${p2}`;
    check('live: disclosure scores higher than ordinary talk', p1 !== null && p2 !== null && p1 > p2);
  }

  const failed = cases.filter((c) => !c.ok);
  console.log(`jev: ${cases.length - failed.length}/${cases.length} ok | live: ${live}`);
  failed.forEach((c) => console.log(`  FAIL ${c.name}`));
  process.exitCode = failed.length ? 1 : 0;
})();
