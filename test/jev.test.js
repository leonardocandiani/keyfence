'use strict';
// The classifier's privacy contract: no candidate value ever leaves the machine.
// Mocked fetch captures the exact request body; the live part (only when
// TYPESAFE_API_KEY is set) checks the classifier actually tells disclosure from
// ordinary talk using shapes alone.

const { mask, classify, isCandidate, candidatesOf, mayBeSecret, judge } = require('../src/jev');
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

// Dates, times, rates and formatted numbers are data. A message quoting data
// windows kept them pending for a whole session when the classifier was down.
for (const w of ['15/03/2024', '28/02/2025', '17/11/23', '2027-04-19', '2027-04-19T08:15:00Z', '08:15:42', '15h30', '12,34%', '7,5%', '4.321', '12.345', '1.234.567,89', '7.000,00', '88,8%']) {
  check(`data is not a candidate: ${w}`, !isCandidate(w) && !mayBeSecret(w) && !mayBeSecret(w, true));
}
for (const w of ['Kq9zPm2x!', '15/03/2024Kq', 'ab15/03/2024', '88776655*', '123.456.789-01']) {
  check(`a secret-like word is still a candidate: ${w}`, mayBeSecret(w, true));
}
check('a digits-only PIN is still a candidate when the message talks about access', mayBeSecret('15032024', true));
{
  const msg = 'a senha não entra; janela Moskit de 15/03/2024 a 28/02/2025, 12.345 leads, 7,5% silêncio, 12,34% contra 8,5%, código Kq9zPm2x!';
  const c = candidatesOf(msg);
  check('a message with data windows keeps only the real candidate', c.length === 1 && c[0] === 'Kq9zPm2x!');
}

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
    // An unreachable API is not a keyfence failure: report it, do not fail the suite.
    if (p1 === null || p2 === null) live = 'API unavailable, skipped';
    else check('live: disclosure scores higher than ordinary talk', p1 > p2);
  }

  // --- a partial answer settles what it answered --------------------------------
  global.fetch = async (_url, opts) => {
    const q = Object.keys(JSON.parse(opts.body).questions);
    return { ok: true, json: async () => ({ answers: { [q[0]]: { noul: 0.91 } } }) };
  };
  const partial = await judge('usa Kq9zPm2x! e Zx7abcde12345 no teste', ['Kq9zPm2x!', 'Zx7abcde12345'], { jev: { ...cfg.jev, jobTimeoutMs: 2000 } });
  global.fetch = realFetch;
  check('partial answer: the answered word gets a verdict', Boolean(partial) && partial.length === 1 && partial[0].value === 'Kq9zPm2x!' && partial[0].p === 0.91);

  const failed = cases.filter((c) => !c.ok);
  console.log(`jev: ${cases.length - failed.length}/${cases.length} ok | live: ${live}`);
  failed.forEach((c) => console.log(`  FAIL ${c.name}`));
  process.exitCode = failed.length ? 1 : 0;
})();
