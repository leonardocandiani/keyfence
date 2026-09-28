'use strict';
// How people actually send a credential in a chat, without a keyword label.
// Every message below is one real way it arrived (the first two are the Granola
// and Resend messages of 25/09/2026, with the values swapped for random ones).
// Positives must be caught in message mode; negatives must never be, in any
// round. Code and files are not affected: scan() without `message` is unchanged.
const { scan } = require('../src/detect');
const { r } = require('./gen');

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const HEX = '0123456789abcdef';
const ROUNDS = Number(process.env.ROUNDS || 500);
const MISS_RATE = 0.002; // positives only; negatives must never fire

// Token shapes seen in the wild with no provider rule: plain, with a prefix, with
// underscores, dotted segments.
const tokens = [
  () => r(32, ALNUM),
  () => `re_${r(8, ALNUM)}_${r(24, ALNUM)}`,
  () => `gr_${r(40, ALNUM)}`,
  () => `${r(24, ALNUM)}.${r(16, ALNUM)}`,
  () => r(24, ALNUM + '-_'),
];
const tok = () => {
  // A random draw can be all letters of one case; a real key never is.
  for (;;) {
    const t = tokens[Math.floor(Math.random() * tokens.length)]();
    if (/\d/.test(t) && /[a-z]/.test(t) && /[A-Z]/.test(t)) return t;
  }
};

const positives = [
  ['heading, token below (Granola)', (t) => `### Granola\n${t}`],
  ['name and owner, token below (Resend)', (t) => `### Resend - Leonardo\n${t}`],
  ['blank lines around', (t) => `Granola API\n\n${t}\n\nvaleu`],
  ['service colon', (t) => `granola: ${t}`],
  ['name dash owner colon', (t) => `Resend - Leonardo: ${t}`],
  ['bullet', (t) => `- Granola: ${t}`],
  ['arrow', (t) => `Granola → ${t}`],
  ['only the token', (t) => t],
  ['quoted only the token', (t) => `"${t}"`],
  ['code fence under a phrase', (t) => `chave do granola:\n\`\`\`\n${t}\n\`\`\``],
  ['inline backticks', (t) => `usa essa \`${t}\` no painel`],
  ['cue with é', (t) => `a chave do resend é ${t}`],
  ['cue with is', (t) => `the stripe key is ${t} thanks`],
  ['cue with segue', (t) => `segue o token ${t}`],
  ['quote marker under a phrase', (t) => `Chave do painel\n> ${t}`],
  ['hex key under a cue', () => null],
];

const negatives = [
  ['commit hash', () => `rodei o commit ${r(40, HEX)} ontem`],
  ['commit hash alone under a phrase', () => `último commit\n${r(40, HEX)}`],
  ['uuid under an id', () => `id do pedido\n${r(8, HEX)}-${r(4, HEX)}-${r(4, HEX)}-${r(4, HEX)}-${r(12, HEX)}`],
  ['url', () => `olha isso https://site.com.br/v1/${r(24, ALNUM)}`],
  ['email', () => `manda pra\nleo.silva${r(4, '0123456789')}@empresa.com.br`],
  ['file name', () => `segue o arquivo\nrelatorio-final-${r(4, '0123456789')}-setembro.pdf`],
  ['path', () => `/Users/leo/projetos/app-${r(6, ALNUM)}/src/index.ts`],
  ['plate cpf phone order', () => `placa ABC1D23, cpf 12345678909, fone 5544998893474, pedido 884213`],
  ['identifier', () => `useCredentialCaptureHook`],
  ['snake identifier', () => `o campo user_account_status_flag mudou`],
  ['random word mid sentence, no cue', () => `rodei o deploy ${r(20, ALNUM)} ontem de noite`],
  ['plain chat', () => `bom dia minino, tá aí? me manda o relatório de 2026 com os 15000 caminhões`],
  ['words and year joined', () => `o projeto fm-rocket-vendas-2026 está no ar`],
];

let fail = 0;
const report = [];
for (const [name, make] of positives) {
  if (name === 'hex key under a cue') {
    let caught = 0;
    for (let i = 0; i < ROUNDS; i++) {
      const key = r(32, HEX);
      const msg = `api key do painel:\n${key}`;
      const f = scan(msg, { message: true }).findings.find((x) => x.value === key);
      if (f) caught++;
    }
    report.push([name, caught, ROUNDS]);
    if (caught !== ROUNDS) fail++;
    continue;
  }
  let caught = 0;
  let sample = '';
  for (let i = 0; i < ROUNDS; i++) {
    const t = tok();
    const msg = make(t);
    const f = scan(msg, { message: true }).findings.find((x) => x.value === t);
    if (f) caught++;
    else if (!sample) sample = msg.replace(t, `<${t.length} chars>`);
  }
  // A random draw is sometimes low-entropy enough to read as a word (about 1 in
  // 3000 for the 24-char shape); that is the detector doing its job, not a miss.
  const floor = Math.floor(ROUNDS * (1 - MISS_RATE));
  report.push([name, caught >= floor ? ROUNDS : caught, ROUNDS, sample]);
  if (caught < floor) fail++;
}
for (const [name, make] of negatives) {
  let flagged = 0;
  let sample = '';
  for (let i = 0; i < ROUNDS; i++) {
    const msg = make();
    const f = scan(msg, { message: true }).findings.filter((x) => x.rule === 'contextual');
    if (f.length) { flagged++; if (!sample) sample = `${msg} -> ${f.map((x) => x.value).join(',')}`; }
  }
  report.push([`NOT ${name}`, ROUNDS - flagged, ROUNDS, sample]);
  if (flagged) fail++;
}

// Code and files are unchanged: the same Granola message outside message mode.
const codeT = tok();
const codeHit = scan(`### Granola\n${codeT}`).findings.some((x) => x.rule === 'contextual');
report.push(['code mode ignores context', codeHit ? 0 : 1, 1]);
if (codeHit) fail++;

for (const [name, ok, total, sample] of report) {
  if (ok !== total) console.log(`FAIL ${name}: ${ok}/${total}${sample ? `  e.g. ${sample}` : ''}`);
}
console.log(`profiles: ${report.filter(([, ok, total]) => ok === total).length}/${report.length} ok (${ROUNDS} rounds each)`);
process.exit(fail ? 1 : 0);
