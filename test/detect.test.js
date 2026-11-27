'use strict';
// Detection quality: every positive caught by the expected rule, zero negatives
// flagged, ambiguous strings caught only by the ambiguous layer. Runs each
// generator many times because the content is random.
const { scan } = require('../src/detect');
const WEAK = new Set(require('../src/rules').rules.filter((r) => r.weak).map((r) => r.id));
const { positives, negatives, ambiguous, r } = require('./gen');

const ROUNDS = Number(process.env.ROUNDS || 50);
let fail = 0;
const miss = [];

for (const [rule, gen] of positives) {
  let caught = 0;
  let wrong = new Set();
  for (let i = 0; i < ROUNDS; i++) {
    const tok = gen();
    const text = `before ${tok} after`;
    const { findings } = scan(text);
    const hit = findings.find((f) => text.slice(f.start, f.end).length >= 8 && tok.includes(f.value));
    if (hit && hit.rule === rule) caught++;
    else wrong.add(hit ? hit.rule : 'none');
  }
  // Provider shapes must be caught every time. Labeled values carry a documented
  // statistical limit: a short, letters-only random value can look like an
  // identifier (fooBarBazQu) and is skipped on purpose to avoid flagging code.
  // Labeled values and weak rules (bearer, URLs with passwords) skip random
  // values that look like plain words, on purpose (measured miss ~0.12%). Allow
  // 1%, and never fewer than 3 misses, so a small ROUNDS is not a coin toss.
  const lenient = rule === 'labeled' || WEAK.has(rule);
  const need = lenient ? ROUNDS - Math.max(3, Math.ceil(ROUNDS * 0.01)) : ROUNDS;
  if (caught < need) { fail++; miss.push(`  miss ${rule}: ${caught}/${ROUNDS} (got ${[...wrong].join(',')})`); }
}

const fps = [];
for (const text of negatives) {
  const { findings } = scan(text);
  if (findings.length) { fail++; fps.push(`  false positive: ${findings.map((f) => f.rule).join(',')} in "${text.slice(0, 60)}"`); }
}

let ambCaught = 0;
for (const gen of ambiguous) {
  for (let i = 0; i < ROUNDS; i++) {
    const r = scan(gen(), { ambiguous: true });
    if (r.findings.length === 0 && r.ambiguous.length === 1) ambCaught++;
  }
}
const ambTotal = ambiguous.length * ROUNDS;
if (ambCaught < ambTotal * 0.95) { fail++; }

// keyfence's own source is code full of labels (password, token, auth) next to
// regexes, ternaries and template literals: none of it is a secret.
const fsx = require('fs');
const pathx = require('path');
const srcDir = pathx.join(__dirname, '..', 'src');
for (const f of fsx.readdirSync(srcDir).filter((x) => x.endsWith('.js'))) {
  const hits = scan(fsx.readFileSync(pathx.join(srcDir, f), 'utf8')).findings;
  if (hits.length) { fail++; fps.push(`  false positive in own source src/${f}: ${hits.map((h) => h.rule).join(',')}`); }
}

// In a message, a password label in front of `NAME=value` points at an assignment:
// the variable is not the secret, so a flag (one digit) or a public URL is not one.
for (const [text, secret] of [
  ['senha: SITE_LIBERADO=1', false],
  ['password: SITE_LIBERADO=9', false],
  ['Senha: SITE_PUBLIC_URL=https://exemplo.vercel.app', false],
  ['senha: DB_PASSWORD=hunter2xyz', true],
  ['senha: hunter2xyz', true],
]) {
  const hit = scan(text, { message: true }).findings.length > 0;
  if (hit !== secret) { fail++; fps.push(`  assignment after label (${secret ? 'missed' : 'false positive'}): ${text.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9')}`); }
}

// Code read under a password label (PR 717 do multiatendimento-fmrocket, 12/11/2026):
// a member access or a comparison is not a value, a quoted literal still is.
for (const [text, secret] of [
  ['must_change_password: row.must_change_password,', false],
  ['must_change_password: c.must_change_password === 1,', false],
  ['must_change_password: !!c.must_change_password,', false],
  ['must_change_password: c.must_change_password ? true : false,', false],
  ['must_change_password: Boolean(c.must_change_password),', false],
  ['must_change_password: true,', false],
  ['const x = { must_change_password: row.must_change_password, id: 1 };', false],
  ['password: "Zk9QwR3vLm7XqT2n",', true],
  // .env and shell form (no spaces around `=`) and quoted literals are values, even all-lowercase with dots.
  ['pass' + 'word=correct.horse.battery.password', true],
  ['PASS' + 'WORD=correct.horse.battery.password', true],
  ['DB_PASS' + 'WORD=correct.horse.battery.password', true],
  ['pass' + 'word: "correct.horse.battery.password",', true],
  ["pass" + "word = 'correct.horse.battery.password';", true],
  ['password = row.password;', false],
  // YAML without quotes, alone on its line, three or more dotted words: a value. Ending in a comma, or obj.field, is a read.
  ['db:\n  pass' + 'word: correct.horse.battery.staple\n', true],
  ['- pass' + 'word: correct.horse.battery.staple\n', true],
  ['pass' + 'word: correct.horse.battery.password', true],
  ['pass' + 'word: valor.com.pontos', true],
  ['must_change_password: row.must_change_password\n', false],
  ['pass' + 'word: correct.horse.battery.staple,\n', false],
  // Last property of a multi-line object literal has no comma: code, not YAML.
  ['const u = {\n  id: 1,\n  pass' + 'word: row.user.password\n};\n', false],
  ['await db.insert({\n  email: x,\n  pass' + 'word: row.user.password\n})\n', false],
  ['  id: 1,\n  pass' + 'word: row.user.password\n}\n', false],
  ['must_change_password: "Zk9QwR3vLm7XqT2n",', true],
]) {
  const hit = scan(text).findings.length > 0;
  if (hit !== secret) { fail++; fps.push(`  code under password label (${secret ? 'missed' : 'false positive'}): ${text}`); }
}

// The same lowercase dotted value typed in a message is still the password (the
// code rule is off there), and a quoted literal is refused in both modes.
for (const [text, secret, message] of [
  ['senha: row.must_change_password', true, true],
  ['password: abc.defg.hijk_lmn', true, true],
  ['token: row.must_change_password', true, true],
  ['must_change_password: row.must_change_password,', true, true],
  ['senha: "Zk9QwR3vLm7XqT2n"', true, true],
  ['senha: "Zk9QwR3vLm7XqT2n"', true, false],
]) {
  const hit = scan(text, { message }).findings.length > 0;
  if (hit !== secret) { fail++; fps.push(`  message mode unchanged (${message ? 'message' : 'code'}, ${secret ? 'missed' : 'false positive'}): ${text}`); }
}

// The id of an autonomy event (`central-enviar texto --autonomia <id>`) names an event and opens
// nothing; the same shape without the `ev_autonomia_` prefix is a random token and stays caught.
{
  const id = ['ev', 'autonomia', 'c', '1783958520123', 'ab3c9x'].join('_');
  const rnd = ['qz', 'Kd8fXm2Lp', 't', '4829103847562', 'Rw93kz'].join('_');
  for (const [text, opts, secret] of [
    [`central-enviar texto --autonomia ${id} --para x --mensagem oi`, { ambiguous: true }, false],
    [`central-enviar texto --autonomia ${id} --para x --mensagem oi`, { message: true, ambiguous: true }, false],
    [`responda o evento:\n${id}\ne mande ao ricardo`, { message: true, ambiguous: true }, false],
    [id, { message: true, ambiguous: true }, false],
    [`central-enviar texto --autonomia ${rnd} --para x --mensagem oi`, { ambiguous: true }, true],
  ]) {
    const r = scan(text, opts);
    const hit = r.findings.length + r.ambiguous.length > 0;
    if (hit !== secret) { fail++; fps.push(`  autonomy event id (${secret ? 'missed' : 'false positive'}): ${text.replace(id, '<ID>').replace(rnd, '<RANDOM>')}`); }
  }
}

// `Senha:` followed by a login e-mail on the next line: the e-mail is the login, the password is the word that
// follows it (same line or the line below). Found by the Central's property test (PR 982).
{
  const pw = ['Kx9', 'mQ2zL!pR7'].join('');
  for (const [text, secret] of [
    [`senha:\nmaria@exemplo.com ${pw}`, true],
    [`senha:\nmaria@exemplo.com\n${pw}`, true],
    [`Senha: ${pw}`, true],
    [`login: maria@exemplo.com\nsenha: ${pw}`, true],
  ]) {
    const r = scan(text, { message: true });
    if (r.findings.some((f) => f.value === pw) !== secret) { fail++; fps.push(`  label then login e-mail (password missed): ${text.replace(pw, '<PASSWORD>')}`); }
  }
  const only = scan('senha:\nmaria@exemplo.com', { message: true });
  if (only.findings.some((f) => f.value === 'maria@exemplo.com')) { fail++; fps.push('  label then only a login e-mail: the e-mail is not the secret'); }
}

// A label whose value is, on the next line, another label (`Senha:` then `token: x`): the second one opens its own
// match and the password after it is the secret. Found by the Central's property test (PR 983).
{
  const pw = ['Kx9', 'mQ2zL!pR7'].join('');
  for (const text of [`senha:\ntoken : ${pw}`, `senha:\ntoken: ${pw}`, `senha:\nchave = ${pw}`, `senha:\nsenha: ${pw}`]) {
    if (!scan(text, { message: true }).findings.some((f) => f.value === pw)) { fail++; fps.push(`  label then another label (password missed): ${text.replace(pw, '<PASSWORD>')}`); }
  }
}

// Regression of the two label-on-next-line rules above: the match also takes the `\n` before the label, which is
// not a line break between the label and its value. A password shaped like an e-mail, on a `Senha:` line that has
// another line above it, is still the password (found by the seeded whole-value test, seeds 44, 56, 87, 160, 192).
{
  const mail = ['4k4.@kkkkk.kk', 'x@y9.zz'];
  const pw = ['Kx9', 'mQ2zL!pR7'].join('');
  const cases = [
    ...mail.map((v) => [`Usuário: joao.silva\nSenha: ${v}`, v]),
    ...mail.map((v) => [`<pasted_content id="a1">\n### Painel\n\nUsuário: joao\nSenha: ${v}\n</pasted_content id="a1">`, v]),
    [`Usuário: joao\nsenha:\ntoken: ${pw}`, pw],
  ];
  for (const [text, secret] of cases) {
    if (!scan(text, { message: true }).findings.some((f) => f.value === secret)) { fail++; fps.push(`  label after another line, value missed: ${text.replace(secret, '<VALUE>').replace(/\n/g, '\\n')}`); }
  }
}

// A credential written as markdown (bold field, table row, password column): the emphasis marks
// and the pipes sit where the labeled rule expects `:` or `=`. A real password stayed seven months in
// a report in this shape (27/11/2026). Both modes: a file read and a pasted message.
{
  const pw = ['Zq7', r(5)].join(''); // always a digit, so it never passes for a word
  const long = ['Zq7!', r(10)].join('');
  const key = ['Vb4', r(25)].join('');
  const caught = [
    [`| **Senha** | \`${pw}\` |`, pw],
    [`| Senha | ${pw} |`, pw],
    [`| **Campo** | **Valor** |\n|---|---|\n| **Password** | **${long}** |`, long],
    [`> | Senha do painel | \`${long}\` | trocar depois |`, long],
    [`| API Key | \`${key}\` |`, key],
    [`**Senha:** \`${pw}\``, pw],
    [`**Senha**: ${pw}`, pw],
    [`- **Password:** ${long} (conta de teste)`, long],
    [`__Token__: \`${key}\``, key],
    [`**Client Secret:** "${key}"`, key],
    [`| Usuário | Senha |\n|:---|---:|\n| joao | \`${pw}\` |\n| maria | ${long} |`, pw],
    [`| Usuário | Senha |\n|:---|---:|\n| joao | \`${pw}\` |\n| maria | ${long} |`, long],
    [`| **Senha** | \`a|${pw}\` |`, `a|${pw}`],
    [`| Senha | 7392-0418-55 |`, '7392-0418-55'],
    [`**Password:** "cavalo ${pw} bateria grampo"`, `cavalo ${pw} bateria grampo`],
    [`| Senha | \`cavalo ${pw} bateria\` |`, `cavalo ${pw} bateria`],
    [`**Password:** Cavalo(${4000 + 271})`, `Cavalo(${4000 + 271})`], [`**Password:** "Cavalo(${4000 + 271})"`, `Cavalo(${4000 + 271})`],
    [`| Senha | Cavalo(${4000 + 271}) |`, `Cavalo(${4000 + 271})`],
    [`Usuário | Senha\n--- | ---\njoao | ${pw}\n\nfim`, pw],
    [`Campo | Valor\n:--|--:\nSenha | \`${long}\``, long],
    [`| Usuário | Senha\n|---|---\n| joao | ${pw}`, pw],
  ];
  const quiet = [
    '| password | string |', '| password | `string` |', '| senha | obrigatória |', '| Senha | pré-definida |',
    '| token | varchar(255) |', '| token | VARCHAR |', '| key | user.id |', '| secret | YOUR_SECRET |',
    '| Senha | ******** |', '| Senha | `<SENHA>` |', '| Senha | [redigido] |', '| Senha | `$FIN_SENHA` |',
    '| Input token | $15.00/MTok |', '| Output token | 1.234.567 |', '| Chave PIX | financeiro@exemplo.com.br |',
    '| Token | https://exemplo.com.br/oauth/token |', '| Campo | Senha |\n|---|---|\n| tipo | texto |',
    '| Senha | Senha do usuário |', '**Senha:** obrigatória', '**Token:** gerado no login a cada sessão',
    '**Auth:** Header `Authorization`', '**Password:** `string` (required)', '**Chave:** placa_veiculo',
    '**Senha:** use a do cofre', 'cat x | grep senha | head -5',
    '| `/auth/b2b` | `B2BSignupPage` |', '- **Chave**: `senderId:conversaAtual`', '| AGENTE_API_KEY | `agent-handler.ts:42` |',
    '| Token | `did_you:mean_match` |', '| auth-reviewer | Auth/Session |', '| Auth issues | @security-team |',
    '- **Pass Rate:** {(passed/total)*100:.1f}%', `| Token TTL token | 1.2${String.fromCharCode(8211)}2.4s |`, '| TOKEN | Idêntico |', '| Secret | Settings |',
    '| Token | `bun run test --watch` |', '**Chave:** "nome do campo no banco"',
    '| pass | `node "$CLI" run --symptoms "x9" <app>` |', '**Senha:** getPassword()', '| Token | readToken(env2) |', '| senha | varchar(50) |', '| password | NVARCHAR(255) |', '| PASSWORD | `DB_PASSWORD_9` / `Chave-Dois9` |',
    'grep senha access.log | wc -l\n---\n| fim', 'senha | Zq7semtabela\n\noutro texto', 'Usuário | Senha\ntexto solto | outro',
    '---\nsenha | exemplo\n---', '  |> Map.put(:password, hashed)',
  ];
  for (const opts of [{}, { message: true }]) {
    const mode = opts.message ? 'message' : 'file';
    for (const [text, secret] of caught) {
      const hit = scan(text, opts).findings.find((f) => f.value === secret);
      if (!hit || text.slice(hit.start, hit.end) !== secret) { fail++; fps.push(`  markdown credential missed (${mode}): ${text.split(secret).join('<VALUE>').replace(pw, '<VALUE>').replace(long, '<VALUE>')}`); }
    }
  }
  // Long runs of what the markdown reader looks for must not make it slow (the reader of words
  // once froze the daily maintain for days). Another process, so a regression fails instead of hanging.
  {
    const script = `const { scan } = require(${JSON.stringify(require('path').join(__dirname, '..', 'src', 'detect'))});
      const n = 100000;
      for (const t of ['**' + ' '.repeat(n) + 'x', '**Senha:**' + ' '.repeat(n) + 'x y', '**Senha:** x' + ' '.repeat(n) + 'y',
        '|---|---|\\n'.repeat(20000), 'a | b\\n--- | ---\\n' + '--- | ---\\n'.repeat(20000), '**Senha:** "' + 'a '.repeat(n),
        '|' + ' |'.repeat(n), '**Senha**'.repeat(n / 10)]) scan(t, { message: true });`;
    const done = require('child_process').spawnSync(process.execPath, ['-e', script], { timeout: 20000 });
    if (done.status !== 0) { fail++; fps.push(`  markdown reader too slow or crashed on long input (status ${done.status})`); }
  }

  // A numeric password is a password when typed under a password column or cell.
  if (!scan('| Senha | 739204 |', { message: true }).findings.some((f) => f.value === '739204')) { fail++; fps.push('  markdown numeric password missed (message)'); }
  for (const text of quiet) {
    if (scan(text).findings.length) { fail++; fps.push(`  markdown false positive: ${text}`); }
  }
}

console.log(`positives: ${positives.length - miss.length}/${positives.length} rules caught every round (${ROUNDS} rounds)`);
miss.forEach((m) => console.log(m));
console.log(`negatives: ${negatives.length - fps.length}/${negatives.length} clean`);
fps.forEach((m) => console.log(m));
console.log(`ambiguous: ${ambCaught}/${ambTotal} caught by the ambiguous layer only`);
process.exitCode = fail ? 1 : 0;
