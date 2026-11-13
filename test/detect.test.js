'use strict';
// Detection quality: every positive caught by the expected rule, zero negatives
// flagged, ambiguous strings caught only by the ambiguous layer. Runs each
// generator many times because the content is random.
const { scan } = require('../src/detect');
const WEAK = new Set(require('../src/rules').rules.filter((r) => r.weak).map((r) => r.id));
const { positives, negatives, ambiguous } = require('./gen');

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

console.log(`positives: ${positives.length - miss.length}/${positives.length} rules caught every round (${ROUNDS} rounds)`);
miss.forEach((m) => console.log(m));
console.log(`negatives: ${negatives.length - fps.length}/${negatives.length} clean`);
fps.forEach((m) => console.log(m));
console.log(`ambiguous: ${ambCaught}/${ambTotal} caught by the ambiguous layer only`);
process.exitCode = fail ? 1 : 0;
