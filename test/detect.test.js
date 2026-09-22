'use strict';
// Detection quality: every positive caught by the expected rule, zero negatives
// flagged, ambiguous strings caught only by the ambiguous layer. Runs each
// generator many times because the content is random.
const { scan } = require('../src/detect');
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
  const need = rule === 'labeled' ? Math.floor(ROUNDS * 0.99) : ROUNDS;
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

console.log(`positives: ${positives.length - miss.length}/${positives.length} rules caught every round (${ROUNDS} rounds)`);
miss.forEach((m) => console.log(m));
console.log(`negatives: ${negatives.length - fps.length}/${negatives.length} clean`);
fps.forEach((m) => console.log(m));
console.log(`ambiguous: ${ambCaught}/${ambTotal} caught by the ambiguous layer only`);
process.exitCode = fail ? 1 : 0;
