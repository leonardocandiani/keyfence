'use strict';
// A secret is captured whole, whatever it contains: any printable character in
// any position, in the ways people actually paste credentials. Either the rules
// return the exact value, or the value reaches the classifier as one candidate;
// never in pieces. Values come from a seeded generator: a failure prints the seed,
// and `SEED=<n> node test/whole-value.test.js` reproduces it exactly.

const { scan } = require('../src/detect');
const { candidatesOf } = require('../src/jev');
const { commonForm } = require('../src/forms');

const ROUNDS = Number(process.env.ROUNDS || 400);
const SEED = Number(process.env.SEED || 20261117);
// Seeds that once failed (17/11/2026, the label-on-next-line rules read the `\n` before the label as the one
// before the value) stay in the run for good. A seed reproduces only with the same number of rounds (each layout
// takes its values from the one stream), so they always run with FIXED_ROUNDS, whatever ROUNDS says.
// SEED=<n> runs only that seed, with ROUNDS.
const FIXED_SEEDS = [44, 56, 87, 160, 192, 203, 224, 283];
const FIXED_ROUNDS = 400;
const RUNS = process.env.SEED ? [[SEED, ROUNDS]] : [[SEED, ROUNDS], ...FIXED_SEEDS.map((seed) => [seed, FIXED_ROUNDS])];
let state = SEED >>> 0;
function rnd(n) {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return Math.floor((((t ^ (t >>> 14)) >>> 0) / 4294967296) * n);
}
const PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join('');
const pick = (set) => set[rnd(set.length)];
const without = (bad) => [...PRINTABLE].filter((c) => !bad.includes(c)).join('');

// Where a value sits decides what it may contain. On a `Label: value` line (or a
// value on a line of its own) the value runs to the end of the line, so anything
// goes but a leading quote, which reads as quoting. In running text the value
// may not start or end with punctuation the sentence itself would use: in "a
// senha é X?" nobody can tell whose `?` it is, so the sentence gets it. Nor
// may it be wholly shaped like a file path (/ab/cd99, ~/x, ./x): in prose that
// reads as one.
// Nor may it be wholly a plain identifier, file name, e-mail or dotted name (word.word9):
// by shape alone those are never asked about; a label still captures them.
// Anywhere, a value that is wholly `$NAME` reads as a variable, one that is wholly `$(...)` as a command
// substitution and one that is wholly `<your-password>` as a placeholder (PLACEHOLDER in src/detect.js),
// not a password.
const FIELD = (v) => !/^["'`]/.test(v) && !/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v) && !/^\$\(.*\)$/.test(v) && !/^<[\w\s.-]+>$/.test(v);
// In `.env`, `.env` in quotes and JSON the hook reads `UPPER_NAME=rest` as a variable assignment being copied
// (`OK_56=helSI`); in a `Senha:` line the same text is a password.
const ENVFIELD = (v) => FIELD(v) && !/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+=/.test(v);
// In running text a word ending in a known file extension (`.js` in any case) is a file name (NOT_A_VALUE in src/jev.js).
const PROSE = (v) => FIELD(v) && !/\.(?:js|ts|tsx|jsx|md|json|py|sh|html|css|png|jpg|pdf|txt)$/i.test(v) && !/^(?:(?:~|\.{1,2})\/[\w@+.-]*|\/[\w@+.-]+\/[\w@+.-]+)(?:\/[\w@+.-]+)*\/?$/.test(v) && !/[.,;:?!"'`)\]}>]$/.test(v) && !/^[([{<:=]/.test(v) && !/^[)\]}>]/.test(v) && !commonForm(v);
const LAYOUTS = [
  ['label', '', FIELD, (v) => `Senha: ${v}`],
  ['login + label', '', FIELD, (v) => `Usuário: joao.silva\nSenha: ${v}`],
  ['env', '', ENVFIELD, (v) => `DB_PASSWORD=${v}`],
  ['env quoted', '"\\$`', ENVFIELD, (v) => `DB_PASSWORD="${v}"`],
  ['json', '"\\', ENVFIELD, (v) => `{"user": "joao", "password": "${v}"}`],
  ['pasted block', '', FIELD, (v) => `<pasted_content id="a1">\n### Painel\n\nUsuário: joao\nSenha: ${v}\n</pasted_content id="a1">`],
  ['label on next line', '', FIELD, (v) => `senha:\n${v}`],
  ['prose', '', PROSE, (v) => `a senha do painel é ${v} pode usar`],
  ['prose login', '', PROSE, (v) => `segue o acesso login joao senha ${v}`],
  ['prose period', '', PROSE, (v) => `a senha do painel é ${v}.`],
  ['prose comma', '', PROSE, (v) => `a senha é ${v}, e o login é joao`],
  ['token', '', PROSE, (v) => `o token da api é ${v}`],
];

function value(bad, fits) {
  const set = without(bad);
  for (;;) {
    const n = 10 + rnd(21);
    // Guarantees it looks like a password: letters, digits and a symbol somewhere.
    const v = Array.from({ length: n }, () => pick(set));
    v[rnd(n)] = pick('abcdefghijkmnpqrstuvwxyz');
    v[rnd(n)] = pick('ABCDEFGHJKLMNPQRSTUVWXYZ');
    v[rnd(n)] = pick('23456789');
    if (fits(v.join(''))) return v.join('');
  }
}

const fails = new Map();
const failedSeeds = new Set();
for (const [seed, rounds] of RUNS) {
  state = seed >>> 0;
  for (const [name, bad, fits, layout] of LAYOUTS) {
    for (let i = 0; i < rounds; i++) {
      const v = value(bad, fits);
      const text = layout(v);
      const found = scan(text, { message: true }).findings.map((f) => f.value);
      const whole = found.includes(v) || candidatesOf(text, found, 50).includes(v);
      const pieces = found.some((f) => f !== v && v.includes(f));
      if (whole && !pieces) continue;
      const key = `${name}: ${pieces ? 'in pieces' : 'not whole'} [seed ${seed}]`;
      const shapes = fails.get(key) || [];
      shapes.push(v.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9'));
      fails.set(key, shapes);
      failedSeeds.add(seed);
    }
  }
}
state = SEED >>> 0;

// Fixed cases: every refusal the generator leaves out on purpose has its own proof here, with the layout that
// refuses it and one that does not, and every value that once came back in pieces stays as a case.
//   whole   the value comes back as one finding or one candidate, and no finding is a piece of it
//   refused nothing comes back: by design (src/detect.js PLACEHOLDER, src/jev.js NOT_A_VALUE, the env assignment)
const LAYOUT = Object.fromEntries(LAYOUTS.map(([name, , , layout]) => [name, layout]));
const FIXED_CASES = [
  // `$(command)` is a command substitution; without the closing `)` it is a password.
  ['$(]nEjbSh~JX*!6-Z*^S4D))', 'json', 'refused'],
  ['$(nEjbShJX6Z*S4D)', 'json', 'refused'],
  ['$(]nEjbSh~JX*!6-Z*^S4D', 'json', 'whole'],
  ['$(nEjbShJX6Z*S4D', 'json', 'whole'],
  // `<name>` is a placeholder in every layout.
  ['<tYT7mdgmc7H2U6vsqkLK>', 'label', 'refused'],
  ['<tYT7mdgmc7H2U6vsqkLK>', 'json', 'refused'],
  ['<tYT7mdgmc7H2U6vsqkLK', 'label', 'whole'],
  // A known file extension, in any case, makes a word of running text a file name; in a `Senha:` line it is a password.
  ['3Opn2_lV.jS', 'prose period', 'refused'],
  ['3Opn2_lV.jS', 'prose', 'refused'],
  ['3Opn2_lV.jS', 'label', 'whole'],
  ['3Opn2_lVxjS', 'prose period', 'whole'],
  // `UPPER_NAME=rest` is an assignment in `.env` and JSON; in a `Senha:` line it is a password.
  ['OK_56=helSI', 'env', 'refused'],
  ['OK_56=helSI', 'env quoted', 'refused'],
  ['VRAO8_H4=$:', 'json', 'refused'],
  ['OK_56=helSI', 'label', 'whole'],
  ['ok56_x=helSI', 'json', 'whole'],
  // Passwords with `->` or backticks in running text came back in pieces (scanContextual took the part after the
  // `>` or between the backticks as a word of its own); seeds 203, 224 and 283 found them.
  ['d`U9VE4vwo=qKG14-Et`>E0>e)MvkR', 'prose comma', 'whole'],
  ['.t&eM8->5NbM0/L2ta0Iw3va', 'prose login', 'whole'],
  ['6<XL\\U->A7H7P0QFQ6qSi=jN5', 'prose comma', 'whole'],
];
for (const [v, layoutName, want] of FIXED_CASES) {
  const text = LAYOUT[layoutName](v);
  const found = scan(text, { message: true }).findings.map((f) => f.value);
  const reached = found.includes(v) || candidatesOf(text, found, 50).includes(v);
  const pieces = found.some((f) => f !== v && v.includes(f));
  const got = pieces ? 'in pieces' : reached ? 'whole' : 'refused';
  if (got !== want) fails.set('fixed case', [...(fails.get('fixed case') || []), `${layoutName}: wanted ${want}, got ${got}: ${v.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9')}`]);
}

// The saved value must come back exactly when the shell loads the file: the
// hook writes it, `set -a; . .env` reads it. A value that comes back different is
// the same failure as one captured in pieces: the person has to send it again.
const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const HOOK = path.join(__dirname, '..', 'bin', 'keyfence-hook.js');
const { parseEnv } = require('../src/capture');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-whole-'));
const cfgFile = path.join(tmp, 'config.json');
fs.writeFileSync(cfgFile, JSON.stringify({ jev: { enabled: false }, capture: { globalFile: path.join(tmp, 'g', 'secrets.env') } }));
const env = { ...process.env, KEYFENCE_CONFIG: cfgFile, KEYFENCE_VAULT_DIR: path.join(tmp, 'vault'), KEYFENCE_VAULT_KEY_FILE: path.join(tmp, 'vk'), KEYFENCE_REGISTRY: path.join(tmp, 'reg.json') };
const TRIPS = Number(process.env.TRIPS || 60);
let trips = 0;
const FIXED = ['~::abcD9efgh9:k', 'abcD9efg:~:k9Zq', 'abcD9efgh9k:~', 'abcD9~/x:k9Zq'];
for (let i = 0; i < TRIPS; i++) {
  const repo = path.join(tmp, `r${i}`);
  fs.mkdirSync(repo);
  execFileSync('git', ['init', '-q'], { cwd: repo });
  fs.writeFileSync(path.join(repo, '.gitignore'), '.env\n');
  // `~` at the start of the value, or after a `:`, followed by `:` `/` or the end, is a home directory
  // to bash when the file is sourced: these must come back exactly, not as $HOME.
  const v = i < FIXED.length ? FIXED[i] : value('', FIELD);
  const prompt = `acesso do painel\n\nUsuário: joao\nSenha: ${v}`;
  spawnSync(process.execPath, [HOOK], { cwd: repo, env, encoding: 'utf8', input: JSON.stringify({ session_id: `whole-${process.pid}-${i}`, hook_event_name: 'UserPromptSubmit', prompt, cwd: repo }) });
  const file = path.join(repo, '.env');
  const passwords = () => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').map((l) => l.split('=')[0]).filter((n) => /PASSWORD$/.test(n)) : []);
  // The capture saves a provisional name at once and a background job adds the
  // real one: wait for it, then every name must load back the exact value, and
  // keyfence's own reader must agree with bash.
  for (let t = Date.now(); Date.now() - t < 8000 && !passwords().some((n) => !/^KF_/.test(n));) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  const names = passwords();
  const back = names.map((n) => spawnSync('bash', ['-c', `set -a; . ./.env; set +a; printf %s "$${n}"`], { cwd: repo, encoding: 'utf8' }).stdout);
  const parsed = names.map((n) => parseEnv(fs.readFileSync(file, 'utf8')).get(n));
  if (names.some((n) => !/^KF_/.test(n)) && back.every((b) => b === v) && parsed.every((p) => p === v)) { trips++; continue; }
  const key = `round trip: ${names.length ? 'came back different' : 'nothing saved'}`;
  fails.set(key, [...(fails.get(key) || []), v.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9')]);
}
fs.rmSync(tmp, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
console.log(`round trip: ${trips}/${TRIPS} saved and loaded back exactly`);

const total = LAYOUTS.length * RUNS.reduce((sum, [, rounds]) => sum + rounds, 0) + TRIPS;
const failed = [...fails.values()].reduce((s, x) => s + x.length, 0);
console.log(`whole value: ${total - failed}/${total} captured whole (${ROUNDS} per layout, plus ${RUNS.length - 1} fixed seeds)`);
for (const [k, shapes] of fails) console.log(`  ${k}: ${shapes.length} (e.g. ${shapes.slice(0, 3).join('  ')})`);
for (const seed of failedSeeds) console.log(`  seed ${seed}: rerun with SEED=${seed} ROUNDS=${seed === SEED ? ROUNDS : FIXED_ROUNDS} node test/whole-value.test.js`);
process.exitCode = failed ? 1 : 0;
