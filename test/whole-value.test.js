'use strict';
// A secret is captured whole, whatever it contains: any printable character in
// any position, in the ways people actually paste credentials. Either the rules
// return the exact value, or the value reaches the classifier as one candidate;
// never in pieces. Values are random at run time.

const crypto = require('crypto');
const { scan } = require('../src/detect');
const { candidatesOf } = require('../src/jev');

const ROUNDS = Number(process.env.ROUNDS || 400);
const PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join('');
const pick = (set) => set[crypto.randomInt(set.length)];
const without = (bad) => [...PRINTABLE].filter((c) => !bad.includes(c)).join('');

// Where a value sits decides what it may contain. On a `Label: value` line (or a
// value on a line of its own) the value runs to the end of the line, so anything
// goes but a leading quote, which reads as quoting. In running text the value
// may not start or end with punctuation the sentence itself would use: in "a
// senha é X?" nobody can tell whose `?` it is, so the sentence gets it. Nor
// may it be wholly shaped like a file path (/ab/cd99, ~/x, ./x): in prose that
// reads as one.
// Anywhere, a value that is wholly `$NAME` reads as a variable, not a password.
const FIELD = (v) => !/^["'`]/.test(v) && !/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(v);
const PROSE = (v) => FIELD(v) && !/^(?:(?:~|\.{1,2})\/[\w@+.-]*|\/[\w@+.-]+\/[\w@+.-]+)(?:\/[\w@+.-]+)*\/?$/.test(v) && !/[.,;:?"'`)\]}>]$/.test(v) && !/^[([{<:=]/.test(v) && !/^[)\]}>]/.test(v);
const LAYOUTS = [
  ['label', '', FIELD, (v) => `Senha: ${v}`],
  ['login + label', '', FIELD, (v) => `Usuário: joao.silva\nSenha: ${v}`],
  ['env', '', FIELD, (v) => `DB_PASSWORD=${v}`],
  ['env quoted', '"\\$`', FIELD, (v) => `DB_PASSWORD="${v}"`],
  ['json', '"\\', FIELD, (v) => `{"user": "joao", "password": "${v}"}`],
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
    const n = 10 + crypto.randomInt(21);
    // Guarantees it looks like a password: letters, digits and a symbol somewhere.
    const v = Array.from({ length: n }, () => pick(set));
    v[crypto.randomInt(n)] = pick('abcdefghijkmnpqrstuvwxyz');
    v[crypto.randomInt(n)] = pick('ABCDEFGHJKLMNPQRSTUVWXYZ');
    v[crypto.randomInt(n)] = pick('23456789');
    if (fits(v.join(''))) return v.join('');
  }
}

const fails = new Map();
for (const [name, bad, fits, layout] of LAYOUTS) {
  for (let i = 0; i < ROUNDS; i++) {
    const v = value(bad, fits);
    const text = layout(v);
    const found = scan(text, { message: true }).findings.map((f) => f.value);
    const whole = found.includes(v) || candidatesOf(text, found, 50).includes(v);
    const pieces = found.some((f) => f !== v && v.includes(f));
    if (whole && !pieces) continue;
    const key = `${name}: ${pieces ? 'in pieces' : 'not whole'}`;
    const shapes = fails.get(key) || [];
    shapes.push(v.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9'));
    fails.set(key, shapes);
  }
}

// The saved value must come back exactly when the shell loads the file: the
// hook writes it, `set -a; . .env` reads it. A value that comes back different is
// the same failure as one captured in pieces: the person has to send it again.
const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const HOOK = path.join(__dirname, '..', 'bin', 'keyfence-hook.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-whole-'));
const cfgFile = path.join(tmp, 'config.json');
fs.writeFileSync(cfgFile, JSON.stringify({ jev: { enabled: false }, capture: { globalFile: path.join(tmp, 'g', 'secrets.env') } }));
const env = { ...process.env, KEYFENCE_CONFIG: cfgFile, KEYFENCE_VAULT_DIR: path.join(tmp, 'vault'), KEYFENCE_VAULT_KEY_FILE: path.join(tmp, 'vk'), KEYFENCE_REGISTRY: path.join(tmp, 'reg.json') };
const TRIPS = Number(process.env.TRIPS || 60);
let trips = 0;
for (let i = 0; i < TRIPS; i++) {
  const repo = path.join(tmp, `r${i}`);
  fs.mkdirSync(repo);
  execFileSync('git', ['init', '-q'], { cwd: repo });
  fs.writeFileSync(path.join(repo, '.gitignore'), '.env\n');
  const v = value('', FIELD);
  const prompt = `acesso do painel\n\nUsuário: joao\nSenha: ${v}`;
  spawnSync(process.execPath, [HOOK], { cwd: repo, env, encoding: 'utf8', input: JSON.stringify({ session_id: `whole-${process.pid}-${i}`, hook_event_name: 'UserPromptSubmit', prompt, cwd: repo }) });
  const file = path.join(repo, '.env');
  const names = fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').map((l) => l.split('=')[0]).filter((n) => /PASSWORD$/.test(n)) : [];
  const back = names.map((n) => spawnSync('bash', ['-c', `set -a; . ./.env; set +a; printf %s "$${n}"`], { cwd: repo, encoding: 'utf8' }).stdout);
  if (back.length === 1 && back[0] === v) { trips++; continue; }
  const key = `round trip: ${names.length ? 'came back different' : 'nothing saved'}`;
  fails.set(key, [...(fails.get(key) || []), v.replace(/[A-Za-z]/g, 'a').replace(/[0-9]/g, '9')]);
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`round trip: ${trips}/${TRIPS} saved and loaded back exactly`);

const total = LAYOUTS.length * ROUNDS + TRIPS;
const failed = [...fails.values()].reduce((s, x) => s + x.length, 0);
console.log(`whole value: ${total - failed}/${total} captured whole (${ROUNDS} per layout)`);
for (const [k, shapes] of fails) console.log(`  ${k}: ${shapes.length} (e.g. ${shapes.slice(0, 3).join('  ')})`);
process.exitCode = failed ? 1 : 0;
