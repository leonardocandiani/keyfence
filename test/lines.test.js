'use strict';
// A session log past 512 MB cannot be read with readFileSync('utf8'); maintenance
// reads logs in blocks instead. Synthetic data only; a tiny block size forces
// every boundary case (line and multi-byte character split across blocks).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { eachLine, eachLineWith } = require('../src/lines');
const { exposedValues } = require('../src/discover');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-lines-'));
const cases = [];
const check = (name, got, want) => cases.push({ name, ok: JSON.stringify(got) === JSON.stringify(want), got, want });

const body = ['primeira linha', 'ação com acentuação e emoji ✓ 😀', '', 'última sem quebra'];
const file = path.join(tmp, 'a.jsonl');
fs.writeFileSync(file, body.join('\n'));
for (const size of [1, 2, 3, 5, 7, 64]) check(`block ${size} gives the same lines`, [...eachLine(file, size)].filter((l) => l !== ''), body.filter((l) => l !== ''));
fs.writeFileSync(file, 'a\nb\n');
check('trailing newline adds no empty line', [...eachLine(file, 2)], ['a', 'b']);
fs.writeFileSync(file, '');
check('empty file yields nothing', [...eachLine(file)], []);

const mixed = ['nada aqui', 'tem tok.en+1 no meio', 'ação ✓ tok.en+1 e [x](y) 😀', 'dois tok.en+1 e outro-valor tok.en+1', '', 'só outro-valor', 'tokxen+1 não casa', 'fim com tok.en+1'];
for (const tail of ['', '\n']) {
  fs.writeFileSync(file, mixed.join('\n') + tail);
  const want = [...eachLine(file)].filter((l) => l.includes('tok.en+1') || l.includes('outro-valor'));
  for (const size of [1, 2, 3, 5, 7, 11, 64, 4096]) check(`eachLineWith block ${size}${tail ? ' with trailing newline' : ''} equals the filtered lines`, [...eachLineWith(file, ['tok.en+1', 'outro-valor'], size)], want);
}
fs.writeFileSync(file, mixed.join('\n'));
check('a needle with regex characters matches only itself', [...eachLineWith(file, ['tok.en+1'])].includes('tokxen+1 não casa'), false);
check('an empty needle keeps every line, as includes("") did', [...eachLineWith(file, ['zzz', ''], 5)], [...eachLine(file, 5)]);
check('no needles yields nothing', [...eachLineWith(file, [])], []);
check('the last line without newline is matched', [...eachLineWith(file, ['fim com'], 3)], ['fim com tok.en+1']);

const root = path.join(tmp, 'projects', 'p1');
fs.mkdirSync(root, { recursive: true });
const value = 'Zk9QwR3vLm7XcB2nHs5TyU8eJd4GfA6p';
fs.writeFileSync(path.join(root, 's.jsonl'), `{"m":"nada"}\n{"m":"uso ${value} aqui"}\n`);
process.env.KEYFENCE_LOGS_DIR = path.join(tmp, 'projects');
check('a value found in a log is exposed', [...exposedValues([value, 'outro-valor-que-nao-esta'])], [value]);

fs.rmSync(tmp, { recursive: true, force: true });
const failed = cases.filter((c) => !c.ok);
console.log(`lines: ${cases.length - failed.length}/${cases.length} scenarios ok`);
failed.forEach((c) => console.log(`  FAIL ${c.name}: got ${JSON.stringify(c.got)}, want ${JSON.stringify(c.want)}`));
process.exitCode = failed.length ? 1 : 0;
