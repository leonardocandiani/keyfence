'use strict';
// A session log past 512 MB cannot be read with readFileSync('utf8'); maintenance
// reads logs in blocks instead. Synthetic data only; a tiny block size forces
// every boundary case (line and multi-byte character split across blocks).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { eachLine } = require('../src/lines');
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
