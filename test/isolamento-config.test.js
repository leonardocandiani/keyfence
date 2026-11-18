'use strict';
// Regression: test/tidy.test.js once read the user's real config and ran its maintain.onFailure
// (a real `central quadro criar`) with the fake error "boom". Here the home config is a fake one that
// writes a marker file; the suite must finish without ever running it.
// `node test/isolamento-config.test.js <arquivo>` runs another test file under the same trap.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-isolamento-'));
const home = path.join(tmp, 'home');
const marker = path.join(tmp, 'onFailure-rodou.txt');
fs.mkdirSync(path.join(home, '.config', 'keyfence'), { recursive: true });
fs.writeFileSync(path.join(home, '.config', 'keyfence', 'config.json'), JSON.stringify({
  maintain: { onFailure: [process.execPath, '-e', 'require("fs").writeFileSync(process.argv[1], process.argv[2])', marker, '{error}'] },
}));

const env = { ...process.env, HOME: home, USERPROFILE: home };
for (const k of ['KEYFENCE_CONFIG', 'KEYFENCE_VAULT_DIR', 'KEYFENCE_VAULT_KEY_FILE', 'KEYFENCE_LOGS_DIR', 'KEYFENCE_REGISTRY']) delete env[k];
const alvo = process.argv[2] ? path.resolve(process.argv[2]) : path.join(__dirname, 'tidy.test.js');
const r = spawnSync(process.execPath, [alvo], { env, encoding: 'utf8', timeout: 120000 });

const cases = [
  ['the suite finishes with exit 0 under a home that has an onFailure', r.status, 0],
  ['the onFailure of the home config never ran', fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : 'never ran', 'never ran'],
];
let failed = 0;
for (const [name, got, want] of cases) {
  if (got !== want) { failed++; console.log(`  FAIL ${name}: got ${got}, want ${want}`); }
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`isolamento-config: ${cases.length - failed}/${cases.length} ok`);
process.exit(failed ? 1 : 0);
