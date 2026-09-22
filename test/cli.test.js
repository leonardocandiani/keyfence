'use strict';
// CLI contract: version fast path, home view, structured errors, scan exit codes,
// values never printed, idempotent install/uninstall on a throwaway settings file.
const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { positives } = require('./gen');

const BIN = path.join(__dirname, '..', 'bin', 'keyfence.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-cli-'));
const settings = path.join(tmp, 'settings.json');
fs.writeFileSync(settings, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: 'command', command: 'echo other' }] }] } }));
const cli = (args, input) => spawnSync(process.execPath, [BIN, ...args], { input, encoding: 'utf8', env: { ...process.env, KEYFENCE_CONFIG: path.join(tmp, 'none.json') } });

const cases = [];
const check = (name, ok, detail = '') => cases.push({ name, ok, detail });

const v = cli(['--version']);
check('--version prints bare version', v.status === 0 && /^\d+\.\d+\.\d+\n$/.test(v.stdout), v.stdout);
const home = cli([]);
check('home shows bin and description', home.status === 0 && /^bin: /m.test(home.stdout) && /^description: /m.test(home.stdout));
const bad = cli(['scan', '--nope', '-']);
check('unknown flag fails loud with exit 2', bad.status === 2 && /unknown flag --nope/.test(bad.stdout) && /valid flags/.test(bad.stdout));
const badCmd = cli(['frobnicate']);
check('unknown command exit 2', badCmd.status === 2 && /^error: /.test(badCmd.stdout));

const tok = positives.find((p) => p[0] === 'github')[1]();
const s1 = cli(['scan', '-'], `deploy with ${tok}\n`);
check('scan finds token, exit 1', s1.status === 1 && /github/.test(s1.stdout), s1.stdout);
check('scan never prints the value', !s1.stdout.includes(tok));
const s2 = cli(['scan', '-'], 'nothing to see here\n');
check('clean scan exit 0 and explicit zero', s2.status === 0 && /findings: 0 secrets/.test(s2.stdout), s2.stdout);

const i1 = cli(['install', '--settings', settings]);
const after1 = JSON.parse(fs.readFileSync(settings, 'utf8'));
check('install adds three events', i1.status === 0 && ['UserPromptSubmit', 'PreToolUse', 'PostToolUse'].every((e) => after1.hooks[e]), i1.stdout);
check('install keeps other hooks', after1.hooks.Stop && after1.hooks.Stop.length === 1);
const i2 = cli(['install', '--settings', settings]);
check('second install is a no-op', i2.status === 0 && /no-op/.test(i2.stdout), i2.stdout);
const u1 = cli(['uninstall', '--settings', settings]);
const after2 = JSON.parse(fs.readFileSync(settings, 'utf8'));
check('uninstall removes only ours', u1.status === 0 && !after2.hooks.PreToolUse && after2.hooks.Stop.length === 1, u1.stdout);

const failed = cases.filter((c) => !c.ok);
console.log(`cli: ${cases.length - failed.length}/${cases.length} ok`);
failed.forEach((c) => console.log(`  FAIL ${c.name} ${c.detail.slice(0, 200)}`));
fs.rmSync(tmp, { recursive: true, force: true });
process.exitCode = failed.length ? 1 : 0;
