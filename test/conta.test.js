'use strict';
// "conta <serviço>: login ..., senha ..." names the credential for good the moment
// it is pasted, the agent gets a one-line confirmation with names and lengths, a
// 2FA service is flagged as the user's step, and `keyfence conta <serviço>` lists
// what is saved and what is missing. Synthetic values, an isolated vault and registry.

const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { positives } = require('./gen');

const BIN = path.join(__dirname, '..', 'bin', 'keyfence.js');
const HOOK = path.join(__dirname, '..', 'bin', 'keyfence-hook.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-conta-'));
const repo = path.join(tmp, 'repo');
fs.mkdirSync(repo);
execFileSync('git', ['init', '-q'], { cwd: repo });
fs.writeFileSync(path.join(repo, '.gitignore'), '.env\n');
const cfgFile = path.join(tmp, 'config.json');
fs.writeFileSync(cfgFile, JSON.stringify({ jev: { enabled: false }, capture: { globalFile: path.join(tmp, 'global', 'secrets.env') } }));
const env = { ...process.env, KEYFENCE_CONFIG: cfgFile, KEYFENCE_VAULT_DIR: path.join(tmp, 'vault'), KEYFENCE_VAULT_KEY_FILE: path.join(tmp, 'vault-key'), KEYFENCE_REGISTRY: path.join(tmp, 'registry.json') };
const SID = `conta-${process.pid}-${Date.now()}`;

const paste = (prompt) => {
  const res = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ session_id: SID, hook_event_name: 'UserPromptSubmit', cwd: repo, prompt }), env, encoding: 'utf8' });
  let ctx = '';
  try { ctx = JSON.parse(res.stdout).hookSpecificOutput.additionalContext; } catch { /* no context */ }
  return ctx;
};
const conta = (...args) => spawnSync(process.execPath, [BIN, 'conta', ...args], { env, encoding: 'utf8' });
const readEnv = () => { try { return fs.readFileSync(path.join(repo, '.env'), 'utf8'); } catch { return ''; } };

const cases = [];
const check = (name, ok, detail = '') => cases.push({ name, ok: Boolean(ok), detail });

const pw1 = `Zq${positives.find((p) => p[0] === 'github')[1]().slice(4, 14)}9#`;
const login1 = 'leo.teste@exemplo.com';

const a = paste(`conta teste-x: login ${login1}, senha ${pw1}`);
check('names are final at once: login and password under the service', a.includes('$TESTE_X_LEO_LOGIN') && a.includes('$TESTE_X_LEO_PASSWORD'), a);
check('no provisional code', !/KF_|provisional/.test(a), a);
check('the agent is told the one-line confirmation, names and lengths', a.includes(`gravado como $TESTE_X_LEO_LOGIN e $TESTE_X_LEO_PASSWORD (tam ${login1.length} e ${pw1.length})`) || a.includes(`gravado como $TESTE_X_LEO_PASSWORD e $TESTE_X_LEO_LOGIN (tam ${pw1.length} e ${login1.length})`), a);
check('the context never echoes a value', !a.includes(pw1) && !a.includes(login1), '');
const envText = readEnv();
check('both values are in the git-ignored .env under the final names', envText.includes('TESTE_X_LEO_PASSWORD=') && envText.includes('TESTE_X_LEO_LOGIN='), envText.replace(pw1, '<senha>'));

const none = paste('conta teste-y: login leo.y@exemplo.com, senha ainda não tenho');
check('a plain word after "senha" is not saved', !none.includes('TESTE_Y') && !/saved it as/.test(none), none);

const twoFa = paste(`conta teste-z: login z.teste@exemplo.com, senha Zq${pw1.slice(2, 12)}7!, o site pede 2FA por código no e-mail`);
check('2FA: the agent is told that step is the user\'s', /second factor/.test(twoFa) && /never ask for, read or relay that code/.test(twoFa), twoFa);
check('without 2FA the note is absent', !/second factor/.test(a), a);

const pw2 = `Zq${pw1.slice(3, 13)}5!`;
paste(`conta teste-r: login rita.teste@exemplo.com, senha ${pw2}, recuperação: rec.teste@exemplo.com`);

const c1 = conta('teste-x');
check('keyfence conta lists the account and what exists', c1.status === 0 && /teste-x\/leo,dev,active,login password,token recovery/.test(c1.stdout), c1.stdout);
check('keyfence conta lists the variable names', /TESTE_X_LEO_LOGIN,teste-x\/leo/.test(c1.stdout) && /TESTE_X_LEO_PASSWORD,teste-x\/leo/.test(c1.stdout), c1.stdout);
check('keyfence conta never prints a value', !c1.stdout.includes(pw1) && !c1.stdout.includes(login1), '');
const c2 = conta('teste-r');
check('the recovery e-mail is kept and listed', /teste-r\/rita,dev,active,login password recovery,token/.test(c2.stdout) && /TESTE_R_RITA_RECOVERY_EMAIL/.test(c2.stdout), c2.stdout);
check('the recovery e-mail is not taken for the login', /TESTE_R_RITA_LOGIN/.test(c2.stdout), c2.stdout);
const c3 = conta('servico-que-nao-existe');
check('a service with nothing saved says so and how to start', c3.status === 0 && /accounts: 0/.test(c3.stdout) && /empty: /.test(c3.stdout) && /conta servico-que-nao-existe:/.test(c3.stdout), c3.stdout);
const c4 = conta();
check('no service name fails loud with exit 2', c4.status === 2 && /^error: /.test(c4.stdout), c4.stdout);
const c5 = conta('teste-x', '--nope');
check('an unknown flag fails loud with exit 2', c5.status === 2, c5.stdout);

fs.rmSync(tmp, { recursive: true, force: true });
const failed = cases.filter((c) => !c.ok);
console.log(`conta: ${cases.length - failed.length}/${cases.length} scenarios ok`);
failed.forEach((c) => console.log(`  FAIL ${c.name}${c.detail ? `: ${String(c.detail).slice(0, 400)}` : ''}`));
process.exitCode = failed.length ? 1 : 0;
