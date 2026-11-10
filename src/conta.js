'use strict';
// `keyfence conta <serviço>`: what keyfence already holds for an account at a
// service and what is still missing. Names and roles only, never a value.

const os = require('os');
const { slug } = require('./credential');
const { readRegistry } = require('./capture');

const ROLES = ['login', 'password', 'token', 'recovery'];
const roleOf = (field) => (field === 'api_key' || field === 'secret' ? 'token' : field);

function accountsOf(service) {
  const vault = require('./vault');
  const names = [];
  for (const [file, map] of Object.entries(readRegistry().names)) {
    for (const [name, meta] of Object.entries(map)) {
      if (meta && typeof meta.alias === 'string' && meta.alias.startsWith(`${service}/`)) names.push({ name, alias: meta.alias, file: file.replace(os.homedir(), '~') });
    }
  }
  return vault.list(`${service}/`).map((rec) => {
    const have = new Set(rec.fields.map(roleOf));
    return {
      alias: rec.alias,
      environment: rec.environment,
      status: rec.status,
      have: ROLES.filter((r) => have.has(r)),
      missing: ROLES.filter((r) => !have.has(r)),
      names: names.filter((n) => n.alias === rec.alias).map((n) => n.name).sort(),
    };
  });
}

function report(rawService) {
  const service = slug(rawService);
  if (!service) return { error: 'a service name is required', hint: 'keyfence conta <serviço>' };
  const accounts = accountsOf(service);
  const lines = [`service: ${service}`, `accounts: ${accounts.length}`];
  if (!accounts.length) {
    lines.push('empty: nothing saved for this service yet');
    lines.push('help[1]:', `  Paste in the chat: conta ${service}: login <e-mail>, senha: <senha>  (keyfence saves it and answers with the names)`);
    return { text: `${lines.join('\n')}\n` };
  }
  lines.push(`contas[${accounts.length}]{alias,environment,status,have,missing}:`);
  for (const a of accounts) lines.push(`  ${a.alias},${a.environment},${a.status},${a.have.join(' ') || '-'},${a.missing.join(' ') || '-'}`);
  const names = accounts.flatMap((a) => a.names.map((name) => ({ name, alias: a.alias })));
  if (names.length) {
    lines.push(`names[${names.length}]{name,account}:`);
    for (const n of names) lines.push(`  ${n.name},${n.alias}`);
  }
  lines.push('help[3]:',
    '  Work with the names ($NAME in commands); keyfence loads the values and never prints them',
    '  Missing token: only if the service has an API; missing recovery: paste "recuperação: <e-mail>" with the account',
    '  A service that asks for 2FA or a code by e-mail: that step is the user\'s, the session never asks for the code');
  return { text: `${lines.join('\n')}\n` };
}

module.exports = { report, accountsOf };
