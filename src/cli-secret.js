'use strict';
// `keyfence secret`: manage the vault. A value is only ever typed at a hidden
// prompt on a real terminal (/dev/tty). No flag, argument or pipe takes one, and
// no command prints one. Agents run tools without a terminal, so only a person
// can add or rotate a secret.

const fs = require('fs');
const tty = require('tty');
const vault = require('./vault');

const POLICY_FLAGS = ['--op', '--target', '--command', '--project', '--fill', '--auth', '--expires'];
const SUBS = {
  add: { flags: ['--env', '--field', '--exposed', ...POLICY_FLAGS], usage: 'keyfence secret add <alias> [--env dev|test|prod] [--field name]... [--op request|run|browser.fill]... [--target host]... [--command prog]... [--fill form=field]...' },
  rotate: { flags: [], usage: 'keyfence secret rotate <alias>' },
  list: { flags: [], usage: 'keyfence secret list [prefix]' },
  show: { flags: [], usage: 'keyfence secret show <alias>' },
  policy: { flags: POLICY_FLAGS, usage: 'keyfence secret policy <alias> --op ... --target ... (replaces the policy)' },
  revoke: { flags: [], usage: 'keyfence secret revoke <alias>' },
  reactivate: { flags: [], usage: 'keyfence secret reactivate <alias>' },
  rm: { flags: [], usage: 'keyfence secret rm <alias>' },
};
const BOOL = new Set(['--exposed']);
const MULTI = new Set(['--field', '--op', '--target', '--command', '--project', '--fill']);

function out(s) { process.stdout.write(`${s}\n`); }
function fail(msg, hint, code = 2) {
  out(`error: ${msg}${hint ? `\nhelp: ${hint}` : ''}`);
  process.exitCode = code;
}

function parse(sub, argv) {
  const spec = SUBS[sub];
  const flags = {};
  const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { args.push(a); continue; }
    if (!spec.flags.includes(a)) return { error: `unknown flag ${a} for \`secret ${sub}\``, hint: spec.usage };
    const k = a.slice(2);
    if (BOOL.has(a)) { flags[k] = true; continue; }
    const v = argv[++i];
    if (v === undefined) return { error: `${a} needs a value`, hint: spec.usage };
    if (MULTI.has(a)) (flags[k] = flags[k] || []).push(v); else flags[k] = v;
  }
  return { flags, args };
}

function policyOf(f) {
  const fill = {};
  for (const pair of f.fill || []) {
    const [form, field] = pair.split('=');
    fill[form] = field;
  }
  return { operations: f.op, targets: f.target, commands: f.command, projects: f.project, fill_map: fill, auth: f.auth, expires: f.expires };
}

// Hidden input from the controlling terminal. Throws without one.
function readHidden(label) {
  let fd;
  try {
    fd = fs.openSync('/dev/tty', 'r+');
  } catch {
    return Promise.reject(new Error('this needs a terminal: type the value in your own terminal, agents cannot add secrets'));
  }
  const input = new tty.ReadStream(fd);
  const output = new tty.WriteStream(fd);
  return new Promise((resolve, reject) => {
    const bytes = [];
    const done = (err) => {
      input.setRawMode(false);
      input.destroy();
      output.write('\n');
      output.destroy();
      if (err) { bytes.fill(0); reject(err); } else { const b = Buffer.from(bytes); bytes.fill(0); resolve(b); }
    };
    output.write(`${label} (hidden): `);
    input.setRawMode(true);
    input.on('data', (chunk) => {
      for (const c of chunk) {
        if (c === 3) return done(new Error('cancelled'));
        if (c === 13 || c === 10) return done(bytes.length ? null : new Error('empty value'));
        if (c === 127 || c === 8) bytes.pop(); else bytes.push(c);
      }
    });
  });
}

async function readFields(names, alias) {
  const fields = {};
  for (const name of names) fields[name] = await readHidden(names.length > 1 ? `${alias} ${name}` : alias);
  return fields;
}

function describe(d) {
  const p = d.policy;
  return [
    `secret: ${d.alias}`,
    `environment: ${d.environment}`,
    `status: ${d.status}`,
    `version: ${d.version}`,
    `fields: ${d.fields.join(',')}`,
    `exposed: ${d.exposed}`,
    `operations: ${p.operations.join(',') || 'none (nothing allowed yet)'}`,
    `targets: ${p.targets.join(',') || '-'}`,
    `commands: ${p.commands.join(',') || '-'}`,
    `projects: ${p.projects.join(',') || 'any'}`,
    `fill_map: ${Object.entries(p.fill_map).map(([k, v]) => `${k}=${v}`).join(',') || '-'}`,
    `last_used: ${d.lastUsed || 'never'}`,
    'value: never shown',
  ].join('\n');
}

const run = {
  async add(f, [alias]) {
    const fields = await readFields(f.field && f.field.length ? f.field : ['value'], alias);
    out(describe(vault.add(alias, fields, { environment: f.env, exposed: f.exposed, policy: policyOf(f) })));
  },
  async rotate(f, [alias]) {
    const cur = vault.show(alias);
    if (!cur) return fail(`no secret ${alias}`, 'keyfence secret list');
    out(describe(vault.rotate(alias, await readFields(cur.fields, alias))));
  },
  list(f, [prefix = '']) {
    const rows = vault.list(prefix);
    if (!rows.length) return out(`secrets: 0${prefix ? ` under ${prefix}` : ''} in the vault\nhelp[1]:\n  Run \`keyfence secret add <alias>\` in your own terminal`);
    out(`secrets[${rows.length}]{alias,environment,status,operations}:`);
    for (const r of rows) out(`  ${r.alias},${r.environment},${r.status},${r.policy.operations.join('|') || 'none'}`);
  },
  show(f, [alias]) {
    const d = vault.show(alias);
    if (!d) return fail(`no secret ${alias}`, 'keyfence secret list');
    out(describe(d));
  },
  policy(f, [alias]) { out(describe(vault.setPolicy(alias, policyOf(f)))); },
  revoke(f, [alias]) { out(describe(vault.revoke(alias))); },
  reactivate(f, [alias]) { out(describe(vault.reactivate(alias))); },
  rm(f, [alias]) { out(vault.remove(alias) ? `removed: ${alias} (all versions)` : `secret: ${alias} not found (no-op)`); },
};

async function main(argv) {
  const [sub, ...rest] = argv;
  if (!sub || !SUBS[sub]) return fail(sub ? `unknown subcommand ${sub}` : 'secret needs a subcommand', `subcommands: ${Object.keys(SUBS).join(', ')}`);
  const parsed = parse(sub, rest);
  if (parsed.error) return fail(parsed.error, parsed.hint);
  if (sub !== 'list' && !parsed.args[0]) return fail(`secret ${sub} needs an alias`, SUBS[sub].usage);
  try {
    await run[sub](parsed.flags, parsed.args);
  } catch (e) {
    fail(e.message, null, 1);
  }
}

module.exports = { main, SUBS };
