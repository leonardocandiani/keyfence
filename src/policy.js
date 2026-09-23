'use strict';
// Policy of a vault secret: what may be done with it, where, from which project.
// Default deny: an empty policy allows nothing. Validation is strict so a policy
// that would let a caller print the value (a shell, an interpreter) never lands.

const OPERATIONS = ['request', 'run', 'browser.fill'];
// Programs that would print whatever they are given: never allowed to receive a secret.
const SHELLS = /^(?:sh|bash|zsh|fish|dash|ksh|csh|tcsh|env|xargs|node|nodejs|bun|deno|python\d*(?:\.\d+)?|ruby|perl|php|lua|osascript|awk|gawk|sed|cat|echo|printf|tee)$/;
const HOST = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function validatePolicy(p, fields) {
  const out = {
    operations: operations(p.operations),
    targets: arr(p.targets).map(host),
    commands: arr(p.commands).map(command),
    projects: arr(p.projects).map(String),
    fill_map: fillMap(p.fill_map, fields),
    auth: auth(p.auth),
    expires: expires(p.expires),
  };
  requirements(out);
  return out;
}

function operations(list) {
  const ops = arr(list);
  const bad = ops.find((op) => !OPERATIONS.includes(op));
  if (bad) throw new Error(`unknown operation "${bad}": use ${OPERATIONS.join(', ')}`);
  return ops;
}

function host(t) {
  const h = String(t).toLowerCase();
  if (!HOST.test(h)) throw new Error(`target "${t}" is not a hostname (like api.example.com or *.example.com)`);
  return h;
}

function command(c) {
  if (SHELLS.test(String(c).split('/').pop())) throw new Error(`"${c}" would print the secret: shells, interpreters and printers are never allowed`);
  return String(c);
}

function fillMap(map, fields) {
  const out = {};
  for (const [formField, secretField] of Object.entries(map || {})) {
    if (!fields.includes(secretField)) throw new Error(`fill_map uses unknown field "${secretField}"`);
    out[formField] = secretField;
  }
  return out;
}

function auth(a) {
  if (!a) return null;
  if (!/^(?:bearer|basic|header:[A-Za-z0-9-]+|query:[A-Za-z0-9_]+)$/.test(a)) throw new Error(`auth "${a}" must be bearer, basic, header:<Name> or query:<name>`);
  return a;
}

function expires(e) {
  if (!e) return null;
  if (Number.isNaN(Date.parse(e))) throw new Error(`expires "${e}" is not a date`);
  return e;
}

// Each operation needs the part of the policy that bounds it.
function requirements(p) {
  const need = [
    ['request', p.targets.length, 'request needs at least one target host'],
    ['run', p.commands.length, 'run needs at least one allowed command'],
    ['browser.fill', p.targets.length && Object.keys(p.fill_map).length, 'browser.fill needs a target domain and a fill_map'],
  ];
  for (const [op, ok, msg] of need) if (p.operations.includes(op) && !ok) throw new Error(msg);
}

const arr = (x) => (x === undefined || x === null ? [] : Array.isArray(x) ? x : [x]);

// Does the policy allow this use? Returns null when allowed, else the reason.
function check(policy, { operation, host, command, cwd, now = new Date() }) {
  if (!policy.operations.includes(operation)) return `operation ${operation} is not allowed for this secret`;
  if (policy.expires && now > new Date(policy.expires)) return 'the secret expired';
  if (policy.projects.length && !policy.projects.some((p) => cwd && (cwd === p || cwd.startsWith(`${p}/`)))) return `not allowed from ${cwd || 'this directory'}`;
  if (host !== undefined && !policy.targets.some((t) => (t.startsWith('*.') ? host.endsWith(t.slice(1)) : host === t))) return `host ${host} is not an allowed target`;
  if (command !== undefined && !policy.commands.includes(command)) return `command ${command} is not allowed`;
  return null;
}

module.exports = { validatePolicy, check, OPERATIONS };
