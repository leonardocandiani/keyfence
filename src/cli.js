'use strict';
// keyfence CLI. Output is TOON on stdout; errors are structured on stdout with
// exit 2 for usage errors. Diagnostics, if any, go to stderr.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { scan, shape } = require('./detect');
const { rules } = require('./rules');
const config = require('./config');
const { VERSION } = require('./version');

const HOME = os.homedir();
const tilde = (p) => (p.startsWith(HOME) ? `~${p.slice(HOME.length)}` : p);
const HOOK_BIN = path.resolve(__dirname, '..', 'bin', 'keyfence-hook.js');
const EVENTS = ['UserPromptSubmit', 'PreToolUse', 'PostToolUse'];

// --- output helpers ------------------------------------------------------------

const q = (v) => {
  const s = String(v);
  return /[,\n":]|^\s|\s$/.test(s) ? JSON.stringify(s) : s;
};
function table(name, fields, rows) {
  const lines = [`${name}[${rows.length}]{${fields.join(',')}}:`];
  for (const r of rows) lines.push(`  ${fields.map((f) => q(r[f])).join(',')}`);
  return lines.join('\n');
}
function help(lines) {
  return lines.length ? `help[${lines.length}]:\n${lines.map((l) => `  ${l}`).join('\n')}` : '';
}
function fail(msg, hint, code = 2) {
  process.stdout.write(`error: ${msg}\n${hint ? `help: ${hint}\n` : ''}`);
  process.exitCode = code;
}

// --- argument parsing: every command declares its flags ------------------------

const COMMANDS = {
  scan: { flags: ['--ambiguous', '--full', '--json'], usage: 'keyfence scan <file|dir|-> [--ambiguous] [--full] [--json]' },
  rules: { flags: [], usage: 'keyfence rules' },
  install: { flags: ['--dry-run', '--settings'], usage: 'keyfence install [--dry-run] [--settings <path>]' },
  uninstall: { flags: ['--dry-run', '--settings'], usage: 'keyfence uninstall [--dry-run] [--settings <path>]' },
  config: { flags: [], usage: 'keyfence config' },
  maintain: { flags: ['--apply', '--install', '--uninstall'], usage: 'keyfence maintain [--apply] [--install|--uninstall]  (tidy, merge duplicates, list what to rotate; --install runs it daily)' },
  tidy: { flags: ['--apply'], usage: 'keyfence tidy [env-file...] [--apply]  (without --apply: show the plan only)' },
  secret: { flags: [], usage: 'keyfence secret add|rotate|list|show|policy|revoke|reactivate|rm (values only at a hidden terminal prompt)' },
};
const VALUE_FLAGS = new Set(['--settings']);

function parse(cmd, argv) {
  const spec = COMMANDS[cmd];
  const flags = {};
  const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { flags.help = true; continue; }
    if (a.startsWith('--')) {
      if (!spec.flags.includes(a)) {
        return { error: `unknown flag ${a} for \`${cmd}\``, hint: `valid flags for \`${cmd}\`: ${spec.flags.join(', ') || '(none)'}. usage: ${spec.usage}` };
      }
      flags[a.slice(2)] = VALUE_FLAGS.has(a) ? argv[++i] : true;
      if (VALUE_FLAGS.has(a) && !flags[a.slice(2)]) return { error: `${a} needs a value`, hint: spec.usage };
      continue;
    }
    args.push(a);
  }
  return { flags, args };
}

// --- settings.json (Claude Code) -----------------------------------------------

function settingsPath(flags) {
  return flags.settings ? path.resolve(flags.settings) : path.join(HOME, '.claude', 'settings.json');
}
function hookCommand() {
  return `node ${JSON.stringify(HOOK_BIN)}`;
}
function readSettings(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (e.code === 'ENOENT') return {};
    throw new Error(`cannot parse ${tilde(file)}: ${e.message}`);
  }
}
function isOurs(h) {
  return /keyfence-hook\.js/.test(String(h.command || ''));
}
function installedEvents(settings) {
  const hooks = settings.hooks || {};
  return EVENTS.filter((ev) => (hooks[ev] || []).some((e) => (e.hooks || []).some(isOurs)));
}

// --- commands --------------------------------------------------------------------

function cmdHome() {
  const cfg = config.load();
  let installed = [];
  let note = '';
  try {
    installed = installedEvents(readSettings(settingsPath({})));
  } catch (e) {
    note = e.message;
  }
  const jev = !cfg.jev.enabled ? 'off' : require('./jev').apiKey(cfg) ? 'on' : `on, but no key (set ${cfg.jev.apiKeyEnv} or write it to ${cfg.jev.apiKeyFile})`;
  const out = [
    `bin: ${tilde(path.resolve(__dirname, '..', 'bin', 'keyfence.js'))}`,
    'description: Keeps secrets from leaking out of AI coding agent sessions',
    `version: ${VERSION}`,
    `claude_code_hook: ${installed.length === EVENTS.length ? 'installed' : installed.length ? `partial (${installed.join(', ')})` : 'not installed'}${note ? ` (${note})` : ''}`,
    `rules: ${rules.length} provider rules + labeled values + entropy`,
    `prompt_mode: ${cfg.promptMode}`,
    `classifier: ${jev}`,
    `config: ${tilde(config.configPath())}${fs.existsSync(config.configPath()) ? '' : ' (not created, defaults in use)'}`,
    help([
      installed.length === EVENTS.length ? 'Run `keyfence scan <path>` to check files for secrets' : 'Run `keyfence install` to protect Claude Code sessions',
      'Run `keyfence scan -` to check text piped on stdin',
      'Run `keyfence rules` to list what is detected',
    ]),
  ];
  process.stdout.write(`${out.join('\n')}\n`);
}

function walk(p, acc) {
  const st = fs.statSync(p);
  if (st.isFile()) { acc.push(p); return acc; }
  for (const name of fs.readdirSync(p)) {
    if (name === 'node_modules' || name === '.git' || name === 'dist' || name === 'build') continue;
    walk(path.join(p, name), acc);
  }
  return acc;
}

function lineOf(text, idx) {
  let n = 1;
  for (let i = 0; i < idx; i++) if (text.charCodeAt(i) === 10) n++;
  return n;
}

// Scans the given paths; returns the findings or a usage error.
function collect(flags, args) {
  const rows = [];
  let files = 0;
  const each = (label, text) => {
    files++;
    const { findings, ambiguous } = scan(text, { ambiguous: !!flags.ambiguous });
    for (const f of [...findings, ...ambiguous]) {
      rows.push({ file: label, line: lineOf(text, f.start), rule: f.rule, confidence: f.confidence, shape: shape(f.value) });
    }
  };
  for (const a of args) {
    if (a === '-') { each('stdin', fs.readFileSync(0, 'utf8')); continue; }
    if (!fs.existsSync(a)) return { error: `no such file or directory: ${a}` };
    for (const f of walk(a, [])) {
      let text;
      try { text = fs.readFileSync(f, 'utf8'); } catch { continue; }
      if (!text.includes('\u0000')) each(tilde(path.resolve(f)), text); // skip binary
    }
  }
  return { rows, files };
}

function render(flags, args, rows, files) {
  if (flags.json) return `${JSON.stringify({ files, findings: rows })}\n`;
  const plural = files === 1 ? '' : 's';
  if (!rows.length) return `findings: 0 secrets in ${files} file${plural}\n`;
  const LIMIT = 50;
  const shown = flags.full ? rows : rows.slice(0, LIMIT);
  const tips = [];
  if (shown.length < rows.length) tips.push(`Run \`keyfence scan ${args.join(' ')} --full\` to see all ${rows.length}`);
  tips.push('Values are never printed; open the file at the line to review');
  return `count: ${shown.length} of ${rows.length} total in ${files} file${plural}\n${table('findings', ['file', 'line', 'rule', 'shape'], shown)}\n${help(tips)}\n`;
}

function cmdScan(flags, args) {
  if (!args.length) return fail('scan needs a path, or - for stdin', COMMANDS.scan.usage);
  const { rows, files, error } = collect(flags, args);
  if (error) return fail(error, COMMANDS.scan.usage);
  process.stdout.write(render(flags, args, rows, files));
  if (rows.length) process.exitCode = 1; // secrets found, like other scanners
}

function cmdRules() {
  process.stdout.write(`${table('rules', ['id', 'name'], rules)}\n${help(['Labeled values (token=, password:, senha:) and high-entropy strings are detected without a rule'])}\n`);
}

function cmdConfig() {
  const cfg = config.load();
  const view = {
    promptMode: cfg.promptMode,
    ttlHours: cfg.ttlHours,
    taintAmbiguousFromPrompt: cfg.taintAmbiguousFromPrompt,
    vaultPatterns: cfg._vault.length,
    egressAllowTools: cfg.egress.allowTools.length,
    blockNewSecretsInTrackedFiles: cfg.egress.blockNewSecretsInTrackedFiles,
    classifier: cfg.jev.enabled,
  };
  process.stdout.write(`config: ${tilde(config.configPath())}\n${Object.entries(view).map(([k, v]) => `${k}: ${v}`).join('\n')}\n`);
}

function writeSettings(file, settings) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file)) fs.copyFileSync(file, `${file}.bak-keyfence`);
  const tmp = `${file}.tmp-keyfence-${process.pid}`;
  fs.writeFileSync(tmp, `${JSON.stringify(settings, null, 2)}\n`);
  JSON.parse(fs.readFileSync(tmp, 'utf8'));
  fs.renameSync(tmp, file);
}

function cmdInstall(flags) {
  const file = settingsPath(flags);
  const settings = readSettings(file);
  settings.hooks = settings.hooks || {};
  const cmd = hookCommand();
  const changes = [];
  for (const ev of EVENTS) {
    const entries = settings.hooks[ev] = settings.hooks[ev] || [];
    const mine = entries.flatMap((e) => (e.hooks || []).filter(isOurs));
    if (mine.length && mine.every((h) => h.command === cmd)) continue;
    if (mine.length) { mine.forEach((h) => { h.command = cmd; }); changes.push(`${ev}: path repaired`); continue; }
    entries.push({ matcher: '*', hooks: [{ type: 'command', command: cmd, timeout: 10 }] });
    changes.push(`${ev}: added`);
  }
  if (!changes.length) return process.stdout.write(`install: already installed in ${tilde(file)} (no-op)\n`);
  if (!flags['dry-run']) writeSettings(file, settings);
  process.stdout.write(`install: ${flags['dry-run'] ? 'would change' : 'updated'} ${tilde(file)}\n${changes.map((c) => `  ${c}`).join('\n')}\n${help([
    'New and running sessions pick this up on their next tool call',
    'Run `keyfence` to check status',
  ])}\n`);
}

function cmdUninstall(flags) {
  const file = settingsPath(flags);
  const settings = readSettings(file);
  let removed = 0;
  for (const ev of Object.keys(settings.hooks || {})) {
    const before = settings.hooks[ev];
    settings.hooks[ev] = before
      .map((e) => ({ ...e, hooks: (e.hooks || []).filter((h) => !isOurs(h)) }))
      .filter((e) => e.hooks.length);
    removed += before.length - settings.hooks[ev].length;
    if (!settings.hooks[ev].length) delete settings.hooks[ev];
  }
  if (!removed) return process.stdout.write(`uninstall: not installed in ${tilde(file)} (no-op)\n`);
  if (!flags['dry-run']) writeSettings(file, settings);
  process.stdout.write(`uninstall: ${flags['dry-run'] ? 'would remove' : 'removed'} ${removed} hook entr${removed === 1 ? 'y' : 'ies'} from ${tilde(file)}\n`);
}

async function cmdMaintain(flags) {
  const m = require('./maintain');
  if (flags.install) { const r = m.install(); return process.stdout.write(`maintain: scheduled ${r.schedule}\nplist: ${tilde(r.plist)}\nlog: ${tilde(r.log)}\n`); }
  if (flags.uninstall) return process.stdout.write(m.uninstall() ? 'maintain: schedule removed\n' : 'maintain: no schedule installed (no-op)\n');
  const r = await m.maintain({ apply: Boolean(flags.apply) });
  const renamed = r.tidied.flatMap((t) => t.changes.map((c) => ({ file: tilde(t.file), old: c.old, record: c.alias, new: c.names.join(' ') })));
  const out = [`maintain: ${flags.apply ? 'applied' : 'plan only'} at ${new Date().toISOString()}`];
  out.push(renamed.length ? table('renamed', ['file', 'old', 'record', 'new'], renamed) : 'renamed: 0 generic names');
  const moved = r.synced.filter((x) => x.action !== 'unchanged' && x.action !== 'checked');
  out.push(moved.length ? table('vault', ['alias', 'action'], moved) : `vault: ${r.synced.length} credential(s) in step with their env files`);
  out.push(r.merged.length ? table('merged', ['kept', 'removed'], r.merged) : 'merged: 0 duplicates');
  if (r.unclear.length) out.push(`same_value_unclear[${r.unclear.length}]:\n${r.unclear.map((u) => `  ${u}`).join('\n')}`);
  out.push(`rotate_soon[${r.exposed.length}]: ${r.exposed.join(', ') || 'none'} (went through a chat)`);
  out.push(`unused_90_days[${r.stale.length}]: ${r.stale.join(', ') || 'none'}`);
  if (!flags.apply) out.push(help(['Run `keyfence maintain --apply` to make the changes', 'Run `keyfence maintain --install` to run it daily']));
  process.stdout.write(`${out.join('\n')}\n`);
}

// The project's .env and the private global file, when they exist.
function defaultEnvFiles() {
  let root = process.cwd();
  try { root = require('child_process').execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { /* not a repo */ }
  return [path.join(root, '.env'), path.join(HOME, '.config', 'keyfence', 'secrets.env')].filter((f) => fs.existsSync(f));
}

function tidyNotes(r) {
  const notes = [];
  if (r.unmatched.length) notes.push(`${tilde(r.file)}: ${r.unmatched.join(', ')} not found as a credential in any recent message; left as is`);
  if (r.backup) notes.push(`${tilde(r.file)}: backup at ${tilde(r.backup)}`);
  return notes;
}

async function cmdTidy(flags, args) {
  const { tidyFile } = require('./tidy');
  const files = args.length ? args.map((f) => path.resolve(f)) : defaultEnvFiles();
  if (!files.length) return process.stdout.write('tidy: no env file here\nhelp[1]:\n  Run `keyfence tidy <path/to/.env>`\n');
  const verb = flags.apply ? '' : 'would be ';
  const rows = [];
  const notes = [];
  for (const f of files) {
    const r = await tidyFile(f, { apply: Boolean(flags.apply) });
    for (const c of r.changes) rows.push({ file: tilde(f), old: c.old, record: c.alias, new: c.names.join(' '), action: verb + c.action });
    notes.push(...tidyNotes(r));
  }
  process.stdout.write(renderTidy(rows, notes, Boolean(flags.apply)));
}

function renderTidy(rows, notes, applied) {
  const out = [rows.length ? table('changes', ['file', 'old', 'record', 'new', 'action'], rows) : 'changes: 0 generic names to fix'];
  if (notes.length) out.push(`notes[${notes.length}]:\n${notes.map((n) => `  ${n}`).join('\n')}`);
  if (!applied && rows.length) out.push(help(['Run `keyfence tidy --apply` (same arguments) to make these changes']));
  return `${out.join('\n')}\n`;
}

function main(argv = process.argv.slice(2)) {
  const [cmd, ...rest] = argv;
  if (!cmd) return cmdHome();
  if (cmd === '--help' || cmd === '-h') {
    return process.stdout.write(`usage:\n${Object.values(COMMANDS).map((c) => `  ${c.usage}`).join('\n')}\n`);
  }
  if (!COMMANDS[cmd]) return fail(`unknown command ${cmd}`, `commands: ${Object.keys(COMMANDS).join(', ')}`);
  if (cmd === 'secret') return require('./cli-secret').main(rest);
  const parsed = parse(cmd, rest);
  if (parsed.error) return fail(parsed.error, parsed.hint);
  if (parsed.flags.help) return process.stdout.write(`usage: ${COMMANDS[cmd].usage}\n`);
  try {
    const res = ({ scan: cmdScan, rules: cmdRules, install: cmdInstall, uninstall: cmdUninstall, config: cmdConfig, tidy: cmdTidy, maintain: cmdMaintain })[cmd](parsed.flags, parsed.args);
    if (res && res.catch) res.catch((e) => fail(e.message, null, 1));
  } catch (e) {
    fail(e.message, null, 1);
  }
}

module.exports = { main };
