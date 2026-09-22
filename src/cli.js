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

function main(argv = process.argv.slice(2)) {
  const [cmd, ...rest] = argv;
  if (!cmd) return cmdHome();
  if (cmd === '--help' || cmd === '-h') {
    return process.stdout.write(`usage:\n${Object.values(COMMANDS).map((c) => `  ${c.usage}`).join('\n')}\n`);
  }
  if (!COMMANDS[cmd]) return fail(`unknown command ${cmd}`, `commands: ${Object.keys(COMMANDS).join(', ')}`);
  const parsed = parse(cmd, rest);
  if (parsed.error) return fail(parsed.error, parsed.hint);
  if (parsed.flags.help) return process.stdout.write(`usage: ${COMMANDS[cmd].usage}\n`);
  try {
    ({ scan: cmdScan, rules: cmdRules, install: cmdInstall, uninstall: cmdUninstall, config: cmdConfig })[cmd](parsed.flags, parsed.args);
  } catch (e) {
    fail(e.message, null, 1);
  }
}

module.exports = { main };
