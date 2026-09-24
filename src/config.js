'use strict';
// Configuration: defaults merged with ~/.config/keyfence/config.json (or the
// file in KEYFENCE_CONFIG). Every key is optional in the user file.

const fs = require('fs');
const os = require('os');
const path = require('path');

const DEFAULTS = {
  // What happens when a secret is pasted in the prompt:
  //   "capture" -> save it to an env file under a name and let the session go on
  //                using the name (the default)
  //   "warn"    -> register it (hash only) and tell the agent to treat it as secret
  //   "block"   -> refuse the prompt; the user re-sends without the value
  promptMode: 'capture',
  capture: {
    // "project": the repo's .env when git ignores it, else globalFile.
    // "global": always globalFile.
    target: 'project',
    globalFile: '~/.config/keyfence/secrets.env',
    // Load captured variables into a Bash command that references them.
    inject: true,
  },
  // Replace remembered secrets in tool output before the agent sees it.
  redactOutput: true,
  // Where `discover` and the daily `maintain` look for credentials already on disk.
  discover: { roots: ['~'], depth: 5 },
  // Hours a tainted secret stays protected in a session.
  ttlHours: 12,
  // Taint high-entropy strings with no label or known prefix when they appear in
  // the user's prompt. Never applied to tool output (too many random ids there).
  taintAmbiguousFromPrompt: true,
  vault: {
    // Reading these prints the secret into the transcript. Using them is fine.
    patterns: [
      '(^|/)\\.credentials\\.json$',
      '(^|/)\\.aws/credentials$',
      '(^|/)\\.ssh/id_[a-z0-9_]+$',
      '(^|/)\\.pgpass$',
      '(^|/)\\.netrc$',
      '(^|/)\\.npmrc$',
      '(^|/)\\.pypirc$',
      '(^|/)\\.git-credentials$',
      '(^|/)\\.docker/config\\.json$',
      '(^|/)application_default_credentials\\.json$',
      '(^|/)\\.env(\\.(?!example$|sample$|template$|dist$)[A-Za-z0-9_.-]+)?$',
      '(^|/)\\.config/keyfence/secrets\\.env$',
      '(^|/)\\.config/keyfence/vault(/|$)',
    ],
    extraPatterns: [],
  },
  egress: {
    // MCP tools always leave the machine. These are allowed to receive a secret
    // because their purpose is storing one (regex on the full tool name).
    allowTools: ['__(create|edit|update)_(project_)?env', '__(create|update)_shared_env_variable$', '__set_secret$'],
    // Block writing a NEW high-confidence secret (not only tainted ones) into a
    // file that git tracks.
    blockNewSecretsInTrackedFiles: true,
  },
  // Optional classifier for ambiguous prompts. It only ever receives the SHAPE of
  // candidate values (aaAA99...) and the surrounding words with values removed.
  jev: {
    enabled: false,
    endpoint: 'https://api.typesafe.ai/v1/systemone',
    apiKeyEnv: 'TYPESAFE_API_KEY',
    // Hooks do not inherit your shell, so a file is usually the practical source.
    apiKeyFile: '~/.config/typesafe/api-key',
    model: 'jev-latest',
    timeoutMs: 4000,
    // Per-word judgement runs in the background after the prompt, so it may take
    // longer; a word is a secret at this probability or above.
    jobTimeoutMs: 15000,
    pickThreshold: 0.5,
    // Below pickThreshold but at or above this, a word is not saved but stays
    // protected: "use this: x7Kq..." with no context is unclear, not safe.
    keepThreshold: 0.2,
    threshold: 0.18, // calibrated: disclosures 0.22-0.59, ordinary talk 0.04-0.12 (test/jev-calibrate.js)
  },
};

function merge(a, b) {
  if (!b || typeof b !== 'object' || Array.isArray(b)) return b === undefined ? a : b;
  const out = { ...a };
  for (const k of Object.keys(b)) out[k] = merge(a ? a[k] : undefined, b[k]);
  return out;
}

function configPath() {
  return process.env.KEYFENCE_CONFIG || path.join(os.homedir(), '.config', 'keyfence', 'config.json');
}

function load() {
  let user = {};
  try {
    user = JSON.parse(fs.readFileSync(configPath(), 'utf8'));
  } catch { /* no user config: defaults */ }
  const cfg = merge(DEFAULTS, user);
  cfg._vault = [...cfg.vault.patterns, ...cfg.vault.extraPatterns].map((p) => new RegExp(p));
  cfg._allowTools = cfg.egress.allowTools.map((p) => new RegExp(p));
  return cfg;
}

module.exports = { load, configPath, DEFAULTS };
