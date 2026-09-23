'use strict';
// Optional classifier (TypeSafe jev) for prompts the rules cannot decide.
//
// Privacy contract, enforced here and covered by tests: the request NEVER
// contains a candidate value. Every word that could be a secret (mixed letters
// and digits, or long random-looking) is replaced by its shape before the text
// leaves the machine. The classifier judges intent from the words around it:
// "a senha do banco é aaaaaa999" is a password disclosure whatever the value is.

const fs = require('fs');
const os = require('os');
const { shape, entropy } = require('./detect');

function apiKey(cfg) {
  if (process.env[cfg.jev.apiKeyEnv]) return process.env[cfg.jev.apiKeyEnv];
  if (!cfg.jev.apiKeyFile) return null;
  try {
    return fs.readFileSync(cfg.jev.apiKeyFile.replace(/^~(?=\/)/, os.homedir()), 'utf8').trim() || null;
  } catch {
    return null;
  }
}

// Design tokens and code identifiers: `--color-primary-500`, `max-width`, `primary-500`.
// Labels (`senha:`), emails and URLs are context, not the secret itself.
const looksLikeIdentifier = (w) => w.startsWith('--') || /^[a-z]+(?:[-_.](?:[a-z]+|[0-9]+))+$/.test(w)
  || /[:=]$/.test(w) || /^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$/.test(w) || w.startsWith('http://') || w.startsWith('https://')
  || w.startsWith('/') || w.startsWith('~/');

// A word is a candidate if it could plausibly be a credential.
function isCandidate(w) {
  if (w.length < 6 || w.length > 256 || looksLikeIdentifier(w)) return false;
  // Accented letters are letters: "proteção" is a word, not a password.
  const letters = /\p{L}/u.test(w);
  const digits = /[0-9]/.test(w);
  const symbols = /[^\p{L}\p{N}]/u.test(w);
  if (digits && (letters || symbols)) return true;
  return (letters && symbols && w.length >= 8) || entropy(w) >= 3.5;
}

function mask(text) {
  const candidates = [];
  const masked = text.replace(/[^\s"'`,;()[\]{}<>]+/g, (w) => {
    if (!isCandidate(w)) return w;
    candidates.push(w);
    return `⟨${shape(w)}⟩`;
  });
  return { masked, candidates };
}

// Cheap gate: only call the classifier when the prompt even talks about access.
const CUE = /\b(senha|password|passwd|pass|token|key|chave|secret|segredo|login|acesso|access|credential|credencial|pin|api|auth|bearer|contraseña|clave)\b/i;

async function classify(text, cfg) {
  const key = apiKey(cfg);
  if (!cfg.jev.enabled || !key || !CUE.test(text)) return null;
  const { masked, candidates } = mask(text.slice(0, 4000));
  if (!candidates.length) return null;

  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), cfg.jev.timeoutMs);
  try {
    const res = await fetch(cfg.jev.endpoint, {
      method: 'POST',
      signal: ctl.signal,
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.jev.model,
        state: { message: masked, note: 'Values between ⟨ ⟩ were replaced by their shape: a=lowercase, A=uppercase, 9=digit.' },
        questions: {
          shares_secret: {
            type: 'noul',
            instructions: 'Does `message` disclose a password, API key, token or other credential through one of the ⟨masked⟩ values?',
          },
        },
      }),
    });
    if (!res.ok) return null;
    const j = await res.json();
    const p = j && j.answers && j.answers.shares_secret && j.answers.shares_secret.noul;
    if (typeof p !== 'number') return null;
    return { probability: p, isSecret: p >= cfg.jev.threshold, candidates };
  } catch {
    return null; // timeout or network: fail open, rules already ran
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { classify, mask, isCandidate, apiKey };
