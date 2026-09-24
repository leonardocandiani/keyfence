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

// --- per-word judgement ------------------------------------------------------
// The rules decide what they recognize; everything else that could be a
// credential goes to the classifier one word at a time, masked, so it answers
// "which word" and not only "is there one". Emails are candidates here: an email
// can be the password. Context decides, not the shape.
const NOT_A_VALUE = (w) => w.startsWith('--') || /[:=]$/.test(w) || /^https?:\/\//.test(w)
  || /^[~./]/.test(w) || /^v?\d+(?:\.\d+)+$/.test(w) || /^\d{1,7}$/.test(w)
  || /\.(?:js|ts|tsx|jsx|md|json|py|sh|html|css|png|jpg|pdf|txt)$/i.test(w)
  || /^\p{Ll}+(?:[-_.]\p{Ll}+)*$/u.test(w);

function mayBeSecret(w, cue = false) {
  // A PIN or numeric password is a candidate only when the message talks about access.
  if (cue && /^\d{4,12}$/.test(w)) return true;
  if (w.length < 6 || w.length > 256 || NOT_A_VALUE(w)) return false;
  const digits = /[0-9]/.test(w);
  const symbols = /[^\p{L}\p{N}]/u.test(w);
  const mixedCase = /\p{Ll}\p{Lu}|\p{Lu}\p{Ll}+\p{Lu}/u.test(w);
  return digits || symbols || mixedCase || entropy(w) >= 3.5;
}

// Candidate words of a prompt, most random-looking first, capped.
function candidatesOf(text, skip = [], max = 12) {
  const seen = new Set(skip);
  const out = [];
  const cue = CUE.test(text);
  for (const raw of String(text).match(/[^\s"'`,;()[\]{}<>]+/g) || []) {
    // Sentence punctuation ends a word; `!` often ends a password, so it stays.
    const w = raw.replace(/[.,:;?]+$/, '');
    if (seen.has(w) || !mayBeSecret(w, cue)) continue;
    seen.add(w);
    out.push(w);
  }
  return out.sort((a, b) => entropy(b) * b.length - entropy(a) * a.length).slice(0, max);
}

// Worth a classifier call: the message talks about access, or a candidate looks
// like a credential on its own (long, or three kinds of character).
const KINDS3 = (w) => [/\p{Ll}/u, /\p{Lu}/u, /[0-9]/, /[^\p{L}\p{N}]/u].filter((re) => re.test(w)).length >= 3;
function worthAsking(text, cands) {
  return cands.length > 0 && (CUE.test(text) || cands.some((c) => c.length >= 16 || (c.length >= 8 && KINDS3(c))));
}

// Longest first, so a candidate inside another is not masked twice.
function maskIds(text, cands) {
  let masked = text;
  [...cands].map((c, i) => [c, i]).sort((a, b) => b[0].length - a[0].length)
    .forEach(([c, i]) => { masked = masked.split(c).join(`⟨c${i + 1}:${shape(c)}⟩`); });
  return masked;
}

const LOGIN_Q = 'Is ⟨ID⟩ in `message` the username, login or email used to sign in, given together with a password?';
const PICK = 'Is ⟨ID⟩ in `message` a secret the user is sharing: a password, API key, token or other credential that grants access? '
  + 'Usernames, emails used only as logins, ids, hashes, commit SHAs, plates and codes are not secrets unless the message uses them as the password.';

/**
 * Judge each candidate from its context. Returns [{value, p}], or null when the
 * classifier is unavailable (no key, timeout, error): the caller fails safe.
 */
async function judge(text, cands, cfg) {
  const key = apiKey(cfg);
  if (!key || !cands.length) return null;
  const questions = {};
  cands.forEach((c, i) => {
    questions[`c${i + 1}`] = { type: 'noul', instructions: PICK.replace('ID', `c${i + 1}`) };
    questions[`l${i + 1}`] = { type: 'noul', instructions: LOGIN_Q.replace('ID', `c${i + 1}`) };
  });
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), cfg.jev.jobTimeoutMs || 15000);
  try {
    const res = await fetch(cfg.jev.endpoint, {
      method: 'POST',
      signal: ctl.signal,
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: cfg.jev.model,
        state: { message: maskIds(text.slice(0, 8000), cands), note: 'Values between ⟨ ⟩ were replaced by an id and their shape: a=lowercase, A=uppercase, 9=digit.' },
        questions,
      }),
    });
    if (!res.ok) return null;
    const j = await res.json();
    const a = (j && j.answers) || {};
    const out = cands.map((value, i) => ({ value, p: a[`c${i + 1}`] && a[`c${i + 1}`].noul, login: (a[`l${i + 1}`] && a[`l${i + 1}`].noul) || 0 }));
    return out.every((x) => typeof x.p === 'number') ? out : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { classify, mask, isCandidate, apiKey, judge, candidatesOf, maskIds, mayBeSecret, worthAsking, CUE };
