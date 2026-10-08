'use strict';
// Shapes that are never a credential by themselves. A code identifier, a file
// name, an e-mail, a session name or a formatted number only becomes a secret
// through explicit context ("senha:", "token:", a credential field), never
// through how it looks. The opposite list, `strongShape`, is what stays
// protected when nothing can judge a word: a known provider prefix or a long
// random-looking run.

const { entropy } = require('./entropy');

// Dates, times, percentages and formatted numbers are data, not credentials. A
// message quoting a data window ("15/03/2024 a 28/02/2025") or a rate ("40,53%")
// held those words as pending for the whole session when the classifier was down.
// A digits-only PIN is not affected: the callers check it before this runs.
const FORMATTED = (w) => /^\d{1,2}[/.-]\d{1,2}(?:[/.-](?:\d{2}|\d{4}))?$/.test(w)
  || /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/.test(w)
  || /^\d{1,2}(?::\d{2}){1,2}$/.test(w) || /^\d{1,2}h\d{2}$/.test(w)
  || /^[+-]?\d{1,3}(?:([.,])\d{3})(?:\1\d{3})*(?:[.,]\d{1,2})?%?$/.test(w)
  || /^[+-]?\d+(?:[.,]\d+)?%$/.test(w) || /^[+-]?\d+,\d{1,2}$/.test(w);

// One word of a name: user, User, USER, each with up to four trailing digits.
const WORD = /^(?:[a-z]+|[A-Z][a-z]+|[A-Z]{2,})\d{0,4}$/;

// camelCase / PascalCase made of real syllable-sized words (updateUserByEmail,
// getHTTPResponse). Random letters switch case on single characters, so some
// piece comes out shorter than two letters.
const ACRONYM = /^(?:ID|IDS|URL|URI|HTTP|HTTPS|API|SQL|JSON|XML|HTML|CSS|UI|UUID|SDK|CPF|CNPJ|SMS|PDF|CSV|JWT|SSH|TCP|DNS|CLI|OTP|PIN)$/;

function isCamelIdentifier(w) {
  if (!/^[A-Za-z]+\d{0,4}$/.test(w) || !/[a-z][A-Z]/.test(w)) return false;
  const pieces = w.replace(/\d+$/, '').split(/(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])/);
  if (pieces.length < 2 || !pieces.every((p) => /^[A-Z]?[a-z]+$/.test(p) || ACRONYM.test(p)) || pieces.some((p) => p.length < 2)) return false;
  // Short joiners (By, To, Id) are fine between real words; a string made mostly
  // of them is random letters that happen to switch case.
  return pieces.filter((p) => p.length >= 4).length >= Math.max(2, Math.ceil(pieces.length / 2));
}

// snake_case, kebab-case, UPPER_SNAKE and dotted names: runs of words joined by
// - _ or . (user_id_42, config.db.host, max-width).
function isNameIdentifier(w) {
  const runs = w.split(/[-_.]/);
  return runs.length >= 2 && runs.every((r) => WORD.test(r) || isCamelIdentifier(r) || /^\d{1,4}$/.test(r))
    && runs.some((r) => /^[A-Za-z]{2,}/.test(r));
}

// Two or more uppercase words joined by hyphens: how sessions get named.
const isSessionName = (w) => /^[A-Z]{2,}\d{0,4}(?:-[A-Z]{2,}\d{0,4})+$/.test(w);

// `.env.local`, `.gitignore`, `next.config.mjs`, `relatorio-final.pdf`, `src/app/page.tsx`.
function isFileName(w) {
  const segs = w.split('/');
  const last = segs[segs.length - 1];
  if (!last || segs.some((s, i) => !s && i !== 0 && i !== segs.length - 1)) return false;
  const dir = segs.slice(0, -1).filter((s) => s && s !== '~' && s !== '.' && s !== '..');
  const stem = (s) => s.replace(/^\./, '').split(/[-_.]/).every((r) => WORD.test(r) || isCamelIdentifier(r) || /^\d{1,4}$/.test(r));
  if (dir.some((s) => !stem(s))) return false;
  if (/^\.[a-z][a-z0-9_.-]*$/.test(last)) return last.slice(1).split(/[-_.]/).every((r) => /^[a-z]+\d{0,4}$/.test(r));
  const dot = last.lastIndexOf('.');
  return dot > 0 && /^[a-z][a-z0-9]{0,5}$/.test(last.slice(dot + 1)) && stem(last.slice(0, dot)) && /[A-Za-z]{2}/.test(last.slice(0, dot));
}

// `auth/updateUserByEmail`, `src/app`, `~/projetos/keyfence`: a path whose every part is a word, an
// identifier or a file name. A base64 chunk with slashes has parts that are none of those.
function isPath(w) {
  if (!w.includes('/') || /\s/.test(w)) return false;
  const parts = w.split('/').filter((x) => x && x !== '~' && x !== '.' && x !== '..');
  const word = (x) => WORD.test(x) || isCamelIdentifier(x) || isNameIdentifier(x) || isFileName(x) || /^\d{1,4}$/.test(x);
  return parts.length >= 1 && parts.every((x) => word(x) && (x.match(/[A-Za-z]/g) || []).length >= 3);
}

// A pasted markup tag (`</nav-header>`, `<my-component>`): a placeholder, not a value.
const isMarkupTag = (w) => /^<\/?[A-Za-z][\w-]*(?:\s[^<>]*)?\/?>$/.test(w);

// Message ids of WhatsApp Web / multi-device (`3EB0` plus hex), which `central msgs`, logs and
// hand-offs quote all day. An id names a message; it grants nothing.
const isMessageId = (w) => /^3EB0[0-9A-F]{16,28}$/.test(w);

const isEmail = (w) => /^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$/.test(w);

/**
 * Which common form a word has, or null. Order matters only for the label.
 * A password that happens to look like one of these is still caught by an
 * explicit label ("senha: x"); only the shape alone says nothing.
 */
function commonForm(w) {
  const s = String(w);
  if (FORMATTED(s)) return 'formatted';
  if (isEmail(s)) return 'email';
  if (isMessageId(s)) return 'id';
  if (isFileName(s)) return 'file';
  if (isPath(s)) return 'path';
  if (isMarkupTag(s)) return 'markup';
  if (isSessionName(s)) return 'session';
  if (isCamelIdentifier(s)) return 'identifier';
  if (isNameIdentifier(s)) return 'name';
  return null;
}

// Provider prefixes that are credentials wherever they appear.
const KNOWN_PREFIX = /^(?:sk[-_]|pk_(?:live|test)_|rk_(?:live|test)_|gh[pousr]_|github_pat_|glpat-|xox[abprs]-|xapp-|AKIA|ASIA|AIza|ya29\.|eyJ|npm_|pypi-|SG\.|shpat_|hf_|gsk_|r8_|xai-|pplx-|whsec_|dop_v1_|sbp_|tskey-|ntn_|lin_api_|re_[A-Za-z0-9]{20,}$)/;

const classes = (s) => [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(s)).length;

/**
 * A word that stays protected even when no classifier is there to judge it: a
 * known provider prefix, or a long run of random-looking characters.
 */
function strongShape(w) {
  const s = String(w);
  if (KNOWN_PREFIX.test(s) && s.length >= 12) return true;
  if (commonForm(s)) return false;
  if (s.length >= 32 && classes(s) >= 3 && entropy(s) >= 3.5) return true;
  // Hex and UUID: an API key as often as a hash, and indistinguishable by shape.
  if (s.length >= 32 && /^[0-9a-f-]+$/i.test(s) && entropy(s) >= 3.3) return true;
  return s.length >= 40 && /^[A-Za-z0-9+/_=-]+$/.test(s) && entropy(s) >= 4;
}

module.exports = { FORMATTED, commonForm, strongShape, isCamelIdentifier, isNameIdentifier, isSessionName, isFileName, isEmail };
