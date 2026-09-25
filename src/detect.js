'use strict';
// Detection engine. Three layers, from most to least certain:
//   1. provider rules (rules.js): known shapes, high confidence
//   2. labeled values: `token=...`, `"password": "..."`, `senha: ...` with an
//      entropy floor and a placeholder filter, medium confidence
//   3. ambiguous candidates: long high-entropy strings with no label and no
//      known prefix, low confidence. Returned separately; the caller decides
//      what to do with them (keyfence only taints them when they come from the
//      user's own prompt, or when the optional classifier says so).

const { rules } = require('./rules');

// Labels in English, Portuguese and Spanish. The value is the first run of
// non-space, non-quote characters after the separator.
// Label, separator and optional opening quote; then the value. In a message the
// value may start with anything but a space or quote (its end is found from the
// message's syntax); in code it must open with 8 plain characters, as quotes,
// brackets and commas there are the language's own syntax.
const LABEL_HEAD = /(?:^|[^A-Za-z0-9])((?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|pass|senha|contrasena|contraseña|secret|segredo|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|credencial|chave|bearer))["']?\s*(?:[:=]|=>|:=)\s*(["'`]?)/.source;
const LABEL = new RegExp(LABEL_HEAD + /([^\s"'`][^\s"'`,;()[\]{}<>]*)(\(?)/.source, 'gi');
const LABEL_CODE = new RegExp(LABEL_HEAD + /([^\s"'`,;()[\]{}<>]{8,})(\(?)/.source, 'gi');

// Values that look like placeholders, references or code, never a real secret.
// Each one is the whole value's shape, never a prefix: `my_Dog2024!` is a
// password even though `my_api_key` is an example.
const PLACEHOLDER = new RegExp(`^(?:${[
  '[xX*.#-]{3,}', // xxxx, ****
  '<[\\w\\s.-]+>', // <your-password>
  '\u27e8.*', // a value keyfence already replaced: \u27e8NAME\u27e9
  '\\{\\{.*\\}\\}', // {{ secret }}
  '\\$\\{?[A-Za-z_][A-Za-z0-9_]*\\}?', // $VAR, ${VAR}
  '\\$\\(.*\\)', // $(command)
  '(?:process\\.env|import\\.meta\\.env)(?:\\.[A-Za-z_]\\w*|\\[.*\\])',
  'os\\.environ(?:\\[.*\\]|\\.get\\(.*\\))',
  '(?:os\\.)?(?:env|getenv)\\(.*\\)',
  'secrets\\.[A-Za-z_][\\w.]*',
  '(?:vault:|op:\\/\\/|ssm:|arn:aws:)\\S+',
  '(?:true|false|null|none|nil|undefined|required|optional|string|number|redacted|changeme|placeholder|dummy|test123|password1?2?3?|senha1?2?3?)',
  '(?:your|my|example|exemplo|sample|fake|test|replace|insert|put)[_-][A-Za-z_-]+', // your_api_key
].join('|')})$`, 'i');

function entropy(s) {
  if (!s) return 0;
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function classes(s) {
  let n = 0;
  if (/[a-z]/.test(s)) n++;
  if (/[A-Z]/.test(s)) n++;
  if (/[0-9]/.test(s)) n++;
  if (/[^A-Za-z0-9]/.test(s)) n++;
  return n;
}

// Shapes that are long and random-looking but are not secrets in practice.
function benignShape(s) {
  return /^[0-9a-f]{7,64}$/i.test(s) // git SHA, content hash
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s) // UUID
    || /^\d+$/.test(s)
    || /^(?:sha(?:1|256|384|512)|md5)-/i.test(s) // SRI integrity
    || /^[./~]|\/.*\//.test(s) // path
    || /^[a-z]+:\/\//i.test(s) // URL (credentials in URLs are a provider rule)
    || /^[a-z]*(?:[A-Z][a-z]{2,}){2,}[0-9]{0,2}$/.test(s) // CamelCaseIdentifier (real words, not random letters)
    || /^[a-z]+(?:[_-][a-z]+){2,}$/.test(s); // snake_or_kebab_identifier
}

function caseSwitches(v) {
  let n = 0;
  for (let i = 1; i < v.length; i++) {
    const a = v[i - 1] >= 'a' && v[i - 1] <= 'z';
    const b = v[i] >= 'a' && v[i] <= 'z';
    if (a !== b) n++;
  }
  return n;
}

// Common weak or default passwords that appear in examples and install scripts.
const DEFAULTS = /^(?:password|passw0rd|postgres|mysql|root|admin|administrator|secret|changeme|senha|default|guest|user|test|pass|qwerty|letmein|welcome|12345678|123456789|p@ssw0rd)$/i;

// Does a captured value look like a real secret rather than code or prose?
const HEXLIKE = /^(?:[0-9a-f]{16,128}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

// `labeled` is true when a label (api-key, token, senha...) or a URL parameter
// already says the value is a credential: then a hex or UUID value is a key,
// not a commit hash.
const PASSWORD_LABEL = /senha|pass|pwd|contrase|\bpin\b/i;

// A value that is wholly something other than a secret: a reference to one
// ($VAR, config.db.pass, getPassword()), an identifier or a path.
function isReference(v) {
  return /^\$\{?[A-Z_][A-Z0-9_]*\}?$/i.test(v) // $VAR / ${VAR}
    || /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) // member access
    || /^[A-Za-z_$][\w$.]*\(.*\)[;,]?$/.test(v) // call
    || /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+\/?$/.test(v) // lowercase path or alias: service/api
    || /^[#.][a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/.test(v) // CSS selector: #sip-password, .login-field
    || (/^[A-Za-z]+(?:[_-][A-Za-z]+)+$/.test(v) && v.split(/[_-]/).every((w) => /^(?:[a-z]+|[A-Z][a-z]*|[A-Z]+)$/.test(w))); // snake_case, UPPER_SNAKE, kebab
}

// `message` is true for what a person typed: there `Senha: joao.silva99` is the
// password, while in a file the same shape is code (`password: config.db`).
function looksSecret(v, labeled = false, message = false) {
  // In what a person typed, a password label already says what the value is: any
  // character goes, only a value that is wholly something else (a placeholder,
  // an example) is left out. In code the word sits in keys, ternaries and
  // comparisons (`'password' : /TOKEN$/.test(n)`), so there the value is judged.
  const passwordLabel = typeof labeled === 'string' && PASSWORD_LABEL.test(labeled);
  if (passwordLabel && message) return !!v && v.length >= 6 && !PLACEHOLDER.test(v) && !DEFAULTS.test(v);
  if (!v || v.length < 8 || PLACEHOLDER.test(v) || DEFAULTS.test(v)) return false;
  if (labeled && HEXLIKE.test(v)) return true;
  if (benignShape(v)) return false;
  // Under a label, a long value whose case flips like random text is a token even
  // when it happens to end in digits after a `_` (the name_v2 rule below).
  if (labeled && v.length >= 20 && caseSwitches(v) >= 6 && entropy(v) >= 3.5) return true;
  // Chained assignment in docs (`auth: SESSION_TTL=3600`): judge the right side.
  const asg = /^[A-Z][A-Z0-9_]*=(.+)$/.exec(v);
  if (asg) return looksSecret(asg[1]);
  if (/\$(?:\{|[A-Za-z_]|$)/.test(v)) return false; // template or shell reference: ${X}, $X, trailing $
  if (/^__[A-Za-z]+__|\.\.\.|…/.test(v)) return false; // __PLACEHOLDER__, truncated example
  if (/==(?!=*$)|[?]|&&|\|\|/.test(v)) return false; // code expression, not a value
  if (/^[a-z]+(?:[_-][a-z]+)+[_-]?\d{1,4}$/i.test(v)) return false; // name_v2, retry-count-3
  if (isReference(v) && !/\(/.test(v)) return false;
  const h = entropy(v);
  // Under a label a weak password is still a password (robson9999): lower floor.
  const floor = labeled ? 2.2 : v.length < 16 ? 2.8 : 3.0;
  if (/^[A-Za-z]+$/.test(v)) {
    // Under a password label a word is the password ("senha: flamengo"); under
    // token or key it is more likely a field name ("token": "Categoria").
    if (passwordLabel) return v.length >= 6;
    // A word (word, Word, WORD) is not a secret; random letters switch case often.
    if (/^(?:[a-z]+|[A-Z][a-z]+|[A-Z]+)$/.test(v)) return false;
    return caseSwitches(v) >= 3 && h >= floor;
  }
  return h >= floor && (v.length >= 16 || classes(v) >= 2);
}

// A JWT whose payload says role=anon is a Supabase publishable key: public by
// design, shipped in every frontend bundle.
function publicJwt(v) {
  const part = v.split('.')[1];
  if (!part) return false;
  try {
    const payload = JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    return payload && payload.role === 'anon';
  } catch {
    return false;
  }
}

function scanRules(text, lower) {
  const out = [];
  for (const r of rules) {
    if (r.keywords.length && !r.keywords.some((k) => lower.includes(k))) continue;
    r.re.lastIndex = 0;
    let m;
    while ((m = r.re.exec(text))) {
      const value = m[r.group] || m[0];
      if (r.weak && !looksSecret(value)) continue;
      if (r.id === 'jwt' && publicJwt(value)) continue;
      if (r.id === 'aws-access-key' && value.endsWith('EXAMPLE')) continue; // AWS documentation key
      const start = m.index + (r.group ? m[0].indexOf(value) : 0);
      out.push({ rule: r.id, name: r.name, value, start, end: start + value.length, confidence: 'high' });
      if (m[0].length === 0) r.re.lastIndex++;
    }
  }
  return out;
}

// Where a value ends comes from the message's syntax, never from what the value
// holds: a password can carry any printable character. A value alone at the end
// of its line, after a label or on a line of its own, is taken exactly as written.
// In running text, sentence punctuation glued to it and a bracket or quote it
// does not open come off: "a senha é X, e o login..." or "(senha X)".
const OPENER = { ')': '(', ']': '[', '}': '{', '>': '<' };
const CLOSER = { '(': ')', '[': ']', '{': '}', '<': '>' };
function edgeOf(before, tok, after) {
  if (!after.trim() && (!before.trim() || /[:=]\s*$/.test(before))) return tok;
  let w = tok;
  for (let prev = ''; prev !== w && w;) {
    prev = w;
    w = w.replace(/[.,;:?]+$/, '');
    const first = w[0];
    const last = w[w.length - 1];
    if (w.length > 1 && (CLOSER[first] === last || (/["'`]/.test(first) && first === last))) w = w.slice(1, -1);
    else if (OPENER[last] && !w.includes(OPENER[last])) w = w.slice(0, -1);
    else if (CLOSER[first] && !w.includes(CLOSER[first])) w = w.slice(1);
    else if (/["'`]/.test(last) && w.indexOf(last) === w.length - 1) w = w.slice(0, -1);
    else if (/["'`]/.test(first) && w.lastIndexOf(first) === 0) w = w.slice(1);
  }
  return w;
}

// A quote before the value opens it only when the same quote closes it on that
// line (an escaped quote does not); otherwise the quote belongs to the value.
function fullValue(text, at, quote) {
  const lineStart = text.lastIndexOf('\n', at - 1) + 1;
  const lineEnd = text.indexOf('\n', at) < 0 ? text.length : text.indexOf('\n', at);
  const line = text.slice(at, lineEnd);
  // It closes where the value ends: before a space, a separator or the line end.
  if (quote) {
    const close = new RegExp(`(?<!\\\\)\\${quote}(?=$|[\\s,;)}\\]])`).exec(line);
    if (close) return { value: line.slice(0, close.index), start: at };
  }
  const from = quote ? at - 1 : at;
  const tok = /^\S*/.exec(text.slice(from, lineEnd))[0];
  const value = edgeOf(text.slice(lineStart, from), tok, text.slice(from + tok.length, lineEnd));
  return { value, start: from + tok.indexOf(value) };
}

// Code: the token goes on past the plain start when it has no space; trailing
// punctuation and quotes come off, a closing quote ends a quoted value, and a
// second `=` means chained assignments, not one value.
function codeValue(text, at, quote, raw) {
  const rest = text.slice(at, at + 256);
  if (quote) {
    const close = rest.indexOf(quote);
    return close >= raw.length ? rest.slice(0, close) : raw;
  }
  const tok = /^\S+/.exec(rest)[0].replace(/[,;.:)\]}>'"`]+$/, '');
  return (/=/.test(tok.slice(raw.length)) ? raw : tok).replace(/[.:]+$/, '');
}

function scanLabeled(text, message = false) {
  const out = [];
  const re = message ? LABEL : LABEL_CODE;
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text))) {
    const [, label, quote, raw, call] = m;
    const at = m.index + m[0].length - raw.length - call.length;
    let value;
    let start = at;
    if (message) {
      ({ value, start } = fullValue(text, at, quote));
      // `token = getToken(user, x)` reads as code even in a message; `Senha: ab9(Xy`
      // alone on its line does not.
      if (call && !quote && /^[A-Za-z_$][\w$.]*$/.test(raw) && text.slice(start + value.length).split('\n')[0].trim()) continue;
    } else {
      if (call || PLACEHOLDER.test(raw)) continue; // `token = getToken(` is code
      value = codeValue(text, at, quote, raw);
    }
    if (!value || PLACEHOLDER.test(value)) continue;
    // Unquoted identifier is a variable reference (`auth: isAuthenticatedUser`),
    // unless its case flips like random text: words flip rarely, keys often.
    if (!quote && /^[A-Za-z_$]+$/.test(value) && caseSwitches(value) < value.length / 4) continue;
    if (!looksSecret(value, label, message)) continue;
    out.push({ rule: 'labeled', name: `Labeled secret (${label})`, value, start, end: start + value.length, confidence: 'medium' });
  }
  return out;
}

// Credentials in URL query strings: ?key=, &token=, ?access_token=, ?apikey=.
const URL_RE = /https?:\/\/[^\s"'`<>]+/g;
const URL_PARAM = /^(?:key|api[_-]?key|apikey|x-api-key|access[_-]?token|token|auth|auth[_-]?token|secret|client[_-]?secret|password|pass|pwd|senha|sig|signature)$/i;

function scanUrlParams(text) {
  const out = [];
  URL_RE.lastIndex = 0;
  let m;
  while ((m = URL_RE.exec(text))) {
    let url;
    try { url = new URL(m[0].replace(/[).,;:!?]+$/, '')); } catch { continue; }
    for (const [param, value] of url.searchParams) {
      if (!URL_PARAM.test(param) || !looksSecret(value, true)) continue;
      const start = text.indexOf(value, m.index);
      if (start < 0) continue;
      out.push({ rule: 'url-param', name: `URL parameter (${param})`, value, start, end: start + value.length, confidence: 'high', param, host: url.hostname });
    }
  }
  return out;
}

const CANDIDATE = /[A-Za-z0-9_\-+/=.]{24,}/g;

function scanAmbiguous(text, taken) {
  const out = [];
  CANDIDATE.lastIndex = 0;
  let m;
  while ((m = CANDIDATE.exec(text))) {
    const value = m[0].replace(/^[.\-_/=+]+|[.\-_/=+]+$/g, '');
    if (value.length < 24 || value.length > 512) continue;
    if (benignShape(value) || PLACEHOLDER.test(value)) continue;
    if (classes(value) < 3 || entropy(value) < 4.0) continue;
    const start = m.index + m[0].indexOf(value);
    if (taken.some((f) => start < f.end && f.start < start + value.length)) continue;
    out.push({ rule: 'high-entropy', name: 'High-entropy string', value, start, end: start + value.length, confidence: 'low' });
  }
  return out;
}

// Most specific wins when two findings overlap: provider > labeled > ambiguous,
// then the longer match.
const RANK = { high: 3, medium: 2, low: 1 };
function resolve(findings) {
  const sorted = [...findings].sort((a, b) =>
    RANK[b.confidence] - RANK[a.confidence] || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const kept = [];
  for (const f of sorted) {
    if (!kept.some((k) => f.start < k.end && k.start < f.end)) kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start);
}

/**
 * Scan text for secrets.
 * @param {string} text
 * @param {{ambiguous?: boolean}} [opts]
 * @returns {{findings: object[], ambiguous: object[]}}
 */
function scan(text, opts = {}) {
  if (!text || typeof text !== 'string') return { findings: [], ambiguous: [] };
  const lower = text.toLowerCase();
  const findings = resolve([...scanRules(text, lower), ...scanLabeled(text, opts.message), ...scanUrlParams(text)]);
  const ambiguous = opts.ambiguous ? scanAmbiguous(text, findings) : [];
  return { findings, ambiguous };
}

// Shape of a value with its content removed: letters -> a/A, digits -> 9,
// separators kept, length capped. Safe to show or send; not reversible.
function shape(value) {
  const s = value.slice(0, 48).replace(/[a-z]/g, 'a').replace(/[A-Z]/g, 'A').replace(/[0-9]/g, '9');
  return value.length > 48 ? `${s}…(${value.length})` : s;
}

function redact(text, found) {
  let out = '';
  let i = 0;
  for (const f of [...found].sort((a, b) => a.start - b.start)) {
    if (f.start < i) continue;
    out += text.slice(i, f.start) + `[${f.rule}:${shape(f.value)}]`;
    i = f.end;
  }
  return out + text.slice(i);
}

module.exports = { scan, shape, redact, entropy, looksSecret, edgeOf };
