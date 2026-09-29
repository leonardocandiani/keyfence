'use strict';
// Detection engine. Three layers, from most to least certain:
//   1. provider rules (rules.js): known shapes, high confidence
//   2. labeled values: `token=...`, `"password": "..."`, `senha: ...` with an
//      entropy floor and a placeholder filter, medium confidence
//   2b. in a message only: a token placed where a person puts a credential
//      (alone under a heading or a name, in backticks, after "<name>:" or after
//      "a chave é"), medium confidence
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
// The name of a credential's variable, in the convention keyfence writes them:
// `senha: SIS_ROBSON_PASSWORD` in a message points at the variable, not a value.
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:PASSWORD|PASS|PWD|TOKEN|KEY|SECRET|LOGIN|URL|PIN)(?:_\d+)?$/;

// A value that is wholly something other than a secret: a reference to one
// ($VAR, config.db.pass, getPassword()), an identifier or a path.
function isReference(v) {
  return /^\$\{?[A-Z_][A-Z0-9_]*\}?$/i.test(v) // $VAR / ${VAR}
    || /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+$/.test(v) // member access
    || /^[A-Za-z_$][\w$.]*\(.*\)[;,]?$/.test(v) // call
    || /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+\/?$/.test(v) // lowercase path or alias: service/api
    || /^[#.][a-z][a-z0-9]*(?:[-_][a-z0-9]+)*$/.test(v) // CSS selector: #sip-password, .login-field
    || /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v) // an env variable's name: KF_7F3A_PASSWORD
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
  if (passwordLabel && message) return !!v && v.length >= 6 && !PLACEHOLDER.test(v) && !DEFAULTS.test(v) && !ENV_NAME.test(v);
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

// Credentials a person sends without a keyword label: the way they arrive in a
// chat. Only for what a person typed (message mode); code and files keep the
// three layers above. Each profile is a position that says "this is the value":
//   line     a token alone on its line, under a heading or a name
//            ("### Granola" / "Resend - Leonardo" and the token below it),
//            inside a code fence, or a message that is only the token
//   inline   a token in `backticks`
//   named    "<name>: <token>", "<name> - <token>", "<name> -> <token>" at the
//            end of the line, where the name is a service or a short phrase
//   cue      "a chave do resend é <token>", "the stripe key is <token>",
//            "segue o token <token>": a credential word, a verb, the value
// A token here is at least 16 characters, letters mixed with digits or case,
// random enough, and not a hash, id, path, URL, e-mail or file name.
const CONTEXT_TOKEN = /[A-Za-z0-9_\-+/=.~]{16,512}/g;
const CUE_WORD = /\b(?:token|tokens|chave|key|keys|apikey|api|senha|password|pass|secret|segredo|credencial|credential|acesso|access|bearer|pat)\b/i;
// JS `\b` is ASCII only, so "é" needs its own boundary: (?<![\p{L}\d]) and (?![\p{L}\d]).
const CUE_NAMES = 'token|tokens|chave|key|apikey|senha|password|secret|segredo|credencial|credential|acesso|access|bearer|pat';
const CUE_BEFORE = new RegExp(
  // "a chave do resend é X", "the stripe key is X", "token: X", "chave -> X"
  `(?<![\\p{L}\\d])(?:${CUE_NAMES})(?![\\p{L}\\d])[^\\n]{0,60}?(?:(?<![\\p{L}\\d])(?:é|eh|e|is|são|sao|fica|vai|segue|aqui|abaixo|below|here)(?![\\p{L}\\d])|[:=]|->|→)\\s*["'\`]?$`
  // "segue o token X", "usa a key X": the credential word right before the value
  + `|(?<![\\p{L}\\d])(?:${CUE_NAMES})\\s*["'\`]?$`,
  'iu',
);
const NAME_BEFORE = /(?:^|\n)[ \t>*•-]*([^\n:=`]{1,48}?)[ \t]*(?::|=|->|→|–|—| - )[ \t]*["'`]?$/;
const FILE_NAME = /\.(?:pdf|png|jpe?g|gif|webp|mp[34]|wav|ogg|zip|csv|xlsx?|docx?|pptx?|txt|md|json|ya?ml|js|ts|py|sh|html?)$/i;
const EMAIL = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;
const WORDLIKE = /^(?:[a-z]+|[A-Z][a-z]+|[A-Z]+|\d{1,4}|v\d+)$/;

function contextToken(v, cued) {
  if (v.length < 16 || PLACEHOLDER.test(v) || EMAIL.test(v) || FILE_NAME.test(v)) return false;
  if (/^[a-z]+:\/\//i.test(v) || /^[./~]/.test(v) || /\/.*\//.test(v)) return false;
  if (HEXLIKE.test(v)) return !!cued; // a commit hash or an id, unless the words say key
  // Words joined by separators (relatorio-final-2026, user_id_42, config.db.host)
  // are names, not keys: a key has at least one run that is not a word.
  const runs = v.split(/[-_.+/=~]+/).filter(Boolean);
  if (runs.every((w) => WORDLIKE.test(w))) return false;
  const odd = runs.filter((w) => !WORDLIKE.test(w));
  const randomRun = odd.join('').length >= 10 && odd.some((w) => /\d/.test(w) || caseSwitches(w) >= 4);
  // A dotted token (header.payload) matches the member-access shape of isReference.
  if (benignShape(v) || (isReference(v) && !randomRun)) return false;
  if (!/[A-Za-z]/.test(v) || !randomRun) return false;
  return entropy(v) >= 3.3 && classes(v) >= 2;
}

function lineAround(text, start, end) {
  const a = text.lastIndexOf('\n', start - 1) + 1;
  let b = text.indexOf('\n', end);
  if (b < 0) b = text.length;
  return { a, b, line: text.slice(a, b) };
}

// A line that holds only the value, maybe wrapped in quotes, backticks, a bullet
// or a quote marker.
function aloneOnLine(line, v) {
  return line.replace(/^\s*(?:[>*•-]\s+)*/, '').replace(/^["'`]+|["'`]+$/g, '').trim() === v;
}

function previousLine(text, a) {
  const before = text.slice(0, a).split('\n').map((l) => l.trim()).filter(Boolean);
  return before.length ? before[before.length - 1] : '';
}

function profileOf(text, v, start, end) {
  const { a, b, line } = lineAround(text, start, end);
  const before = text.slice(a, start);
  const after = text.slice(end, b).replace(/^["'`]/, '').trim();
  const prev = previousLine(text, a);
  const onlyToken = text.trim().replace(/^["'`]+|["'`]+$/g, '') === v;
  if (aloneOnLine(line, v)) {
    if (onlyToken) return { profile: 'line', cued: false };
    if (prev && !/^```/.test(prev)) return { profile: 'line', cued: CUE_WORD.test(prev) };
    const fenceHead = text.slice(0, a).split('\n').map((l) => l.trim()).filter(Boolean);
    if (fenceHead.length >= 2) return { profile: 'line', cued: CUE_WORD.test(fenceHead[fenceHead.length - 2]) };
    return null;
  }
  if (text[start - 1] === '`' && text[end] === '`') return { profile: 'inline', cued: CUE_WORD.test(line) };
  if (after && !/^[.,;!?)]*$/.test(after)) {
    // The value sits in running text: only a credential word right before it says so.
    return CUE_BEFORE.test(before) ? { profile: 'cue', cued: true } : null;
  }
  if (CUE_BEFORE.test(before)) return { profile: 'cue', cued: true };
  const named = NAME_BEFORE.exec(text.slice(0, start));
  if (named && named[1].trim().split(/\s+/).length <= 6) return { profile: 'named', cued: CUE_WORD.test(named[1]) };
  return null;
}

function scanContextual(text, taken) {
  const out = [];
  CONTEXT_TOKEN.lastIndex = 0;
  let m;
  while ((m = CONTEXT_TOKEN.exec(text))) {
    // Only sentence punctuation comes off the edges: - _ = + end real keys (base64).
    let value = m[0].replace(/^[./~]+|[./~]+$/g, '');
    let start = m.index + m[0].indexOf(value);
    // `MOSKIT_API_KEY_PROD=<key>`: an `=` followed by more characters is an
    // assignment, never base64 padding (that only closes a key). The value is the
    // right side; the name on the left is what nameFor reads to name it.
    const assign = /^[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+=(?=[^=])/.exec(value);
    if (assign) {
      value = value.slice(assign[0].length);
      start += assign[0].length;
    }
    const end = start + value.length;
    if (taken.some((f) => start < f.end && f.start < end)) continue;
    // The value is a whole word: a piece of a longer one (an URL, an e-mail, a path,
    // a password with symbols the pattern leaves out) is not a value of its own.
    const prev = text[start - 1] || '';
    const next = text.slice(end, end + 2);
    if (prev && !assign && !/[\s"'`(>]/.test(prev)) continue;
    if (next && !/^(?:[\s"'`)]|[.,;:!?](?:\s|$))/.test(next)) continue;
    // Quotes, backticks and parentheses count as an edge only in pairs: `value`,
    // "value", (value). An unpaired one is a symbol inside a longer password.
    const pair = { '"': '"', "'": "'", '`': '`', '(': ')' };
    const opens = pair[prev];
    const closes = /["'`)]/.test(next[0] || '');
    if ((opens || closes) && opens !== next[0]) continue;
    const p = profileOf(text, value, start, end);
    if (!p || !contextToken(value, p.cued)) continue;
    out.push({ rule: 'contextual', name: `Credential by context (${p.profile})`, value, start, end, confidence: 'medium', profile: p.profile });
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
  const known = resolve([...scanRules(text, lower), ...scanLabeled(text, opts.message), ...scanUrlParams(text)]);
  const findings = opts.message ? resolve([...known, ...scanContextual(text, known)]) : known;
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

module.exports = { scan, shape, redact, entropy, looksSecret, edgeOf, scanContextual };
