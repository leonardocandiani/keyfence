'use strict';
// A credential, not loose values. From what the user sent it works out which
// service, whose account, and which value plays which part: login, password,
// token, key, URL. The record goes to the vault as `service/account`
// (`sis/robson`) and to commands under names that say whose values they are
// (`SIS_ROBSON_LOGIN`, `SIS_ROBSON_PASSWORD`).
//
// Naming, in order: a name the user wrote (`PAINEL_PASSWORD=...`) is kept; a
// known provider's token keeps the name its SDK reads (`META_ACCESS_TOKEN`);
// everything else is SERVICE[_ACCOUNT]_ROLE.

const path = require('path');
const { execFileSync } = require('child_process');
const cap = require('./capture');

const ROLE = { PASSWORD: 'password', API_KEY: 'api_key', TOKEN: 'token', PIN: 'pin', CREDENTIAL: 'secret', SECRET: 'secret' };
const LOGIN_LABEL = /(?:^|[\s,;(])(?:login|usu[aá]rio|user(?:name)?|e-?mail|conta|account)\s*[:=]\s*["']?([^\s"',;]+)/gi;
const EMAIL = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
const URL_RE = /https?:\/\/[^\s"'<>]+/g;
const PROD = /\b(?:produ[cç][aã]o|production|prod)\b/i;
const TEST = /\b(?:homolog\w*|staging|sandbox|ambiente de teste|test environment)\b/i;

const slug = (s) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase()
  .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32);
const upper = (s) => slug(s).toUpperCase().replace(/-/g, '_');

function projectName(cwd) {
  let dir = cwd || '';
  try {
    dir = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd, encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch { /* not a repo: the directory itself */ }
  return slug(path.basename(dir).replace(/[-_.](?:api|app|web|backend|frontend|server|site|v\d+)$/i, ''));
}

// The login that goes with the secret: a labeled one, one the classifier
// pointed at, or the only email in a message that carries a password.
function loginIn(text, secrets, hinted) {
  if (hinted.length) return hinted[0];
  for (const m of text.matchAll(LOGIN_LABEL)) if (!secrets.includes(m[1])) return m[1];
  const emails = (text.match(EMAIL) || []).filter((e) => !secrets.includes(e));
  return emails.length === 1 ? emails[0] : null;
}

// robson.silva@empresa.com -> robson ; leo -> leo ; a@b.com -> '' (too short to name anything)
function accountOf(login) {
  if (!login) return '';
  const head = slug(String(login).split('@')[0].split(/[._+-]/)[0]);
  return head.length >= 3 ? head : '';
}

function providerOf(rule) {
  const sdk = cap.NAMES[rule];
  if (!sdk) return null;
  const role = /PASSWORD$/.test(sdk) ? 'password' : /TOKEN$/.test(sdk) ? 'token' : /URL$/.test(sdk) ? 'url' : /SECRET/.test(sdk) ? 'secret' : 'api_key';
  return { service: slug(rule.split('-')[0]), role, sdk };
}

// Name the user wrote before the value, if any (not a bare cue word like senha:).
function explicitName(item, text) {
  if (typeof item.start !== 'number') return null;
  const m = /([A-Za-z][A-Za-z0-9_-]{2,})["'`]?\s*[:=]\s*["'`]?$/.exec(text.slice(Math.max(0, item.start - 64), item.start));
  if (!m || cap.CUE_LABEL.test(m[1].replace(/[_-]/g, '')) || !/[_A-Z-]/.test(m[1])) return null;
  return m[1].toUpperCase().replace(/-/g, '_');
}

// "senha do robson" and "senha da wavoip" read the same: the vault decides. A
// subject that is already an account (sis/robson) is that account; one that is
// already a service stays a service; anything else is taken as the service.
function placeSubject(subject, known) {
  if (!subject) return {};
  const asAccount = known.find((a) => a.split('/')[1] === subject);
  if (asAccount) return { service: asAccount.split('/')[0], account: subject };
  return { service: subject };
}

function describeItem(item, text, cwd, known) {
  const provider = providerOf(item.rule);
  if (provider) return { service: provider.service, role: provider.role, envName: explicitName(item, text) || provider.sdk };
  if (item.rule === 'url-param') {
    const kind = cap.kindOf({ ...item, start: 0 }, `${item.param} `).kind;
    return { service: slug(cap.hostName(item.host)) || projectName(cwd), role: ROLE[kind === 'SECRET' ? 'API_KEY' : kind] || 'api_key', envName: explicitName(item, text) };
  }
  const { kind, subject } = cap.kindOf(item, text);
  const url = (text.match(URL_RE) || [])[0];
  let host = '';
  try { host = url ? cap.hostName(new URL(url).hostname) : ''; } catch { /* not a URL */ }
  const placed = placeSubject(slug(subject), known);
  return { service: placed.service || slug(host) || projectName(cwd), account: placed.account, role: ROLE[kind] || 'secret', envName: explicitName(item, text) };
}

/**
 * Group the secret items of a message into credential records.
 * @param {string} text the user's message
 * @param {{value:string, rule:string, start?:number}[]} items secrets found in it
 * @param {string} cwd the session's directory
 * @param {string[]} hintedLogins values the classifier said are the login
 * @param {string[]} known aliases already in the vault (metadata only)
 */
function build(text, items, cwd, hintedLogins = [], known = []) {
  const values = items.map((i) => i.value);
  const login = loginIn(text, values, hintedLogins);
  const url = (text.match(URL_RE) || []).find((u) => !values.some((v) => u.includes(v)));
  const environment = PROD.test(text) ? 'prod' : TEST.test(text) ? 'test' : 'dev';
  const byAlias = new Map();
  for (const item of items) {
    const d = describeItem(item, text, cwd, known);
    const account = d.account || (d.role === 'password' || d.role === 'pin' ? accountOf(login) : '');
    const alias = `${d.service || 'misc'}/${account || 'default'}`;
    if (!byAlias.has(alias)) byAlias.set(alias, { alias, service: d.service || 'misc', account, environment, fields: {}, envNames: {} });
    const rec = byAlias.get(alias);
    let role = d.role;
    for (let n = 2; rec.fields[role] !== undefined && rec.fields[role] !== item.value; n++) role = `${d.role}_${n}`;
    rec.fields[role] = item.value;
    rec.envNames[role] = d.envName || [upper(rec.service), account && upper(account), role.toUpperCase()].filter(Boolean).join('_');
  }
  for (const rec of byAlias.values()) {
    const base = [upper(rec.service), rec.account && upper(rec.account)].filter(Boolean).join('_');
    if (login && (rec.fields.password || rec.fields.pin) && !Object.values(rec.fields).includes(login)) {
      rec.fields.login = login;
      rec.envNames.login = `${base}_LOGIN`;
    }
    if (url && rec.fields.password) {
      rec.fields.url = url;
      rec.envNames.url = `${base}_URL`;
    }
  }
  return [...byAlias.values()];
}

module.exports = { build, projectName, accountOf, slug };
