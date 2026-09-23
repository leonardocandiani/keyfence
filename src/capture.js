'use strict';
// Capture mode: a credential pasted in the prompt is saved to an env file the
// moment it arrives, under a name, so the session goes on using it by name.
// The project's .env is used when git ignores it; otherwise a private global
// file. The value is written only there, never to keyfence's state.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

// Conventional variable names per provider rule, the ones SDKs read by default.
const NAMES = Object.fromEntries(`
anthropic           ANTHROPIC_API_KEY
openai              OPENAI_API_KEY
openai-legacy       OPENAI_API_KEY
huggingface         HF_TOKEN
replicate           REPLICATE_API_TOKEN
groq                GROQ_API_KEY
xai                 XAI_API_KEY
perplexity          PERPLEXITY_API_KEY
aws-access-key      AWS_ACCESS_KEY_ID
google-api          GOOGLE_API_KEY
google-oauth-secret GOOGLE_CLIENT_SECRET
digitalocean        DIGITALOCEAN_TOKEN
tailscale           TS_AUTHKEY
doppler             DOPPLER_TOKEN
fly                 FLY_API_TOKEN
github              GITHUB_TOKEN
github-fine         GITHUB_TOKEN
gitlab              GITLAB_TOKEN
npm                 NPM_TOKEN
pypi                PYPI_TOKEN
stripe              STRIPE_SECRET_KEY
stripe-webhook      STRIPE_WEBHOOK_SECRET
asaas               ASAAS_API_KEY
mercadopago         MERCADOPAGO_ACCESS_TOKEN
slack               SLACK_TOKEN
slack-webhook       SLACK_WEBHOOK_URL
discord-webhook     DISCORD_WEBHOOK_URL
discord-bot         DISCORD_BOT_TOKEN
telegram-bot        TELEGRAM_BOT_TOKEN
meta                META_ACCESS_TOKEN
twilio              TWILIO_API_KEY
sendgrid            SENDGRID_API_KEY
mailgun             MAILGUN_API_KEY
resend              RESEND_API_KEY
postmark            POSTMARK_SERVER_TOKEN
supabase-access     SUPABASE_ACCESS_TOKEN
supabase-secret     SUPABASE_SECRET_KEY
notion              NOTION_TOKEN
linear              LINEAR_API_KEY
shopify             SHOPIFY_ACCESS_TOKEN
atlassian           ATLASSIAN_API_TOKEN
figma               FIGMA_TOKEN
sentry              SENTRY_AUTH_TOKEN
db-url              DATABASE_URL
jwt                 JWT
`.trim().split('\n').map((l) => l.split(/\s+/)));

const expand = (p) => p.replace(/^~(?=\/|$)/, os.homedir());

// What the words right before the value call it: "senha: x", "a senha é x".
const KINDS = [
  [/senha|password|passwd|pwd|\bpass\b|contrase/i, 'PASSWORD'],
  [/api[\s_-]?key|apikey|chave|\bkey\b/i, 'API_KEY'],
  [/token/i, 'TOKEN'],
  [/pin\b/i, 'PIN'],
  [/credencial|credential/i, 'CREDENTIAL'],
];
const ascii = (w) => w.normalize('NFD').replace(/[^A-Za-z0-9]/g, '').toUpperCase();

// The nearest cue before the value names its kind; "senha da wavoip" also names
// its subject: WAVOIP_PASSWORD.
const STOP = /^(?:com|para|pra|the|and|que|sem|por|via|meu|minha|nosso|nossa|this|that|your|my|app|api|www)$/i;
const subjectOf = (w) => (w && !STOP.test(w) ? ascii(w) : '');

// The nearest cue before the value names its kind. The subject comes from the
// words after the cue ("senha da wavoip": WAVOIP_PASSWORD) or, failing that,
// from a login/account phrase nearby ("Login SIS ... Senha:": SIS_PASSWORD).
function kindName(item, text) {
  const at = typeof item.start === 'number' ? item.start : text.indexOf(item.value);
  const before = at > 0 ? text.slice(Math.max(0, at - 160), at) : String(item.name || '');
  let best = null;
  for (const [re, kind] of KINDS) {
    for (const m of before.matchAll(new RegExp(re.source, 'gi'))) {
      if (!best || m.index > best.index) best = { index: m.index, kind };
    }
  }
  if (!best) return 'SECRET';
  const subj = subjectNear(before, best.index);
  return subj ? `${subj}_${best.kind}` : best.kind;
}

const AFTER_CUE = /^\S*\s+(?:d[aoe]s?|of|for)\s+(?:the\s+)?([^\s,.:;!?/]{2,24})/i;
const LOGIN_OF = /(?:login|acesso|conta|account|credenciais?)\s+(?:d[aoe]s?\s+|of\s+|for\s+)?([^\s,.:;!?/]{2,24})/gi;

// "senha da wavoip" names WAVOIP; failing that, "Login SIS" nearby names SIS.
function subjectNear(before, cueAt) {
  const after = AFTER_CUE.exec(before.slice(cueAt));
  if (after && subjectOf(after[1])) return subjectOf(after[1]);
  const logins = [...before.matchAll(LOGIN_OF)];
  return logins.length ? subjectOf(logins[logins.length - 1][1]) : '';
}

// Host of an API URL as a name: api.fipeapi.com.br -> FIPEAPI.
function hostName(host) {
  const labels = String(host || '').toLowerCase().split('.')
    .filter((l, i, all) => !(i >= all.length - 2 && /^(?:com|net|org|io|br|co|dev|ai|app|gov|edu|info|me|us|uk)$/.test(l)))
    .filter((l) => !/^(?:api|apis|www|app|v\d+|rest|gateway)$/.test(l));
  return labels.length ? ascii(labels[labels.length - 1]) : '';
}

const CUE_LABEL = /^(?:senha|password|passwd|pwd|pass|token|secret|segredo|key|apikey|chave|auth|credential|credencial|contrasena|contraseña)$/i;

// A label right before the value in the prompt (an env-style name followed by
// = or :) names it; otherwise the provider's conventional name; otherwise the
// kind the words around it describe.
function nameFor(item, text) {
  if (item.rule === 'url-param') {
    const hit = KINDS.find(([re]) => re.test(item.param));
    const kind = hit ? hit[1] : 'API_KEY';
    const host = hostName(item.host);
    return host ? `${host}_${kind}` : kind;
  }
  if (typeof item.start === 'number') {
    const before = text.slice(Math.max(0, item.start - 64), item.start);
    const m = /([A-Za-z][A-Za-z0-9_-]{2,})["'`]?\s*[:=]\s*["'`]?$/.exec(before);
    // A label that is only a cue word (senha:, api_key=) says the kind, not the name.
    if (m && !CUE_LABEL.test(m[1].replace(/[_-]/g, '')) && /[_A-Z-]/.test(m[1])) return m[1].toUpperCase().replace(/-/g, '_');
  }
  if (NAMES[item.rule]) return NAMES[item.rule];
  if (/^(labeled|high-entropy|classifier)$/.test(item.rule)) return kindName(item, text);
  return `${item.rule.toUpperCase().replace(/[^A-Z0-9]+/g, '_')}_TOKEN`;
}

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 2000, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
}

// The project's .env when the session runs inside a repo that ignores it.
function targetFile(cwd, cfg) {
  if (cfg.capture.target === 'project' && cwd) {
    try {
      const root = git(['rev-parse', '--show-toplevel'], cwd);
      const env = path.join(root, '.env');
      try {
        git(['check-ignore', '-q', env], root);
        return { file: env, project: true };
      } catch { /* .env not ignored: never write a secret there */ }
    } catch { /* not a repo */ }
  }
  return { file: expand(cfg.capture.globalFile), project: false };
}

function parseEnv(src) {
  const out = new Map();
  for (const line of src.split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out.set(m[1], v);
  }
  return out;
}

const quote = (v) => (/^[A-Za-z0-9_\-+/=.:@~%,]+$/.test(v) ? v : `'${v.replace(/'/g, "'\\''")}'`);

/**
 * Save values to the env file. Same value already there: reuse its name.
 * Name taken by another value: suffix _2, _3 (never overwrite).
 * @returns {{file: string, project: boolean, saved: {name: string, rule: string, value: string, reused: boolean}[]}}
 */
function save(items, prompt, cwd, cfg) {
  const { file, project } = targetFile(cwd, cfg);
  let src = '';
  try { src = fs.readFileSync(file, 'utf8'); } catch { /* new file */ }
  const env = parseEnv(src);
  const saved = [];
  let append = '';
  for (const it of items) {
    const existing = [...env].find(([, v]) => v === it.value);
    if (existing) {
      saved.push({ name: existing[0], rule: it.rule, value: it.value, reused: true });
      continue;
    }
    const base = nameFor(it, prompt);
    let name = base;
    for (let i = 2; env.has(name); i++) name = `${base}_${i}`;
    env.set(name, it.value);
    append += `${name}=${quote(it.value)}\n`;
    saved.push({ name, rule: it.rule, value: it.value, reused: false });
  }
  if (append) {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    const sep = src && !src.endsWith('\n') ? '\n' : '';
    fs.appendFileSync(file, sep + append, { mode: 0o600 });
  }
  return { file, project, saved };
}

module.exports = { save, nameFor, targetFile, parseEnv, NAMES };
