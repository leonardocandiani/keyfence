'use strict';
// Fake credentials built at run time, so the repository never contains a
// literal token (GitHub push protection and every scanner would flag it).
// Shapes follow each provider's format; the content is random.

const crypto = require('crypto');

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const URLSAFE = ALNUM + '_-';
const HEX = '0123456789abcdef';
const UPPERNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function r(n, set = ALNUM) {
  const b = crypto.randomBytes(n);
  let s = '';
  for (let i = 0; i < n; i++) s += set[b[i] % set.length];
  return s;
}
const j = (...p) => p.join('');

// [ruleId, generator]
const positives = [
  ['anthropic', () => j('sk-', 'ant-', 'api03-', r(93, URLSAFE))],
  ['anthropic', () => j('sk-', 'ant-', 'oat01-', r(68, URLSAFE))],
  ['openai', () => j('sk-', 'proj-', r(120, URLSAFE))],
  ['openai-legacy', () => j('sk-', r(20), 'T3Blbk', 'FJ', r(20))],
  ['sk-generic', () => j('sk-', r(32, HEX))],
  ['sk-generic', () => j('sk-', 'or-v1-', r(64, HEX))],
  ['huggingface', () => j('hf', '_', r(34))],
  ['replicate', () => j('r8', '_', r(37))],
  ['groq', () => j('gsk', '_', r(52))],
  ['xai', () => j('xai', '-', r(80))],
  ['perplexity', () => j('pplx', '-', r(48))],
  ['aws-access-key', () => j('AK', 'IA', r(16, UPPERNUM))],
  ['google-api', () => j('AI', 'za', r(35, URLSAFE))],
  ['google-oauth-secret', () => j('GOCSPX', '-', r(28, URLSAFE))],
  ['google-oauth-token', () => j('ya29', '.', r(120, URLSAFE))],
  ['azure-storage', () => j('DefaultEndpointsProtocol=https;AccountName=x;Account', 'Key=', r(86, ALNUM + '+/'), '==')],
  ['digitalocean', () => j('dop', '_v1_', r(64, HEX))],
  ['tailscale', () => j('tskey', '-auth-', r(12), '-', r(30))],
  ['doppler', () => j('dp', '.st.', r(44))],
  ['fly', () => j('Fly', 'V1 fm2_', r(80, ALNUM + '+/='))],
  ['heroku', () => j('HRKU', '-', r(70, URLSAFE))],
  ['github', () => j('gh', 'p_', r(36))],
  ['github', () => j('gh', 's_', r(36))],
  ['github-fine', () => j('github', '_pat_', r(82, ALNUM + '_'))],
  ['gitlab', () => j('gl', 'pat-', r(20, URLSAFE))],
  ['npm', () => j('npm', '_', r(36))],
  ['pypi', () => j('pypi', '-AgEIcHlwaS5vcmc', r(80, URLSAFE))],
  ['stripe', () => j('sk', '_live_', r(99))],
  ['stripe', () => j('rk', '_test_', r(40))],
  ['stripe-webhook', () => j('wh', 'sec_', r(32))],
  ['asaas', () => j('$a', 'act_prod_', r(100, ALNUM + ':='))],
  ['mercadopago', () => j('APP', '_USR-', r(16, '0123456789'), '-', r(6, '0123456789'), '-', r(32, HEX), '-', r(9, '0123456789'))],
  ['slack', () => j('xo', 'xb-', r(11, '0123456789'), '-', r(12, '0123456789'), '-', r(24))],
  ['slack-webhook', () => j('https://hooks.', 'slack.com/services/T', r(9, UPPERNUM), '/B', r(9, UPPERNUM), '/', r(24))],
  ['discord-webhook', () => j('https://discord.com/api/', 'webhooks/', r(18, '0123456789'), '/', r(68, URLSAFE))],
  ['discord-bot', () => j('M', r(25, URLSAFE), '.', r(6, URLSAFE), '.', r(38, URLSAFE))],
  ['telegram-bot', () => j(r(10, '0123456789'), ':A', 'A', r(33, URLSAFE))],
  ['meta', () => j('EA', 'AG', r(180))],
  ['twilio', () => j('S', 'K', r(32, HEX))],
  ['sendgrid', () => j('S', 'G.', r(22, URLSAFE), '.', r(43, URLSAFE))],
  ['mailgun', () => j('key', '-', r(32, HEX))],
  ['resend', () => j('re', '_', r(8), '_', r(24))],
  ['postmark', () => j('PM', 'AK-', r(24, HEX), '-', r(34, HEX))],
  ['supabase-access', () => j('sb', 'p_', r(40, HEX))],
  ['supabase-secret', () => j('sb', '_secret_', r(32, URLSAFE))],
  ['notion', () => j('nt', 'n_', r(46))],
  ['linear', () => j('lin', '_api_', r(40))],
  ['shopify', () => j('shp', 'at_', r(32, HEX))],
  ['atlassian', () => j('ATA', 'TT3', r(190, URLSAFE + '='))],
  ['figma', () => j('fi', 'gd_', r(40, URLSAFE))],
  ['sentry', () => j('sn', 'trys_', r(60, ALNUM + '+/='))],
  ['db-url', () => j('postgres', 'ql://app:', r(24), '@db.internal:5432/main')],
  ['basic-auth-url', () => j('https://deploy:', r(20), '@git.example.org/repo.git')],
  ['private-key', () => j('-----BEGIN OPENSSH ', 'PRIVATE KEY-----\n', r(64, ALNUM + '+/'), '\n-----END OPENSSH ', 'PRIVATE KEY-----')],
  ['jwt', () => j('ey', 'J', r(20, URLSAFE), '.ey', 'J', r(40, URLSAFE), '.', r(43, URLSAFE))],
  ['bearer', () => j('Authorization: Bear', 'er ', r(40, URLSAFE))],
  // labeled values (no provider shape)
  ['labeled', () => j('CLOUDFLARE_API_TOKEN=', r(40, URLSAFE))],
  ['labeled', () => j('fipe-api-', 'key=', r(32, HEX))], // hex under an explicit label is a key, not a hash
  ['url-param', () => j('https://api.', 'placa', 'fipe.com.br/v1/placa/ABC1D23?key=', r(32, HEX))],
  ['url-param', () => j('https://example.io/v2/data?page=2&access_', 'token=', r(40, URLSAFE))],
  ['labeled', () => j('VERCEL_TOKEN=', r(24))],
  ['labeled', () => j('"client_secret": "', r(32), '"')],
  ['labeled', () => j('senha: ', r(14, ALNUM + '!@#'))],
  ['labeled', () => j('export DB_PASSWORD="', r(18, ALNUM + '#%&'), '"')],
];

// Things that must NOT be flagged.
const negatives = [
  'commit 3f9a1c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a291 fixes the bug',
  'id: 550e8400-e29b-41d4-a716-446655440000',
  '"integrity": "sha512-Zm9vYmFyYmF6cXV1eGZvb2JhcmJhenF1dXhmb29iYXJiYXpxdXV4Zm9vYmFy=="',
  'password: ${DB_PASSWORD}',
  j('api_key', ' = process.env.OPENAI_API_KEY'),
  'token: <your-token-here>',
  'SECRET_KEY=changeme',
  j('senha', ': senha123'),
  'export GITHUB_TOKEN=$(gh auth token)',
  'const passwordFieldLabel = "Digite sua senha"',
  'The token expires after 3600 seconds and the secret rotates weekly.',
  'see https://github.com/anthropics/claude-code/issues/12345',
  'const ComponentWithVeryLongDescriptiveName = () => null',
  'run npm install --save-dev typescript-eslint-parser-plugin',
  'sk-learn is a python library; use sklearn not sk-learn',
  'path: /Users/leo/Library/Application Support/Code/User/settings.json',
  'auth: required',
  'token_type: Bearer',
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPublicKeyIsNotASecret leo@mac',
  'key-value store',
  'Tip: auto mode handles these prompts for you',
  'base64 image: iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk',
  're_render_component_after_state_change_callback',
  '"token": "Categoria"',
  'token: options.apiKey',
  j('const client = createClient({ apiKey', ': config.openaiKey })'),
  j('DATABASE_URL=postgres://', 'postgres:password', '@localhost:5432/app'),
  'git clone https://${GH_USER}:${GH_TOKEN}@github.com/org/repo',
  'headers: { Authorization: `Bearer ${session_access_token}` }',
  'Authorization: Bearer YOUR_ACCESS_TOKEN_HERE',
  'token = client.auth.getSession(',
  'auth: isAuthenticatedUser,',
  'const token = await supabase.auth.getUser(jwt)',
  'Authorization: Bearer fk_test_TOKEN_HEADER',
  'token: prefix:${SESSION_ID}',
  j('password', ': __PASSWORD__default'),
  j('aws_access_key_id = AK', 'IAIOSFODNN7EXAMPLE'),
  '"token": "⟨META_ACCESS_TOKEN⟩"', // keyfence's own redaction label
  "  'apiKey: config.openaiKey',", // the value's closing quote belongs to the code, not the value
  '"secret": "service/api"', // an alias or path is a name, not a value
  '"secret": "wavoip/test-device/sip"',
  '"password": "#sip-password"', // a CSS selector names a field, it is not the value
  'https://example.com/search?page=2&sort=name&q=relatorio-mensal',
  'https://api.exemplo.com.br/v1/items?key=${API_KEY}',
  'commit: 3f2a9c1d8e7b6a5f4d3c2b1a0f9e8d7c6b5a4f3e',
  'auth: SESSION_TTL=3600',
  'token = user == null ? none : user.token',
  'secret_key: sk-ant-api03-...',
  'token: light_theme_v2',
];

// Ambiguous: no label, no known prefix, random-looking. Should be caught only by
// the ambiguous detector.
const ambiguous = [
  () => j('here it is: ', r(40, URLSAFE)),
  () => j('cf token ', r(40, URLSAFE), ' use it'),
];

module.exports = { positives, negatives, ambiguous, r };
