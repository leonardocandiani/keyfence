'use strict';
// Provider rules. Each rule: id, name, re (global), keywords (lowercase
// substrings that must appear somewhere in the text before the regex runs;
// cheap prefilter), and optional `group` (capture index holding the secret,
// default 0 = whole match).
//
// Only formats with a documented or widely observed shape are here. A provider
// whose tokens have no stable prefix (plain 40-char hex, for example) is left to
// the labeled/entropy detectors in detect.js instead of guessing a regex that
// would either miss or fire on every git SHA.

// weak: the regex matches a structure (URL, header) but not the secret's shape, so
// the captured value must also look random (detect.js looksSecret).
const R = (id, name, re, keywords, group = 0, weak = false) => ({ id, name, re, keywords, group, weak });

const rules = [
  // --- AI providers ---------------------------------------------------------
  R('anthropic', 'Anthropic key', /\bsk-ant-(?:api03|admin01|oat01|ort01)-[A-Za-z0-9_-]{20,}/g, ['sk-ant-']),
  R('openai', 'OpenAI key', /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}/g, ['sk-']),
  R('openai-legacy', 'OpenAI key (legacy)', /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, ['t3blbkfj']),
  R('sk-generic', 'sk- style key (DeepSeek, OpenRouter, others)', /\bsk-(?:or-v1-)?[A-Za-z0-9_-]{24,}/g, ['sk-']),
  R('huggingface', 'Hugging Face token', /\bhf_[A-Za-z0-9]{30,}\b/g, ['hf_']),
  R('replicate', 'Replicate token', /\br8_[A-Za-z0-9]{37}\b/g, ['r8_']),
  R('groq', 'Groq key', /\bgsk_[A-Za-z0-9]{48,}\b/g, ['gsk_']),
  R('xai', 'xAI key', /\bxai-[A-Za-z0-9]{60,}\b/g, ['xai-']),
  R('perplexity', 'Perplexity key', /\bpplx-[A-Za-z0-9]{40,}\b/g, ['pplx-']),

  // --- Cloud and infra ------------------------------------------------------
  R('aws-access-key', 'AWS access key id', /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, ['akia', 'asia', 'abia', 'acca']),
  R('google-api', 'Google API key', /\bAIza[0-9A-Za-z_-]{35}(?![A-Za-z0-9_-])/g, ['aiza']),
  R('google-oauth-secret', 'Google OAuth client secret', /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g, ['gocspx-']),
  R('google-oauth-token', 'Google OAuth access token', /\bya29\.[0-9A-Za-z_-]{20,}/g, ['ya29.']),
  R('azure-storage', 'Azure storage key', /AccountKey=([A-Za-z0-9+/]{80,}={0,2})/g, ['accountkey='], 1),
  R('digitalocean', 'DigitalOcean token', /\bdo[por]_v1_[a-f0-9]{64}\b/g, ['_v1_']),
  R('tailscale', 'Tailscale key', /\btskey-(?:auth|api|client|scim|webhook)-[A-Za-z0-9]+-[A-Za-z0-9]{20,}/g, ['tskey-']),
  R('doppler', 'Doppler token', /\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}/g, ['dp.']),
  R('fly', 'Fly.io token', /\bFlyV1 fm\d_[A-Za-z0-9+/=_-]{40,}/g, ['flyv1']),
  R('heroku', 'Heroku key', /\bHRKU-[A-Za-z0-9_-]{60,}/g, ['hrku-']),

  // --- Code hosting and packages -------------------------------------------
  R('github', 'GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']),
  R('github-fine', 'GitHub fine-grained token', /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, ['github_pat_']),
  R('gitlab', 'GitLab token', /\bgl(?:pat|dt|ptt|rt|oas)-[A-Za-z0-9_-]{20,}/g, ['glpat-', 'gldt-', 'glptt-', 'glrt-', 'gloas-']),
  R('npm', 'npm token', /\bnpm_[A-Za-z0-9]{36}\b/g, ['npm_']),
  R('pypi', 'PyPI token', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g, ['pypi-']),

  // --- Payments -------------------------------------------------------------
  R('stripe', 'Stripe secret key', /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/g, ['sk_live_', 'sk_test_', 'rk_live_', 'rk_test_']),
  R('stripe-webhook', 'Stripe webhook secret', /\bwhsec_[A-Za-z0-9]{24,}\b/g, ['whsec_']),
  R('asaas', 'Asaas key', /\$aact_[A-Za-z0-9_:=+/-]{20,}/g, ['$aact_']),
  R('mercadopago', 'Mercado Pago token', /\b(?:APP_USR|TEST)-\d{10,}-\d{6}-[a-f0-9]{32}-\d{6,}\b/g, ['app_usr-', 'test-']),

  // --- Messaging and email --------------------------------------------------
  R('slack', 'Slack token', /\bxox[abposr]-[A-Za-z0-9-]{10,}/g, ['xox']),
  R('slack-webhook', 'Slack webhook URL', /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g, ['hooks.slack.com']),
  R('discord-webhook', 'Discord webhook URL', /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{50,}/g, ['discord']),
  R('discord-bot', 'Discord bot token', /\b[MN][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}(?![A-Za-z0-9_-])/g, ['.']),
  R('telegram-bot', 'Telegram bot token', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])/g, [':aa']),
  R('meta', 'Meta / WhatsApp Cloud API token', /\bEAA[A-Za-z0-9]{60,}\b/g, ['eaa']),
  R('twilio', 'Twilio API key', /\bSK[0-9a-f]{32}\b/g, ['sk']),
  R('sendgrid', 'SendGrid key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g, ['sg.']),
  R('mailgun', 'Mailgun key', /\bkey-[0-9a-f]{32}\b/g, ['key-']),
  R('resend', 'Resend key', /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}\b/g, ['re_']),
  R('postmark', 'Postmark token', /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/g, ['pmak-']),

  // --- SaaS and databases ---------------------------------------------------
  R('supabase-access', 'Supabase access token', /\bsbp_[a-f0-9]{40}\b/g, ['sbp_']),
  R('supabase-secret', 'Supabase secret key', /\bsb_secret_[A-Za-z0-9_-]{20,}/g, ['sb_secret_']),
  R('notion', 'Notion token', /\b(?:secret_|ntn_)[A-Za-z0-9]{40,}\b/g, ['secret_', 'ntn_']),
  R('linear', 'Linear key', /\blin_api_[A-Za-z0-9]{40}\b/g, ['lin_api_']),
  R('shopify', 'Shopify token', /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, ['shpat_', 'shpca_', 'shppa_', 'shpss_']),
  R('atlassian', 'Atlassian API token', /\bATATT3[A-Za-z0-9_=-]{180,}/g, ['atatt3']),
  R('figma', 'Figma token', /\bfig[dur]_[A-Za-z0-9_-]{38,}/g, ['figd_', 'figu_', 'figr_']),
  R('sentry', 'Sentry token', /\bsntry[su]_[A-Za-z0-9+/=_-]{40,}/g, ['sntrys_', 'sntryu_']),
  R('db-url', 'Database URL with password',
    /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s/@]+:([^@\s/]{3,})@/g,
    ['://'], 1, true),
  R('basic-auth-url', 'URL with embedded password', /\bhttps?:\/\/[^:\s/@]+:([^@\s/]{6,})@[^\s]+/g, ['://'], 1, true),

  // --- Generic structured secrets ------------------------------------------
  R('private-key', 'Private key',
    /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{20,}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g,
    ['private key']),
  R('private-key-header', 'Private key (header only)', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, ['private key']),
  R('jwt', 'JWT', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, ['eyj']),
  R('bearer', 'Bearer token in header', /\b[Bb]earer\s+([A-Za-z0-9._~+/=-]{20,})/g, ['bearer'], 1, true),
];

module.exports = { rules };
