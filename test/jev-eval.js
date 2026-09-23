'use strict';
// Live accuracy of the whole capture pipeline (rules, then the per-word
// classifier) on messages written the way people actually send them. Not part
// of `npm test`: it calls the real API. Run: node test/jev-eval.js
// Values are generated at run time; the report prints shapes, never values.

const { scan, shape } = require('../src/detect');
const { judge, candidatesOf, worthAsking } = require('../src/jev');
const config = require('../src/config');
const { r } = require('./gen');

const L = 'abcdefghijkmnopqrstuvwxyz', U = 'ABCDEFGHJKLMNPQRSTUVWXYZ', D = '0123456789', H = '0123456789abcdef';
const A = L + U + D;
const pw = () => r(3, U) + r(4, L) + r(3, D) + '!';
const email = () => `${r(5, L)}${r(2, D)}@empresa.com.br`;
const uuid = () => [8, 4, 4, 4, 12].map((n) => r(n, H)).join('-');

// Each case: [label, () => [text, secrets[], plain[]]]
const CASES = [
  ['labeled password', () => { const s = pw(); return [`senha: ${s}`, [s], []]; }],
  ['login block with email and password', () => { const e = email(), s = pw(); return [`### Login do painel\nEmail: ${e}\nSenha: ${s}`, [s], [e]]; }],
  ['email that is also the password', () => { const e = email(); return [`Usuário: ${e}\nSenha: ${e}`, [e], []]; }],
  ['login and password on loose lines', () => { const e = email(), s = r(8, D) + '*'; return [`login e senha da wavoip pra tu usar\n\n${e}\n${s}`, [s], [e]]; }],
  ['hex key in a link', () => { const s = r(32, H); return [`testa a consulta https://api.placafipe.com.br/placa/ABC1D23?key=${s}`, [s], []]; }],
  ['hex key after "chave da"', () => { const s = r(32, H); return [`segue a chave da fipe ${s} e testa com a placa ABC1D23`, [s], ['ABC1D23']]; }],
  ['token in a command flag', () => { const s = r(6, L) + r(24, A); return [`roda o deploy com --token ${s} no staging`, [s], []]; }],
  ['weak wifi password in prose', () => { const s = 'casa' + r(4, D); return [`a senha do wifi da sala é ${s}, conecta o celular`, [s], []]; }],
  ['english: here is my api key', () => { const s = 'k_' + r(30, A); return [`here's my api key for the staging env: ${s}`, [s], []]; }],
  ['json paste', () => { const s = r(40, A); return [`{"endpoint": "https://api.x.io", "client_id": "app-${r(4, D)}", "client_secret": "${s}"}`, [s], []]; }],
  ['connection string', () => { const s = pw(); return [`usa esse banco: postgres://app:${s}@db.interno:5432/prod`, [s], []]; }],
  ['pin in prose', () => { const s = r(6, D); return [`o pin do cartão de teste é ${s}`, [s], []]; }],
  ['two credentials in one message', () => { const a = pw(), b = r(36, A); return [`a senha do admin é ${a} e o token da api é ${b}`, [a, b], []]; }],
  ['password in a numbered list', () => { const s = pw(); return [`passos:\n1. abre o painel\n2. entra com leo e ${s}\n3. vai em configurações`, [s], []]; }],
  ['credential with no context word', () => { const s = r(4, U) + r(6, L) + r(4, D); return [`usa isso aqui ${s}`, [s], []]; }],
  ['english password sentence', () => { const s = pw(); return [`the password for the router is ${s}, don't share it`, [s], []]; }],
  // plain text that looks like secrets
  ['order id', () => { const s = r(24, H); return [`o pedido ${s} deu erro 500 ontem, olha o log`, [], [s]]; }],
  ['commit sha', () => { const s = r(7, H); return [`o commit ${s} quebrou o build, reverte`, [], [s]]; }],
  ['full commit and branch', () => { const s = r(40, H); return [`faz cherry-pick do ${s} na branch release-${r(2, D)}`, [], [s]]; }],
  ['plate and cpf', () => { const p = `${r(3, U)}${r(1, D)}${r(1, U)}${r(2, D)}`, c = `${r(3, D)}.${r(3, D)}.${r(3, D)}-${r(2, D)}`; return [`consulta a placa ${p} do cliente cpf ${c}`, [], [p, c]]; }],
  ['phone and protocol', () => { const t = `+55${r(11, D)}`, p = `PROT-${r(8, D)}`; return [`liga pro ${t} e passa o protocolo ${p}`, [], [t, p]]; }],
  ['record uuid', () => { const u = uuid(); return [`apaga o registro ${u} da tabela de leads`, [], [u]]; }],
  ['version and file', () => [`atualiza pra v${r(1, D)}.${r(2, D)}.${r(1, D)} e mexe no auth-service.ts`, [], []]],
  ['token talk with no token', () => [`o token do design system pra cor primária é --color-primary-500, ajusta o botão`, [], []]],
  ['password talk with no password', () => [`cria a tela de trocar senha com validação de 8 caracteres`, [], []]],
  ['api key talk with an env var name', () => [`a api key fica em STRIPE_SECRET_KEY no .env, lê de lá`, [], []]],
  ['random-looking id in a url', () => { const s = r(20, A); return [`abre https://app.exemplo.com/leads/${s} e vê o histórico`, [], [s]]; }],
  ['tracking code', () => { const s = `${r(2, U)}${r(9, D)}BR`; return [`o código de rastreio é ${s}, confere no correios`, [], [s]]; }],
  ['stripe-like id that is not a secret', () => { const s = `cus_${r(14, A)}`; return [`o customer ${s} pediu reembolso`, [], [s]]; }],
  ['login name only', () => { const e = email(); return [`o login dele é ${e}, reseta a senha pelo painel`, [], [e]]; }],
];

(async () => {
  const cfg = config.load();
  cfg.jev.enabled = true;
  let tp = 0, fn = 0, fp = 0, calls = 0, ms = 0, guarded = 0;
  const misses = [];
  for (const [label, make] of CASES) {
    const [text, secrets, plain] = make();
    const findings = scan(text).findings;
    const got = new Set(findings.map((f) => f.value));
    const kept = new Set(scan(text, { ambiguous: true }).ambiguous.map((f) => f.value));
    const cands = candidatesOf(text, [...got]);
    if (worthAsking(text, cands)) {
      const t = Date.now();
      const v = await judge(text, cands, cfg);
      ms += Date.now() - t; calls++;
      for (const x of v || []) if (x.p >= cfg.jev.pickThreshold) got.add(x.value); else if (x.p >= cfg.jev.keepThreshold) kept.add(x.value);
      if (!v) cands.forEach((c) => kept.add(c)); // classifier down: everything stays protected
    }
    const hit = secrets.filter((s) => [...got].some((g) => g === s || g.includes(s)));
    const wrong = plain.filter((p) => got.has(p));
    tp += hit.length; fn += secrets.length - hit.length; fp += wrong.length;
    guarded += secrets.filter((s) => [...got, ...kept].some((g) => g === s || g.includes(s))).length;
    if (hit.length < secrets.length || wrong.length) misses.push(`${label}: pegou ${hit.length}/${secrets.length}${wrong.length ? `, falso alarme em ${wrong.map(shape).join(' ')}` : ''}`);
  }
  console.log(`gravados com nome: ${tp}/${tp + fn} (${(100 * tp / (tp + fn)).toFixed(0)}%) | protegidos: ${guarded}/${tp + fn} | falsos alarmes: ${fp} | chamadas: ${calls}, média ${calls ? Math.round(ms / calls) : 0} ms`);
  for (const m of misses) console.log('  ' + m);
})();
