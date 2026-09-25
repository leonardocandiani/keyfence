'use strict';
// Live accuracy of naming: which service each credential gets from the context
// of messages written the way people send them. Not part of `npm test`: it
// calls the real classifier. Run: node test/naming-eval.js
// Values are generated at run time and never printed.

const { decide } = require('../src/naming');
const config = require('../src/config');
const { r } = require('./gen');

const PW = () => `${r(4)}#${r(3, '0123456789')}]${r(5)}`;
const TOK = () => `EAA${r(40)}`;
const HEX = () => r(32, '0123456789abcdef');

// [what the message looks like, build(value) -> text, services that are right, value]
const CASES = [
  ['cPanel block after "acesso aqui"', (v) => `agora com o acesso aqui, usando o keyfence:\n\n### Cpanel - lojaexemplo.com.br\n\nlojaexemplo.com.br/cpanel\n\nUsuário: lojaadm\nSenha: ${v}`, ['cpanel', 'lojaexemplo'], PW],
  ['"login e senha da wavoip"', (v) => `login e senha da wavoip pra tu usar\n\nmkt@empresa.com.br\n${v}`, ['wavoip'], PW],
  ['"segue o token da meta"', (v) => `segue o token da meta ${v}`, ['meta'], TOK],
  ['production database', (v) => `a senha do banco de produção do supabase é ${v}`, ['supabase'], PW],
  ['admin panel, "acesso aqui"', (v) => `acesso aqui do painel admin do asaas: user leo senha ${v}`, ['asaas'], PW],
  ['swagger link', (v) => `https://api.acmesolucoes.com/swagger/ Usuário: joao@acme.com Senha: ${v}`, ['acmesolucoes', 'acme'], PW],
  ['"sistema SIS"', (v) => `manda ali no sistema SIS com essa: login robson senha ${v}`, ['sis'], PW],
  ['"chave da fipe"', (v) => `chave da fipe pra consulta: ${v}`, ['fipe'], HEX],
  ['"acesso do moskit é esse aqui"', (v) => `o acesso do moskit é esse aqui ó: ${v}`, ['moskit'], PW],
  ['client ftp', (v) => `credenciais do servidor ftp do cliente pneusbrasil: user ftpuser senha ${v}`, ['pneusbrasil', 'ftp'], PW],
  ['English, GitHub', (v) => `here's the GitHub deploy password for the staging box: ${v}`, ['github'], PW],
  ['no service named at all', (v) => `token aqui: ${v}`, ['keyfence'], TOK],
];

(async () => {
  const cfg = config.load();
  if (!require('../src/jev').apiKey(cfg)) { console.log('naming-eval: no classifier key, nothing to measure'); return; }
  let ok = 0;
  const t0 = Date.now();
  for (const [name, text, want, gen] of CASES) {
    const v = gen();
    const [got] = await decide(text(v), [v], [], cfg, process.cwd());
    const hit = want.includes(got.service);
    ok += hit;
    console.log(`${hit ? 'ok  ' : 'MISS'} ${name}: ${got.service} (${got.by})${hit ? '' : `, want ${want.join(' or ')}`} | ${got.ranked.map((x) => `${x.w}=${x.p.toFixed(2)}`).join(' ')}`);
  }
  console.log(`naming: ${ok}/${CASES.length} named right | média ${Math.round((Date.now() - t0) / CASES.length)} ms`);
})();
