'use strict';
// A UUID pasted alone on its line under a title or a service name is an API key
// (Moskit, Asaas and others issue keys as UUIDs). Regression of 29/09/2026:
// "### Moskit Proteauto" followed by the key produced zero findings.

const crypto = require('crypto');
const { scan } = require('../src/detect');

let fail = 0;
const check = (ok, label) => {
  if (!ok) fail++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
};

const uuid = () => crypto.randomUUID();
const found = (text, v) => scan(text, { message: true }).findings.some((f) => f.value === v);

const CAPTURA = [
  (v) => `### Moskit Proteauto\n\n${v}`,
  (v) => `Moskit Proteauto\n${v}`,
  (v) => `## Asaas produção:\n${v}`,
  (v) => `segue a chave nova\n\nRD Station\n${v}`,
];
for (const [i, make] of CAPTURA.entries()) {
  const v = uuid();
  check(found(make(v), v), `UUID sob título/nome é capturado (caso ${i + 1})`);
}

const IGNORA = [
  [() => crypto.randomBytes(20).toString('hex'), (v) => `### Commit\n${v}`, 'hash de commit sob título'],
  [uuid, (v) => `o id do pedido é\n${v}`, 'UUID sob frase com "id"'],
  [uuid, (v) => `### Pedido\n${v}`, 'UUID sob título "Pedido"'],
  [uuid, (v) => `### Trace da requisição\n${v}`, 'UUID sob título de trace'],
  [uuid, (v) => `olha o que apareceu no log hoje cedo quando rodei\n${v}`, 'UUID sob frase longa'],
  [uuid, (v) => `Deu certo.\n${v}`, 'UUID sob frase terminada em ponto'],
];
for (const [gen, make, label] of IGNORA) {
  const v = gen();
  check(!found(make(v), v), `${label} não é capturado`);
}

console.log(fail ? `uuid-titulo: ${fail} failed` : 'uuid-titulo: all passed');
process.exitCode = fail ? 1 : 0;
