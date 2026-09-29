'use strict';
// `NOME=valor` pasted in a message: the value is the right side of the `=`, and
// the name on the left names it. Regression of 29/09/2026: an env name that goes
// on past the credential word (MOSKIT_API_KEY_PROTEAUTO=<uuid>) was saved whole,
// name and `=` included, and the key failed with 401 everywhere it was used.

const crypto = require('crypto');
const { scan } = require('../src/detect');
const { nameFor } = require('../src/capture');

let fail = 0;
const check = (ok, label) => {
  if (!ok) fail++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
};

const uuid = () => crypto.randomUUID();
const b64url = () => crypto.randomBytes(30).toString('base64url');

const NAMES = [
  'MOSKIT_API_KEY_PROTEAUTO',
  'MOSKIT_TOKEN_PROD',
  'API_KEY_MOSKIT',
  'RD_STATION_SECRET_LP',
  'WAVOIP_PASSWORD_PRINCIPAL',
  'moskit_api_key_prod',
];

for (const name of NAMES) {
  for (const gen of [uuid, b64url]) {
    const v = gen();
    const text = `${name}=${v}`;
    const { findings } = scan(text, { message: true });
    const f = findings.find((x) => text.slice(x.start, x.end) === x.value);
    check(!!f && f.value === v, `${name}=<${gen.name}> captures only the value`);
    check(!!f && nameFor(f, text) === name.toUpperCase(), `${name}=<${gen.name}> is named ${name.toUpperCase()}`);
  }
}

// Base64 padding closes a key and stays in it: no `=` in the middle, no split.
for (let i = 0; i < 20; i++) {
  const v = `${crypto.randomBytes(29).toString('base64')}`;
  if (!v.endsWith('=')) continue;
  const text = `segue o token ${v}`;
  const { findings } = scan(text, { message: true });
  check(findings.some((f) => f.value === v), `padded base64 kept whole (${v.replace(/[A-Za-z]/g, 'a').replace(/\d/g, '9').slice(-6)})`);
  break;
}

// An id is not a secret: a UUID under a name with no credential word stays out.
{
  const text = `PROJECT_ID_PROD=${uuid()}`;
  const { findings } = scan(text, { message: true });
  check(findings.length === 0, 'PROJECT_ID_PROD=<uuid> is an id, not captured');
}

// A name that already ends in the credential word keeps working as before.
{
  const v = uuid();
  const text = `MOSKIT_API_KEY=${v}`;
  const { findings } = scan(text, { message: true });
  check(findings.some((f) => f.value === v), 'MOSKIT_API_KEY=<uuid> still captures only the value');
}

console.log(fail ? `assign: ${fail} failed` : 'assign: all passed');
process.exitCode = fail ? 1 : 0;
