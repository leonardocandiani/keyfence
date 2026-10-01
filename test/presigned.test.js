'use strict';
// Pre-signed storage links in tool output pass whole; real credentials around
// them, and writes into tracked files, are still caught. Synthetic values only.

const { spawnSync, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const HOOK = path.join(__dirname, '..', 'bin', 'keyfence-hook.js');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'keyfence-presigned-'));
const repo = path.join(tmp, 'repo');
fs.mkdirSync(repo);
execFileSync('git', ['init', '-q'], { cwd: repo });
const cfgFile = path.join(tmp, 'config.json');
fs.writeFileSync(cfgFile, JSON.stringify({ jev: { enabled: false }, capture: { globalFile: path.join(tmp, 'g', 'secrets.env') } }));
const SID = `presigned-${process.pid}-${Date.now()}`;
const env = { ...process.env, KEYFENCE_CONFIG: cfgFile, KEYFENCE_VAULT_DIR: path.join(tmp, 'vault'), KEYFENCE_VAULT_KEY_FILE: path.join(tmp, 'vault-key'), KEYFENCE_REGISTRY: path.join(tmp, 'registry.json') };

function run(payload) {
  const res = spawnSync(process.execPath, [HOOK], { input: JSON.stringify({ session_id: SID, ...payload }), env, encoding: 'utf8', cwd: repo });
  return res.stdout ? JSON.parse(res.stdout) : null;
}
const post = (tool_response) => run({ hook_event_name: 'PostToolUse', tool_name: 'mcp__elevenlabs__creative_get_flow_run_status', tool_input: {}, tool_response });
const updated = (o) => (o && o.hookSpecificOutput ? o.hookSpecificOutput.updatedToolOutput : undefined);
const decision = (o) => (o && o.hookSpecificOutput && o.hookSpecificOutput.permissionDecision) || 'pass';

const hex = (n) => 'ab12cd34ef56'.repeat(Math.ceil(n / 12)).slice(0, n);
const KEY = 'Zq8Lw3Rk9Tv2Xn7Bm4Cj5Hd6Fg1Sp0Aa';
const GCS = `https://storage.googleapis.com/xi-backend/flows/f1/content.mp3?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=svc-xi%40proj.iam.gserviceaccount.com%2F20261001%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261001T120000Z&X-Goog-Expires=3600&X-Goog-SignedHeaders=host&X-Goog-Signature=${hex(512)}`;
const S3 = `https://bucket.s3.amazonaws.com/a/b.mp3?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=testkeyid%2F20261001%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261001T120000Z&X-Amz-Expires=900&X-Amz-Security-Token=${'Qk9v'.repeat(60)}&X-Amz-SignedHeaders=host&X-Amz-Signature=${hex(64)}`;
const SAS = `https://acct.blob.core.windows.net/c/b.mp3?sv=2023-11-03&se=2026-10-02T00%3A00%3A00Z&sr=b&sp=r&sig=${'Zk3%2Fq8Lw'.repeat(5)}%3D`;
const APIKEY = `https://api.example.io/v1/items?api_key=${KEY}`;

const cases = [];
const check = (name, got, want) => cases.push({ name, got, want, ok: got === want });
const has = (o, s) => JSON.stringify(o).includes(s);

for (const [name, url] of [['GCS', GCS], ['S3', S3], ['Azure SAS', SAS]]) {
  check(`${name} signed URL in tool output passes whole`, post({ content: [{ type: 'text', text: `download: ${url}` }] }) === null, true);
}
check('GCS URL in a JSON field passes whole', post({ outputs: [{ url: GCS, kind: 'audio' }] }) === null, true);

const mixed = updated(post({ text: `${GCS}\nother ${APIKEY}` }));
check('api_key= next to a signed URL is still replaced', !!mixed && !has(mixed, KEY), true);
check('...and the signed URL beside it stays whole', !!mixed && has(mixed, hex(64)), true);

const sneaky = updated(post({ text: `https://api.example.io/x?token=${KEY}&X-Amz-Signature=${hex(64)}` }));
check('token= in a URL that also carries a signature param is replaced', !!sneaky && !has(sneaky, KEY), true);

check('api_key= in a plain URL is replaced', !!updated(post({ text: APIKEY })), true);
check('?token= in a plain URL is replaced', !!updated(post({ text: `see https://x.example.io/cb?token=${KEY} now` })), true);
check('sk-ant key in a plain URL is replaced', !!updated(post({ text: `https://x.io/?k=sk-ant-api03-${'Ab3dE5gH7jK9mN1pQ3sT5vX7zB'.repeat(3)}` })), true);
check('bare password label is replaced', !!updated(post({ text: 'password: Zq8Lw3Rk9Tv2Xn7Bm4Cj' })), true);

const write = (content) => decision(run({ hook_event_name: 'PreToolUse', tool_name: 'Write', tool_input: { file_path: path.join(repo, 'notes.md'), content } }));
check('signed GCS URL into a tracked file is denied', write(`link: ${GCS}`), 'deny');
check('signed S3 URL into a tracked file is denied', write(`link: ${S3}`), 'deny');
check('plain URL into a tracked file is fine', write('link: https://storage.googleapis.com/xi-backend/a.mp3'), 'pass');
const curl = decision(run({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: `curl -sL -o /tmp/a.mp3 '${GCS}'` } }));
check('the agent can download with the signed URL', curl, 'pass');

const failed = cases.filter((c) => !c.ok);
console.log(`presigned: ${cases.length - failed.length}/${cases.length} scenarios ok`);
failed.forEach((c) => console.log(`  FAIL ${c.name}: got ${c.got}, want ${c.want}`));
fs.rmSync(tmp, { recursive: true, force: true });
fs.rmSync(path.join(os.tmpdir(), `keyfence-${SID.replace(/[^A-Za-z0-9_-]/g, '')}.json`), { force: true });
process.exitCode = failed.length ? 1 : 0;
