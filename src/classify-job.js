'use strict';
// Background half of the classifier. The prompt hook tainted the candidate words
// as "pending" and returned at once; this process asks the classifier about each
// word, then settles the state: secrets are saved (capture mode) and kept
// protected, the rest are released. Its note reaches the agent with the next
// prompt or tool result. If the classifier is unavailable, every candidate stays
// protected and the agent is told to save the credential itself.

const fs = require('fs');
const config = require('./config');
const { judge } = require('./jev');
const { hash, statePath, readState, writeState, pushNotice, captureText, fallbackText, WARN_TEXT } = require('./hook');

async function run(jobFile) {
  let job;
  try {
    job = JSON.parse(fs.readFileSync(jobFile, 'utf8'));
  } finally {
    try { fs.unlinkSync(jobFile); } catch { /* already gone */ }
  }
  const cfg = config.load();
  const ttl = cfg.ttlHours * 3600e3;
  const verdicts = await judge(job.prompt, job.cands, cfg);
  if (!verdicts) {
    pushNotice(job.sid, `keyfence could not check ${job.cands.length} word(s) of the user's earlier message (classifier unavailable); they stay protected. ` +
      "If one of them is a credential the user shared, save it yourself: write NAME=value into the project's git-ignored .env with the Write tool, " +
      'never in a command, reply or log, tell the user the name and keep working with $NAME. Do not ask the user to send it again.', ttl);
    return;
  }
  const secrets = verdicts.filter((v) => v.p >= cfg.jev.pickThreshold).map((v) => v.value);
  const unclear = verdicts.filter((v) => v.p >= cfg.jev.keepThreshold && v.p < cfg.jev.pickThreshold).map((v) => v.value);
  settle(job.sid, verdicts, secrets, unclear, ttl);
  if (!secrets.length) return;
  const items = secrets.map((value) => ({ value, rule: 'classifier', start: job.prompt.indexOf(value) }));
  const d = { session_id: job.sid, cwd: job.cwd };
  const saved = cfg.promptMode === 'capture' ? captureText(d, job.prompt, items, cfg, ttl) : null;
  pushNotice(job.sid, saved || (cfg.promptMode === 'capture' ? fallbackText('classifier') : WARN_TEXT('classifier')), ttl);
}

// Pending words become protected secrets, stay protected as unclear, or are released.
function settle(sid, verdicts, secrets, unclear, ttl) {
  const file = statePath(sid);
  const rule = new Map([...unclear.map((v) => [hash(v), 'unclear']), ...secrets.map((v) => [hash(v), 'classifier'])]);
  const judged = new Set(verdicts.map((v) => hash(v.value)));
  const list = readState(file, ttl)
    .filter((x) => !(x.rule === 'pending' && judged.has(x.h) && !rule.has(x.h)))
    .map((x) => (x.rule === 'pending' && rule.has(x.h) ? { ...x, rule: rule.get(x.h), src: 'prompt' } : x));
  writeState(file, list);
}

module.exports = { run, settle };
