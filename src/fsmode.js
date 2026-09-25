'use strict';
// Portability of paths and private files. On macOS and Linux a secret file is
// private through its mode (0600, dirs 0700), set where it is written. Windows
// ignores the mode: there the file is private through its NTFS ACL, with the
// inherited entries removed and full control granted to the current user only.

const os = require('os');
const { execFileSync } = require('child_process');

const WIN = process.platform === 'win32';

// Windows paths use backslashes; every path rule is written with slashes.
const slash = (p) => String(p).replace(/\\/g, '/');

function account() {
  const user = os.userInfo().username;
  return process.env.USERDOMAIN ? `${process.env.USERDOMAIN}\\${user}` : user;
}

// Make a file or directory readable by the current user only. No-op off Windows.
function makePrivate(p, { dir = false } = {}) {
  if (!WIN) return;
  try {
    execFileSync('icacls', [p, '/inheritance:r', '/grant:r', `${account()}:${dir ? '(OI)(CI)F' : 'F'}`], { stdio: 'ignore', windowsHide: true });
  } catch { /* best effort: a broken guard must not stall the agent */ }
}

// True when only the current user has an entry in the file's access list.
// Off Windows: the mode has no group or other bits.
function isPrivate(p) {
  if (!WIN) return (require('fs').statSync(p).mode & 0o077) === 0;
  const out = execFileSync('icacls', [p], { encoding: 'utf8', windowsHide: true });
  const user = os.userInfo().username.toLowerCase();
  const entries = out.split(/\r?\n/).slice(0, -1)
    .map((l, i) => (i === 0 ? l.slice(p.length) : l).trim())
    .filter((l) => l.includes(':('));
  return entries.length > 0 && entries.every((l) => l.split(':(')[0].toLowerCase().split('\\').pop() === user);
}

// Replace a file atomically. On Windows a rename over a file another process has
// open fails with EPERM, EACCES or EBUSY for a moment (the background jobs and
// the hook touch the same files), so it is retried briefly before giving up.
function renameRetry(from, to) {
  const fs = require('fs');
  for (let i = 0; ; i++) {
    try { return fs.renameSync(from, to); } catch (e) {
      if (!WIN || i >= 20 || !['EPERM', 'EACCES', 'EBUSY'].includes(e.code)) throw e;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25 + i * 10);
    }
  }
}

module.exports = { WIN, slash, makePrivate, isPrivate, renameRetry };
