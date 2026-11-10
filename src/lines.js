'use strict';
const fs = require('fs');
const { StringDecoder } = require('string_decoder');

// A session log can pass 512 MB, the longest string Node can hold, so
// `readFileSync(file, 'utf8')` throws on it. Reading in blocks keeps memory flat
// and yields the same lines.
function* eachLine(file, blockSize = 8 * 1024 * 1024) {
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(blockSize);
    const decoder = new StringDecoder('utf8');
    let rest = '';
    for (let n = fs.readSync(fd, buf, 0, blockSize, null); n > 0; n = fs.readSync(fd, buf, 0, blockSize, null)) {
      const parts = (rest + decoder.write(buf.subarray(0, n))).split('\n');
      rest = parts.pop();
      yield* parts;
    }
    rest += decoder.end();
    if (rest) yield rest;
  } finally {
    fs.closeSync(fd);
  }
}

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// The lines of `file` that contain at least one of `needles`, the same ones
// `eachLine(file)` would give when filtered with `line.includes(needle)`. One
// regex pass per block finds the matches and only those lines are cut out;
// the daily scan over tens of GB of session logs spent its time splitting and
// testing lines that hold nothing.
function* eachLineWith(file, needles, blockSize = 8 * 1024 * 1024) {
  if (!needles.length) return;
  if (needles.some((n) => n === '')) {
    yield* eachLine(file, blockSize);
    return;
  }
  const re = new RegExp(needles.map(escapeRegex).join('|'), 'g');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.alloc(blockSize);
    const decoder = new StringDecoder('utf8');
    let rest = '';
    for (let n = fs.readSync(fd, buf, 0, blockSize, null); n > 0; n = fs.readSync(fd, buf, 0, blockSize, null)) {
      const text = rest + decoder.write(buf.subarray(0, n));
      const cut = text.lastIndexOf('\n');
      if (cut < 0) {
        rest = text;
        continue;
      }
      rest = text.slice(cut + 1);
      re.lastIndex = 0;
      for (let m = re.exec(text); m && m.index < cut; m = re.exec(text)) {
        const start = text.lastIndexOf('\n', m.index) + 1;
        const stop = text.indexOf('\n', m.index);
        yield text.slice(start, stop);
        re.lastIndex = stop + 1;
      }
    }
    rest += decoder.end();
    re.lastIndex = 0;
    if (rest && re.test(rest)) yield rest;
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { eachLine, eachLineWith };
