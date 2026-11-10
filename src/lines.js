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

module.exports = { eachLine };
