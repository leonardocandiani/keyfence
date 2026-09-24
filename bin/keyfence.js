#!/usr/bin/env node
'use strict';
// A reader that stops early (`| head`) closes the pipe. Stop writing, but let the
// command finish: exiting here would leave an --apply half done behind exit 0.
process.stdout.on('error', (e) => {
  if (e.code !== 'EPIPE') throw e;
  process.stdout.write = () => true;
});
const argv = process.argv.slice(2);
if (argv.length === 1 && ['-v', '-V', '--version'].includes(argv[0])) {
  process.stdout.write(`${require('../src/version').VERSION}\n`);
} else {
  require('../src/cli').main(argv);
}
