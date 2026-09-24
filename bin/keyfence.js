#!/usr/bin/env node
'use strict';
// A reader that stops early (`| head`) closes the pipe: that is not an error.
process.stdout.on('error', (e) => { if (e.code === 'EPIPE') process.exit(0); throw e; });
const argv = process.argv.slice(2);
if (argv.length === 1 && ['-v', '-V', '--version'].includes(argv[0])) {
  process.stdout.write(`${require('../src/version').VERSION}\n`);
} else {
  require('../src/cli').main(argv);
}
