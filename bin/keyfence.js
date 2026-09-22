#!/usr/bin/env node
'use strict';
const argv = process.argv.slice(2);
if (argv.length === 1 && ['-v', '-V', '--version'].includes(argv[0])) {
  process.stdout.write(`${require('../src/version').VERSION}\n`);
} else {
  require('../src/cli').main(argv);
}
