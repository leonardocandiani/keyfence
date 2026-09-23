#!/usr/bin/env node
'use strict';
// Hook entry point. Kept tiny: it loads only what the hook needs, so every
// tool call pays the minimum startup cost. Never throws, never exits non-zero.
// `--classify <job>` is the background classifier the prompt hook starts.
const job = process.argv[2] === '--classify' ? process.argv[3] : null;
const task = job ? require('../src/classify-job').run(job) : require('../src/hook').main();
task.catch(() => {}).finally(() => process.exit(0));
