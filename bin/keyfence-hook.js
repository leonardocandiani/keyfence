#!/usr/bin/env node
'use strict';
// Hook entry point. Kept tiny: it loads only what the hook needs, so every
// tool call pays the minimum startup cost. Never throws, never exits non-zero.
// `--classify <job>` is the background classifier the prompt hook starts;
// `--name <job>` names a credential saved under a provisional code.
const [flag, job] = process.argv.slice(2);
const task = flag === '--classify' ? require('../src/classify-job').run(job)
  : flag === '--name' ? require('../src/naming').runJob(job)
    : require('../src/hook').main();
task.catch(() => {}).finally(() => process.exit(0));
