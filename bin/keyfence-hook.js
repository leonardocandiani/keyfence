#!/usr/bin/env node
'use strict';
// Hook entry point. Kept tiny: it loads only what the hook needs, so every
// tool call pays the minimum startup cost. Never throws, never exits non-zero.
require('../src/hook').main().catch(() => {}).finally(() => process.exit(0));
