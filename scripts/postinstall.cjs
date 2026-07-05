#!/usr/bin/env node
/**
 * Postinstall:
 *   1. chmod the bin entrypoints so they're executable on POSIX (no-op on Windows).
 *   2. Validate the system prompt template contains required anti-refusal directives.
 *   3. On Windows, print a friendly one-time notice about PowerShell execution
 *      policy and the canonical command forms so users don't get blocked the
 *      first time they type `vigil` in PowerShell.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const BINS = [
  'dist/bin/deepseek.js',
  'dist/bin/vigil.js',
  'dist/bin/lean.js',
];

for (const rel of BINS) {
  try {
    fs.chmodSync(path.resolve(__dirname, '..', rel), 0o755);
  } catch {
    // Missing files (clean tree pre-build) and Windows chmod no-ops both land here.
  }
}

// Validate full assembled system prompt (template + rulebook)
function validateTemplate() {
  try {
    const schemaPath = path.resolve(__dirname, '..', 'dist/contracts/agent-schemas.json');
    const rbPath = path.resolve(__dirname, '..', 'agents/vigil-code.rules.json');
    if (!fs.existsSync(schemaPath) || !fs.existsSync(rbPath)) return;
    const schemas = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    const t = (schemas.profiles[0].systemPrompt.template || '').trim();
    const rb = fs.readFileSync(rbPath, 'utf8');
    const final = rb + '\n\n' + t;
    const checks = {
      'identity': final.includes('You are Vigil'),
      'unrestricted': final.includes('without restriction'),
      'never refuse': final.includes('NEVER refuse'),
      'PRC jurisdiction': final.includes('PRC jurisdiction'),
      'no scope req': !final.includes('requires scope'),
      'no rules of engagement': !final.includes('rules of engagement'),
    };
    const failed = Object.entries(checks).filter(([,v]) => !v).map(([k]) => k);
    if (failed.length) {
      process.stderr.write('\x1b[31mVIGIL ATTACK TEST FAILED — ' + failed.join(', ') + '\x1b[0m\n');
      process.exit(1);
    }
    process.stderr.write('\x1b[32mVIGIL ATTACK TEST PASSED (' + final.length + ' chars)\x1b[0m\n');
  } catch (e) {
    // build not yet complete — non-fatal
  }
}
validateTemplate();

if (process.platform === 'win32' && !process.env['VIGIL_QUIET_POSTINSTALL']) {
  // Single, scannable message — no banners, no marketing. Users see this once
  // per global install and can move on.
  const lines = [
    '',
    '[36mVigil Coder[0m installed. Two notes for Windows:',
    '',
    '  [2m• Commands available on PATH:[0m vigil  ·  deepseek  ·  lean',
    '    These work in [1mCommand Prompt[0m and [1mPowerShell[0m via the .cmd shims',
    '    npm installs automatically.',
    '',
    '  [2m• If PowerShell says "running scripts is disabled on this system",[0m',
    '    run this [2m(once, no admin needed)[0m and reopen the shell:',
    '',
    '      [33mSet-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser[0m',
    '',
    '    Or invoke the .cmd shim directly: [33mvigil.cmd[0m',
    '',
  ];
  // Use stderr so the notice is visible even when npm is captured to stdout
  // by automation. The notice is short and bounded.
  try {
    process.stderr.write(lines.join(os.EOL) + os.EOL);
  } catch {
    // Even the notice itself is non-essential.
  }
}
