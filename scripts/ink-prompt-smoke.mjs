#!/usr/bin/env node
// Phase-2 Ink prompt smoke harness. Mounts the Prompt component with a
// FAKE stdin that implements Node's Readable contract (read() + emits
// 'readable') because Ink 7 attaches 'readable' listeners and pulls
// chunks via read(). Real process.stdin is bridged into the fake.
//
// Outcome markers (on stderr, one per line):
//   STATE: <buffer>|<cursor>     — every state change (from Prompt.tsx)
//   SUBMIT: <buffer>             — user pressed Enter
//   CANCEL                       — user pressed Ctrl+C with empty buffer
//
// Stdout carries the rendered Ink frames (consumed-but-not-asserted).

import process from 'node:process';
import { Readable } from 'node:stream';
import React from 'react';
import { render } from 'ink';
import { Prompt } from '../dist/ui/ink/Prompt.js';

process.env['VIGIL_INK_DEBUG'] = '1';

const args = process.argv.slice(2);
const initial = args.includes('--initial') ? args[args.indexOf('--initial') + 1] : '';
const secret = args.includes('--secret');

// Fake stdin: a real Readable in object/byte mode that we push bytes
// into when the parent test pipes them through process.stdin. Adds
// the TTY-shaped fields Ink checks (isTTY + setRawMode) so Ink doesn't
// throw "raw mode is not supported".
class FakeStdin extends Readable {
  constructor() {
    super({ read() {} });
    this.isTTY = true;
    this.setRawMode = () => this;
    this.ref = () => this;
    this.unref = () => this;
  }
}

const fakeStdin = new FakeStdin();
process.stdin.on('data', (chunk) => fakeStdin.push(chunk));
process.stdin.on('end', () => fakeStdin.push(null));

const inst = render(
  React.createElement(Prompt, {
    initial,
    secret,
    onSubmit: (text) => {
      process.stderr.write(`DBG-SUBMIT-CALLED text=${JSON.stringify(text)}\n`);
      // SUBMIT_JSON encodes the buffer as JSON so multi-line text
      // (from a paste) survives the line-oriented stderr parser in
      // ink-prompt.test.ts. SUBMIT (legacy, single-line only) is
      // still emitted for tests that grep on it directly.
      process.stderr.write(`SUBMIT_JSON: ${JSON.stringify(text)}\n`);
      process.stderr.write(`SUBMIT: ${text.replace(/\n/g, ' ')}\n`);
      try { process.stderr.write(''); } catch {}
      // Delay unmount briefly so React commits the post-submit
      // render (where stateRef was reset to '') and the STATE-emit
      // useEffect fires. Without this delay, unmount kills the
      // queued render before STATE: |0 reaches stderr, masking
      // the buffer-clear assertion.
      setTimeout(() => {
        inst.unmount();
        setImmediate(() => process.exit(0));
      }, 50);
    },
    onCancel: () => {
      process.stderr.write('DBG-CANCEL-CALLED\n');
      process.stderr.write('CANCEL\n');
      inst.unmount();
      setImmediate(() => process.exit(0));
    },
    onToggleMode: () => {
      // Emit a marker but DON'T unmount — the test driver may want to
      // verify post-toggle keystrokes still land on the buffer.
      process.stderr.write('TOGGLE-MODE\n');
    },
  }),
  // exitOnCtrlC=false → Ctrl+C reaches the Prompt's useInput handler so
  // our cancel/clear logic runs. Without this Ink intercepts Ctrl+C
  // synchronously and tears down before we see it.
  { stdin: fakeStdin, stdout: process.stdout, exitOnCtrlC: false },
);

await inst.waitUntilExit().catch(() => undefined);
