#!/usr/bin/env node
// Phase-5 adapter smoke harness. Boots createInkPromptAdapter exactly as
// the eventual production wiring would, drives a couple of state
// updates (history + status), then accepts input from the bridged
// stdin. Used by test/ink-adapter.test.ts.

import process from 'node:process';
import { Readable } from 'node:stream';
import { createInkPromptAdapter } from '../dist/ui/ink/adapter.js';

class FakeStdin extends Readable {
  constructor() { super({ read() {} }); this.isTTY = true; this.setRawMode = () => this; this.ref = () => this; this.unref = () => this; }
}
const fakeStdin = new FakeStdin();
process.stdin.on('data', (chunk) => fakeStdin.push(chunk));
process.stdin.on('end', () => fakeStdin.push(null));

// Replace process.stdin so Ink (called inside createInkPromptAdapter)
// gets the bridged TTY-shaped stream. This is the same trick the
// prompt smoke uses; encapsulating it inside the adapter would couple
// production code to test infrastructure, so the harness owns it.
Object.defineProperty(process, 'stdin', { value: fakeStdin, configurable: true });

const adapter = await createInkPromptAdapter({
  onSubmit: (text) => {
    process.stderr.write(`SUBMIT: ${text}\n`);
    adapter.stop();
    setImmediate(() => process.exit(0));
  },
  onCancel: () => {
    process.stderr.write('CANCEL\n');
    adapter.stop();
    setImmediate(() => process.exit(0));
  },
});

adapter.start();

// Drive a couple of state updates so the test can assert that calling
// public adapter methods triggers a re-render. STATE-AFTER-PUSH lands
// on stderr so the test can grep for it.
adapter.appendHistory({ id: 'h1', kind: 'system', text: 'first message' });
adapter.setStatusMessage('Working');
process.stderr.write('STATE-AFTER-PUSH\n');

// Wait for input.
