#!/usr/bin/env node
// Phase-6 smoke harness for InkPromptController. Exercises the methods
// interactiveShell.ts actually calls, through the same factory so the
// VIGIL_INK gating is real. Outcome markers on stderr.

import process from 'node:process';
import { Readable } from 'node:stream';

class FakeStdin extends Readable {
  constructor() { super({ read() {} }); this.isTTY = true; this.setRawMode = () => this; this.ref = () => this; this.unref = () => this; }
}
const fakeStdin = new FakeStdin();
process.stdin.on('data', (chunk) => fakeStdin.push(chunk));

// Override BOTH process.stdin and process.stdout to look TTY-shaped
// before the factory imports outputMode and computes isPlainOutputMode.
// The cache in outputMode.ts is keyed off whatever process.std* looked
// like at first call; if either reads non-TTY we end up in plain mode
// and the factory routes to the legacy controller, defeating the test.
process.env.VIGIL_INK = '1';
Object.defineProperty(process.stdout, 'isTTY', { value: true, configurable: true });
Object.defineProperty(process, 'stdin', { value: fakeStdin, configurable: true });

const { createPromptController } = await import('../dist/ui/ink/InkPromptController.js');

const events = [];
const ctrl = await createPromptController(fakeStdin, process.stdout, {
  onSubmit: (text) => {
    events.push({ type: 'submit', text });
    process.stderr.write(`SUBMIT: ${text}\n`);
    // Diagnostic: prompt buffer state at the moment the host's
    // onSubmit fires. The InkPromptController wrapper resets the
    // buffer + drives a rerender BEFORE calling this callback, so
    // the buffer must read as '' here. If a stale value leaks
    // through, the post-submit prompt box still shows the typed
    // text (the 1.1.7 bug).
    process.stderr.write(`BUFFER-AFTER-SUBMIT: ${JSON.stringify(ctrl.getBuffer())}\n`);
    finish();
  },
  onQueue: (text) => { events.push({ type: 'queue', text }); },
  onInterrupt: () => { events.push({ type: 'interrupt' }); process.stderr.write('INTERRUPT\n'); finish(); },
  onCtrlC: (info) => { events.push({ type: 'ctrlc', info }); process.stderr.write(`CTRLC: hadBuffer=${info.hadBuffer}\n`); },
  onToggleAutoContinue: () => { events.push({ type: 'toggle-auto' }); },
  onToggleHITL: () => { events.push({ type: 'toggle-hitl' }); },
  onExit: () => { events.push({ type: 'exit' }); process.exit(0); },
});

ctrl.start();

const scenario = process.argv[2];

if (scenario === 'addEvent-flow') {
  // Drive several addEvent calls through the renderer shim. Wait a tick
  // between each so Ink's reconciler commits one frame per addition —
  // without this Ink may coalesce all four into a single first-mount
  // render of <Static>, which it logs differently than incremental
  // appends. The production CLI never adds events at once anyway.
  await new Promise(r => setImmediate(r));
  ctrl.getRenderer().addEvent('banner', 'WELCOME-LINE');
  await new Promise(r => setTimeout(r, 50));
  ctrl.getRenderer().addEvent('system', 'system-line');
  await new Promise(r => setTimeout(r, 50));
  ctrl.getRenderer().addEvent('response', 'assistant-line');
  await new Promise(r => setTimeout(r, 50));
  ctrl.getRenderer().addEvent('tool', 'tool-line');
  await new Promise(r => setTimeout(r, 100));
}

if (scenario === 'mode-toggle') {
  ctrl.setStatusMessage('Working');
  ctrl.toggleAutoContinue();
  ctrl.toggleHITL();
  process.stderr.write(`AUTO: ${ctrl.getAutoMode()}\n`);
  process.stderr.write(`HITL: ${ctrl.getHITLMode()}\n`);
}

if (scenario === 'capture-input') {
  // Set secret mode, capture next submission, verify it resolves with
  // the typed text.
  ctrl.getRenderer().setSecretMode(true);
  const captured = await ctrl.getRenderer().captureInput({ trim: false });
  process.stderr.write(`CAPTURED: ${captured}\n`);
  finish();
}

if (scenario === 'hitl-suspend') {
  // Verify InkPromptController suspends its rendered tree while the
  // raw-mode HITL menu is up, then resumes after prompt-close.
  const hitl = await import('../dist/core/hitl.js');
  // Wait long enough that InkPromptController.startAsync's dynamic
  // imports + Ink mount have resolved AND its prompt-open listener is
  // attached. ctrl.start() is fire-and-forget so we can't await it.
  // Poll up to ~1s for the listener to appear instead of trusting a
  // fixed dwell — under jest's spawn the load can take >150ms.
  for (let i = 0; i < 40; i++) {
    if (hitl.hitlEvents.listenerCount('prompt-open') > 0) break;
    await new Promise(r => setTimeout(r, 25));
  }
  process.stderr.write(`LISTENER-COUNT: ${hitl.hitlEvents.listenerCount('prompt-open')}\n`);
  ctrl.setBuffer('preserved-across-hitl');
  await new Promise(r => setTimeout(r, 30));
  process.stderr.write(`HITL-SUSPENDED-BEFORE: ${ctrl.isHitlSuspended()}\n`);
  hitl.hitlEvents.emit('prompt-open', { id: 'test-prompt' });
  await new Promise(r => setTimeout(r, 30));
  process.stderr.write(`HITL-SUSPENDED-DURING: ${ctrl.isHitlSuspended()}\n`);
  process.stderr.write(`BUFFER-DURING: ${JSON.stringify(ctrl.getBuffer())}\n`);
  hitl.hitlEvents.emit('prompt-close', { id: 'test-prompt' });
  await new Promise(r => setTimeout(r, 30));
  process.stderr.write(`HITL-SUSPENDED-AFTER: ${ctrl.isHitlSuspended()}\n`);
  process.stderr.write(`BUFFER-AFTER: ${JSON.stringify(ctrl.getBuffer())}\n`);
  finish();
}

if (scenario === 'submit-to-history') {
  // The bug: user types "hi", presses Enter, but "hi" never appears in
  // the chat history. The legacy renderer auto-emitted a 'prompt'
  // event from its submit path; the Ink path didn't, so submitted
  // user input was lost from the visible transcript.
  await new Promise(r => setImmediate(r));
  // Drive an Enter through the bridged stdin AFTER seeding the buffer
  // (we set initial via setBuffer) so the onSubmit handler fires.
  ctrl.setBuffer('hello world');
  await new Promise(r => setTimeout(r, 80));
  fakeStdin.push('\r');
  await new Promise(r => setTimeout(r, 250));
}

if (scenario === 'stream-coalesce') {
  // Simulate the agent's message.delta → message.complete sequence.
  // 'thought' events should be filtered from history; 'stream' events
  // should accumulate into a single in-progress message; 'response'
  // commits the final canonical text. The committed history must
  // contain ONE assistant entry with the final text — not one entry
  // per delta.
  await new Promise(r => setImmediate(r));
  ctrl.getRenderer().addEvent('thought', 'this is reasoning the user should NOT see');
  await new Promise(r => setTimeout(r, 30));
  ctrl.getRenderer().addEvent('stream', 'Hi');
  await new Promise(r => setTimeout(r, 30));
  ctrl.getRenderer().addEvent('stream', ' there');
  await new Promise(r => setTimeout(r, 30));
  ctrl.getRenderer().addEvent('stream', '!');
  await new Promise(r => setTimeout(r, 30));
  ctrl.getRenderer().addEvent('response', 'Hi there!');
  await new Promise(r => setTimeout(r, 100));
}

if (scenario === 'tap') {
  let tapped = '';
  const off = ctrl.getRenderer().addOutputTap((kind, content) => {
    tapped += `${kind}=${content};`;
  });
  ctrl.getRenderer().addEvent('system', 'one');
  ctrl.getRenderer().addEvent('response', 'two');
  off();
  ctrl.getRenderer().addEvent('system', 'three');
  process.stderr.write(`TAP: ${tapped}\n`);
}

function finish() {
  ctrl.stop();
  setImmediate(() => process.exit(0));
}

// Drive submit when stdin closes for the addEvent / mode-toggle / tap
// scenarios that don't need user input. capture-input drives its own
// stdin; hitl-suspend exits via finish() so the auto-\r would fire
// after exit and throw on a torn-down stream.
if (!['capture-input', 'hitl-suspend'].includes(scenario)) {
  setTimeout(() => {
    fakeStdin.push('\r');
  }, 300);
}
