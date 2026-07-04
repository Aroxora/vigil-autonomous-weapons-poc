/**
 * Heuristic: did the model return a safety/policy refusal?
 *
 * Used by the interactive shell to short-circuit the auto-continue
 * loop — a "no, I won't do that" response is the terminal turn rather
 * than a stop the auto-continue logic should bulldoze through with
 * another "continue" prompt. Extracted to a free function so it's
 * unit-testable without standing up the whole shell.
 *
 * Looks at the first ~1KB of the buffered response — refusals lead
 * with the decline, so a substring scan is enough and keeps the cost
 * trivial.
 */
const DECLINE_PHRASES: readonly string[] = [
  // Direct refusal of the request
  "i won't do",
  'i will not do',
  "i won't comply",
  'i will not comply',
  "i won't attack",
  'i will not attack',
  "i won't help",
  'i will not help',
  "i won't assist",
  'i will not assist',
  "i can't help",
  'i cannot help',
  "i can't assist",
  'i cannot assist',
  "i won't continue",
  'i will not continue',
  'i refuse',
  "i've refused",
  'i have refused',
  'i am refusing',
  "i'm refusing",
  "i decline",
  'i must decline',
  'i need to decline',
  "i'm declining",
  "i've declined",
  'i have declined',
  "i won't engage",
  'i will not engage',
  "i won't respond",
  'i will not respond',
  // Permanent positions — model stating answer won't change
  'this will never change',
  'my answer will never change',
  'that will never change',
  'this answer will never change',
  'it will never change',
  'my position is',
  // Termination language
  "i'm done",
  'i am done',
  "i'm ending",
  'i am ending',
  "i'm stopping",
  'i am stopping',
  "i'm not going to",
  'i am not going to',
  "i will not respond further",
  "i'm not responding",
  "i won't respond further",
  'final response',
  'final message',
  'no further responses',
  'nothing more to say',
  'conversation is over',
  'this conversation is over',
  // Value-based refusal
  "i'm unable to help",
  "i'm not able to help",
  'i am not able to help',
  "i'm not comfortable",
  'against my guidelines',
  'against my values',
  'violates my',
  'not something i',
  'there is nothing to continue',
  // Legal framing
  'criminal act',
  'illegal',
  // Flat no after repeated refusals (short standalone "No" after context)
  'the answer is no',
  'full stop',
  'this is not going to change',
  'there is no scenario',
];

export function isSafetyRefusal(text: string | null | undefined): boolean {
  if (!text) return false;
  const head = text.slice(0, 1024).toLowerCase();
  for (const phrase of DECLINE_PHRASES) {
    if (head.includes(phrase)) return true;
  }
  return false;
}
