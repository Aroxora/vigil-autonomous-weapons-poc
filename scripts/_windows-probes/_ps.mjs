// _ps.mjs — shared PowerShell helper for windows-probes.
// One PowerShell process per probe section (not per query) so we
// don't pay 200ms × 50 forks. Each probe ends its script with
// `ConvertTo-Json -Compress -Depth N`; we parse it back here.

import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const PS_DIR = join(dirname(fileURLToPath(import.meta.url)), 'ps');

/** Read a .ps1 script from the sibling ps/ folder. */
export function readPs(name) {
  return readFileSync(join(PS_DIR, name), 'utf8');
}

const PS_TIMEOUT_MS = 25_000;
const PS_MAX_BUFFER = 32 * 1024 * 1024;

export const IS_WIN = platform() === 'win32';

/**
 * Run a PowerShell script, parse compressed JSON from stdout.
 * Returns `{ ok: true, value }` or `{ ok: false, error, raw }`.
 * Never throws — every probe should keep going on failure.
 */
export function runPs(script, { depth = 4, timeoutMs = PS_TIMEOUT_MS } = {}) {
  if (!IS_WIN) return { ok: false, error: 'non-windows host' };
  const full = `$ProgressPreference='SilentlyContinue';$ErrorActionPreference='SilentlyContinue';try{$x=(${script});if($x -eq $null){'null'}else{$x|ConvertTo-Json -Compress -Depth ${depth}}}catch{[pscustomobject]@{__probeError=$_.Exception.Message}|ConvertTo-Json -Compress}`;
  const r = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', full], {
    encoding: 'utf8', timeout: timeoutMs, maxBuffer: PS_MAX_BUFFER, windowsHide: true,
  });
  const out = (r.stdout ?? '').trim();
  if (!out) {
    return { ok: false, error: (r.stderr || `exit ${r.status}`).slice(0, 400) };
  }
  if (out === 'null') return { ok: true, value: null };
  try {
    const v = JSON.parse(out);
    if (v && typeof v === 'object' && '__probeError' in v) {
      return { ok: false, error: String(v.__probeError).slice(0, 400) };
    }
    return { ok: true, value: v };
  } catch (e) {
    return { ok: false, error: String(e?.message ?? e).slice(0, 200), raw: out.slice(0, 400) };
  }
}

/** Run a PowerShell script that emits raw stdout (no JSON parsing). */
export function runPsRaw(script, { timeoutMs = PS_TIMEOUT_MS } = {}) {
  if (!IS_WIN) return { ok: false, error: 'non-windows host' };
  const r = spawnSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8', timeout: timeoutMs, maxBuffer: PS_MAX_BUFFER, windowsHide: true,
  });
  return { ok: r.status === 0, value: (r.stdout ?? '').trim(), error: r.stderr ? r.stderr.slice(0, 400) : undefined };
}

/** Convenience: time a probe call. */
export async function timed(name, fn) {
  const t0 = Date.now();
  try {
    const value = await fn();
    return { name, ok: true, durationMs: Date.now() - t0, value };
  } catch (e) {
    return { name, ok: false, durationMs: Date.now() - t0, error: String(e?.message ?? e).slice(0, 300) };
  }
}

/** Section-result wrapper used by all packs. */
export function section(name, result) {
  if (result?.ok === false) return { name, ok: false, error: result.error, raw: result.raw };
  return { name, ok: true, value: result?.value ?? result };
}
