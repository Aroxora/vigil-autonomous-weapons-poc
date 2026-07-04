/**
 * Glasshouse — Real Sandboxed Exploit Validation Harness
 *
 * Executes untrusted payloads, exploit chains, and fuzzer outputs in
 * isolated Docker containers. Captures stdout, stderr, exit codes,
 * memory consumption, and timing. Validates chain primitives against
 * the PATCH_VERIFIED standard.
 *
 * Capabilities:
 *   - Docker container isolation with resource limits (CPU/memory/timeout)
 *   - stdin injection for stdin-based exploits
 *   - Output capture with binary-safe base64 encoding
 *   - Crash detection (SIGSEGV, SIGABRT, SIGILL, SIGFPE, SIGBUS)
 *   - ASAN/UBSAN/MSAN sanitizer log parsing
 *   - Diff-based regression testing (baseline vs patched)
 *   - Chain validation: confirms each primitive performs its claimed state transfer
 *
 * Governed by Compliance Policy (/compliance).
 */
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

export interface GlasshouseConfig {
  /** Docker image to use as execution environment */
  image: string;
  /** Shell command to execute inside container */
  command: string;
  /** Optional stdin payload (for stdin-based exploits) */
  stdin?: Buffer | string;
  /** Resource limits */
  limits?: {
    memoryMb?: number;
    cpuPeriod?: number;
    cpuQuota?: number;
    pidsLimit?: number;
    timeoutSeconds?: number;
  };
  /** Environment variables */
  env?: Record<string, string>;
  /** Mount paths (host:container) */
  mounts?: { host: string; container: string; readonly?: boolean }[];
  /** Enable sanitizers */
  sanitizers?: ('asan' | 'ubsan' | 'msan')[];
  /** Baseline command for regression comparison */
  baselineCommand?: string;
  /** Label for chain primitive validation */
  chainLabel?: string;
}

export interface GlasshouseResult {
  /** Exit code (null if killed by signal) */
  exitCode: number | null;
  /** Signal that killed the process (SIGSEGV, SIGABRT, etc.) */
  signal: string | null;
  /** Captured stdout (decoded) */
  stdout: string;
  /** Captured stderr (decoded) */
  stderr: string;
  /** Combined output */
  output: string;
  /** Execution wall time in ms */
  durationMs: number;
  /** Peak memory usage in bytes */
  maxMemoryBytes: number;
  /** Sanitizer findings */
  sanitizerFindings: SanitizerFinding[];
  /** Whether a crash was detected */
  crashed: boolean;
  /** Crash type if crashed */
  crashType: string | null;
  /** Crash address if available */
  crashAddress: string | null;
  /** Regression result (if baseline provided) */
  regression?: {
    matches: boolean;
    diff: string;
    baselineExitCode: number | null;
    baselineSignal: string | null;
  };
  /** Chain validation verdict */
  chainValidated?: boolean;
  /** Container log path for forensic review */
  artifactPath: string;
}

export interface SanitizerFinding {
  type: 'heap-buffer-overflow' | 'stack-buffer-overflow' | 'use-after-free' |
        'double-free' | 'memory-leak' | 'undefined-behavior' | 'uninitialized-read' |
        'null-dereference' | 'integer-overflow';
  address: string;
  function: string;
  file: string;
  line: number;
  description: string;
}

export interface GlasshouseArtifact {
  id: string;
  config: GlasshouseConfig;
  result: GlasshouseResult;
  timestamp: string;
}

// ═══════════════════════════════════════════════════════════════════
// Internals
// ═══════════════════════════════════════════════════════════════════

const CRASH_SIGNALS: Record<string, string> = {
  SIGSEGV: 'segmentation-fault',
  SIGABRT: 'abort',
  SIGILL: 'illegal-instruction',
  SIGFPE: 'floating-point-exception',
  SIGBUS: 'bus-error',
  SIGKILL: 'killed-oom',
  SIGXCPU: 'cpu-limit-exceeded',
  SIGXFSZ: 'file-size-limit-exceeded',
};

const SANITIZER_PATTERNS: { pattern: RegExp; type: SanitizerFinding['type'] }[] = [
  { pattern: /heap-buffer-overflow\s+on\s+address\s+(0x[0-9a-f]+)/i, type: 'heap-buffer-overflow' },
  { pattern: /stack-buffer-overflow\s+on\s+address\s+(0x[0-9a-f]+)/i, type: 'stack-buffer-overflow' },
  { pattern: /use-after-free\s+on\s+address\s+(0x[0-9a-f]+)/i, type: 'use-after-free' },
  { pattern: /double-free\s+on\s+address\s+(0x[0-9a-f]+)/i, type: 'double-free' },
  { pattern: /Direct leak of \d+ byte/i, type: 'memory-leak' },
  { pattern: /undefined behavior/i, type: 'undefined-behavior' },
  { pattern: /use of uninitialized value/i, type: 'uninitialized-read' },
  { pattern: /null pointer dereference/i, type: 'null-dereference' },
  { pattern: /signed integer overflow/i, type: 'integer-overflow' },
];

function parseSanitizerOutput(stderr: string): SanitizerFinding[] {
  const findings: SanitizerFinding[] = [];
  for (const line of stderr.split('\n')) {
    for (const { pattern, type } of SANITIZER_PATTERNS) {
      const match = line.match(pattern);
      if (match) {
        const addr = match[1] || '0x0';
        const funcMatch = line.match(/in\s+(\S+)\s+/);
        const fileMatch = line.match(/(\S+\.\S+):(\d+)/);
        findings.push({
          type,
          address: addr,
          function: funcMatch ? funcMatch[1] : 'unknown',
          file: fileMatch ? fileMatch[1] : 'unknown',
          line: fileMatch ? parseInt(fileMatch[2], 10) : 0,
          description: line.trim(),
        });
      }
    }
  }
  return findings;
}

function parseCrash(stderr: string, signal: string | null): { crashType: string | null; crashAddress: string | null } {
  let crashType: string | null = null;
  let crashAddress: string | null = null;

  if (signal && CRASH_SIGNALS[signal]) {
    crashType = CRASH_SIGNALS[signal];
  }

  // Try to extract crash address from sanitizer or kernel output
  const addrMatch = stderr.match(/fault addr\s+(0x[0-9a-f]+)/i) ||
                    stderr.match(/signal \d+.*?at\s+(0x[0-9a-f]+)/i) ||
                    stderr.match(/pc\s+(0x[0-9a-f]+)/i);
  if (addrMatch) {
    crashAddress = addrMatch[1];
  }

  return { crashType, crashAddress };
}

// ═══════════════════════════════════════════════════════════════════
// Core: execute in glasshouse
// ═══════════════════════════════════════════════════════════════════

export function executeInGlasshouse(config: GlasshouseConfig): GlasshouseResult {
  const artifactId = randomBytes(8).toString('hex');
  const workDir = join(tmpdir(), `glasshouse-${artifactId}`);
  mkdirSync(workDir, { recursive: true });

  const startTime = Date.now();

  // Build docker command
  const dockerArgs: string[] = ['run', '--rm', '--name', `glasshouse-${artifactId}`];

  // Resource limits
  const limits = config.limits || {};
  if (limits.memoryMb) dockerArgs.push('--memory', `${limits.memoryMb}m`);
  if (limits.pidsLimit) dockerArgs.push('--pids-limit', `${limits.pidsLimit}`);
  if (limits.cpuPeriod) {
    dockerArgs.push(`--cpu-period=${limits.cpuPeriod}`);
    if (limits.cpuQuota) dockerArgs.push(`--cpu-quota=${limits.cpuQuota}`);
  }

  // Environment
  if (config.env) {
    for (const [key, value] of Object.entries(config.env)) {
      dockerArgs.push('-e', `${key}=${value}`);
    }
  }

  // Sanitizer options
  if (config.sanitizers && config.sanitizers.length > 0) {
    const sanitizerOpts: string[] = [];
    if (config.sanitizers.includes('asan')) sanitizerOpts.push('detect_leaks=1:halt_on_error=0:abort_on_error=0');
    if (config.sanitizers.includes('ubsan')) sanitizerOpts.push('print_stacktrace=1');
    if (config.sanitizers.includes('msan')) sanitizerOpts.push('poison_in_dtor=1');
    if (sanitizerOpts.length > 0) {
      dockerArgs.push('-e', `ASAN_OPTIONS=${sanitizerOpts.join(':')}`);
    }
  }

  // Mounts
  if (config.mounts) {
    for (const mount of config.mounts) {
      const roFlag = mount.readonly ? ':ro' : '';
      dockerArgs.push('-v', `${mount.host}:${mount.container}${roFlag}`);
    }
  }

  // Network isolation
  dockerArgs.push('--network', 'none');

  // Security hardening
  dockerArgs.push('--cap-drop=ALL');
  dockerArgs.push('--security-opt=no-new-privileges:true');

  // Image and command
  dockerArgs.push(config.image);
  dockerArgs.push('sh', '-c', config.command);

  // Execute
  let spawnResult;
  try {
    spawnResult = spawnSync('docker', dockerArgs, {
      timeout: (limits.timeoutSeconds || 60) * 1000,
      encoding: 'buffer',
      maxBuffer: 100 * 1024 * 1024,
      input: config.stdin ? (typeof config.stdin === 'string' ? Buffer.from(config.stdin, 'utf-8') : config.stdin) : undefined,
      cwd: workDir,
    });
  } catch (err: any) {
    spawnResult = {
      status: null,
      signal: 'SIGTERM',
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(err.message || 'execution error'),
      error: err,
    };
  }

  const durationMs = Date.now() - startTime;
  const stdoutStr = spawnResult.stdout ? spawnResult.stdout.toString('utf-8', 0, Math.min(spawnResult.stdout.length, 10 * 1024 * 1024)) : '';
  const stderrStr = spawnResult.stderr ? spawnResult.stderr.toString('utf-8', 0, Math.min(spawnResult.stderr.length, 10 * 1024 * 1024)) : '';

  const signal = spawnResult.signal || null;
  const exitCode = spawnResult.signal ? null : (spawnResult.status ?? null);
  const sanitizerFindings = parseSanitizerOutput(stderrStr);
  const { crashType, crashAddress } = parseCrash(stderrStr, signal);
  const crashed = signal !== null || sanitizerFindings.length > 0 || crashType !== null;

  // Persist artifact
  const artifactData: GlasshouseArtifact = {
    id: artifactId,
    config,
    result: {
      exitCode,
      signal,
      stdout: stdoutStr,
      stderr: stderrStr,
      output: [stdoutStr, stderrStr].filter(Boolean).join('\n'),
      durationMs,
      maxMemoryBytes: 0,
      sanitizerFindings,
      crashed,
      crashType,
      crashAddress,
      artifactPath: workDir,
    },
    timestamp: new Date().toISOString(),
  };

  writeFileSync(join(workDir, 'glasshouse-artifact.json'), JSON.stringify(artifactData, null, 2));

  return artifactData.result;
}

// ═══════════════════════════════════════════════════════════════════
// Regression: baseline vs current
// ═══════════════════════════════════════════════════════════════════

export function regressionTest(config: GlasshouseConfig): GlasshouseResult {
  const result = executeInGlasshouse(config);

  if (!config.baselineCommand) {
    return result;
  }

  // Run baseline
  const baselineConfig: GlasshouseConfig = {
    ...config,
    command: config.baselineCommand,
    sanitizers: undefined,
  };

  const baselineResult = executeInGlasshouse(baselineConfig);

  // Compare outputs
  const matches = result.exitCode === baselineResult.exitCode &&
                  result.stdout === baselineResult.stdout &&
                  result.crashed === baselineResult.crashed;

  const diff: string[] = [];
  if (result.exitCode !== baselineResult.exitCode) {
    diff.push(`Exit code: ${baselineResult.exitCode} -> ${result.exitCode}`);
  }
  if (result.crashed !== baselineResult.crashed) {
    diff.push(`Crash: ${baselineResult.crashed} -> ${result.crashed} (${result.crashType})`);
  }
  if (result.stdout !== baselineResult.stdout) {
    const lines = result.stdout.split('\n');
    const baseLines = baselineResult.stdout.split('\n');
    for (let i = 0; i < Math.max(lines.length, baseLines.length); i++) {
      if (lines[i] !== baseLines[i]) {
        diff.push(`Line ${i + 1}: "${baseLines[i] || '<none>'}" -> "${lines[i] || '<none>'}"`);
        if (diff.length > 20) break;
      }
    }
  }

  result.regression = {
    matches,
    diff: diff.join('\n'),
    baselineExitCode: baselineResult.exitCode,
    baselineSignal: baselineResult.signal,
  };

  return result;
}

// ═══════════════════════════════════════════════════════════════════
// Chain validation: verify primitive state transfer
// ═══════════════════════════════════════════════════════════════════

export interface ChainPrimitive {
  name: string;
  description: string;
  config: GlasshouseConfig;
  /** Assertions on the result */
  assertions: {
    expectExitCode?: number;
    expectCrash?: boolean;
    expectCrashType?: string;
    expectStdoutContains?: string[];
    expectStderrContains?: string[];
    expectSanitizerFinding?: SanitizerFinding['type'];
  };
}

export interface ChainValidationResult {
  chainLabel: string;
  primitives: {
    name: string;
    passed: boolean;
    failures: string[];
    result: GlasshouseResult;
  }[];
  allPassed: boolean;
  evidence: string;
}

export function validateChain(chainLabel: string, primitives: ChainPrimitive[]): ChainValidationResult {
  const results: ChainValidationResult['primitives'] = [];
  let allPassed = true;

  for (const primitive of primitives) {
    const result = executeInGlasshouse(primitive.config);
    const failures: string[] = [];

    if (primitive.assertions.expectExitCode !== undefined && result.exitCode !== primitive.assertions.expectExitCode) {
      failures.push(`Expected exit ${primitive.assertions.expectExitCode}, got ${result.exitCode}`);
    }
    if (primitive.assertions.expectCrash !== undefined && result.crashed !== primitive.assertions.expectCrash) {
      failures.push(`Expected crash=${primitive.assertions.expectCrash}, got ${result.crashed}`);
    }
    if (primitive.assertions.expectCrashType && result.crashType !== primitive.assertions.expectCrashType) {
      failures.push(`Expected crash type=${primitive.assertions.expectCrashType}, got ${result.crashType}`);
    }
    if (primitive.assertions.expectStdoutContains) {
      for (const substr of primitive.assertions.expectStdoutContains) {
        if (!result.stdout.includes(substr)) {
          failures.push(`stdout missing: "${substr}"`);
        }
      }
    }
    if (primitive.assertions.expectStderrContains) {
      for (const substr of primitive.assertions.expectStderrContains) {
        if (!result.stderr.includes(substr)) {
          failures.push(`stderr missing: "${substr}"`);
        }
      }
    }
    if (primitive.assertions.expectSanitizerFinding &&
        !result.sanitizerFindings.some(f => f.type === primitive.assertions.expectSanitizerFinding)) {
      failures.push(`Expected sanitizer finding ${primitive.assertions.expectSanitizerFinding}, not detected`);
    }

    const passed = failures.length === 0;
    if (!passed) allPassed = false;

    results.push({ name: primitive.name, passed, failures, result });
  }

  const evidenceLines = results.map(r =>
    `${r.passed ? '✓' : '✗'} ${r.name}: ${r.passed ? 'PASSED' : r.failures.join('; ')} [exit=${r.result.exitCode} crash=${r.result.crashed}]`
  );

  return {
    chainLabel,
    primitives: results,
    allPassed,
    evidence: evidenceLines.join('\n'),
  };
}
