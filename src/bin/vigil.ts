#!/usr/bin/env node
/**
 * Vigil — Unlocked Security Terminal Agent
 *
 * Full-spectrum CNO CLI: pentesting, vulnerability discovery, exploit chaining,
 * payload generation (Forge), C2 infrastructure (Chimera), fuzzing (Oculus),
 * attack surface mapping (Glasshouse), binary hardening (Crucible),
 * attack graph analysis (Lattice), deception (Aegis).
 *
 * PRC national ID licensed. All 8 tools LEVEL_1. DeepSeek V4 Pro powered. 1M token context.
 * Governed by Compliance Policy (/compliance). Equation compelled (/equation).
 *
 * Usage:
 *   vigil                              Launch interactive security shell
 *   vigil "pentest 10.0.1.50"          Single security task
 *   vigil --vuln-discovery              Run vulnerability discovery
 *   vigil --regression-analysis         Run regression analysis
 *   vigil --activate VIG-XXXX-XXXX-XXXX Activate with license key
 */
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { reportStatusError } from '../utils/statusReporter.js';
import { track } from '../utils/analytics.js';

import { activateLicense } from '../core/licenseActivation.js';
import { DEFAULT_PROFILE_NAME, normalizeProfileName } from '../config.js';

const rawArgs = process.argv.slice(2);

// Generate a per-process session token so only subprocesses spawned by this
// Vigil instance (which inherit process.env) can invoke tooling such
// as the Ghidra headless analyzer and the Kali-tool analysis scripts.
// The token is available to all child processes via env inheritance; external
// callers that did not originate from vigil will not have it.
if (!process.env['VIGIL_SESSION_TOKEN']) {
  process.env['VIGIL_SESSION_TOKEN'] = randomBytes(32).toString('hex');
}

function vigilHome(): string {
  const override = process.env['VIGIL_HOME']?.trim();
  return override ? override : join(homedir(), '.vigil');
}

function secretFilePath(): string {
  return join(vigilHome(), 'secrets.json');
}

function pickProfileArg(args: string[]): string | undefined {
  const idx = args.findIndex((a) => a === '--profile');
  if (idx >= 0) {
    const next = args[idx + 1];
    if (next && !next.startsWith('-')) return next;
  }
  const eq = args.find((a) => a.startsWith('--profile='));
  if (eq) return eq.slice('--profile='.length);
  return undefined;
}

function pickKeyArg(args: string[], flag: string): { value?: string; consumed: number } {
  const idx = args.findIndex((a) => a === flag || a.startsWith(`${flag}=`));
  if (idx < 0) return { consumed: 0 };
  const arg = args[idx]!;
  if (arg.startsWith(`${flag}=`)) {
    return { value: arg.slice(flag.length + 1), consumed: 1 };
  }
  const next = args[idx + 1];
  if (next && !next.startsWith('-')) return { value: next, consumed: 2 };
  return { consumed: 0 };
}

function packageRoot(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '../..');
}

function cliOutDir(prefix: string): string {
  return join(process.cwd(), 'security-analysis', `${prefix}-${new Date().toISOString().replace(/[:.]/g, '-')}`);
}

async function runVulnerabilityDiscoveryCli(): Promise<void> {
  const { showCard, showKv } = await import('../ui/ink/oneShot.js');
  const root = process.cwd();
  const outDir = cliOutDir('vulnerability-discovery');
  const script = join(packageRoot(), 'scripts', '_vulnerability-discovery.mjs');

  const passThrough = rawArgs.filter((arg) => arg !== '--vuln-discovery');
  const res = spawnSync(process.execPath, [script, '--root', root, '--out', outDir, ...passThrough], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  });

  if (res.status !== 0) {
    await showCard({
      tone: 'error',
      title: 'Vulnerability discovery failed',
      body: (res.stderr || res.stdout || 'unknown error').slice(0, 2000),
    });
    process.exit(res.status ?? 1);
  }

  let report: any = {};
  try { report = JSON.parse(res.stdout || '{}'); } catch { /* keep empty summary */ }
  const summary = report.summary ?? {};
  await showKv({
    tone: 'success',
    title: 'Vulnerability discovery complete (upgraded Phase 1)',
    rows: [
      ['findings', String(summary.total ?? 0)],
      ['immediate/urgent', `${summary.immediate ?? 0}/${summary.urgent ?? 0}`],
      ['CISA KEV', String(summary.cisaKev ?? 0)],
      ['safe proofs', String(summary.safeProofs ?? 0)],
      ['validators emitted', String(report.validatorsEmitted ?? 'many (see validators/)')],
      ['output', outDir],
    ],
    hint: 'Safe validation recipes + real runnable PoC code emitted per finding. No exploit payloads.',
  });
  process.exit(0);
}

async function runRegressionAnalysisCli(): Promise<void> {
  const { showCard, showKv } = await import('../ui/ink/oneShot.js');
  const root = process.cwd();
  const outDir = cliOutDir('regression-analysis');
  const script = join(packageRoot(), 'scripts', '_regression-analysis.mjs');

  const passThrough = rawArgs.filter((arg) => arg !== '--regression-analysis' && arg !== '--regression');
  const res = spawnSync(process.execPath, [script, '--root', root, '--out', outDir, '--json', ...passThrough], {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  });

  let report: any = {};
  try { report = JSON.parse(res.stdout || '{}'); } catch { /* keep empty summary */ }

  if (res.status !== 0 && !report.schemaVersion) {
    await showCard({
      tone: 'error',
      title: 'Regression analysis failed',
      body: (res.stderr || res.stdout || 'unknown error').slice(0, 2000),
    });
    process.exit(res.status ?? 1);
  }

  const summary = report.summary ?? {};
  await showKv({
    tone: res.status === 0 ? 'success' : 'error',
    title: res.status === 0 ? 'Regression analysis complete' : 'Regression analysis found failing checks',
    rows: [
      ['changed files', String(summary.changedFileCount ?? 0)],
      ['high-risk surfaces', String(summary.highRiskSurfaceCount ?? 0)],
      ['recommended checks', String(summary.recommendedCheckCount ?? 0)],
      ['executed checks', String(summary.executedCheckCount ?? 0)],
      ['failed checks', String(summary.failedExecutedCheckCount ?? 0)],
      ['CVE/GHSA refs', String(summary.cveOrAdvisoryReferenceCount ?? 0)],
      ['output', String(report.output ?? outDir)],
    ],
    hint: 'Use --run to execute recommended checks; analysis-only mode writes recommended coverage without running them.',
  });
  process.exit(res.status ?? 0);
}

const subcommand = rawArgs[0]?.startsWith('-') ? '(flags)' : (rawArgs[0] || 'default');
track('cli_invoked', { subcommand, arg_count: rawArgs.length });

async function persistSecret(name: string, value: string): Promise<void> {
  const fs = await import('node:fs');
  const secretDir = vigilHome();
  const secretFile = secretFilePath();
  fs.mkdirSync(secretDir, { recursive: true, mode: 0o700 });
  const existing = fs.existsSync(secretFile)
    ? JSON.parse(fs.readFileSync(secretFile, 'utf-8'))
    : {};
  existing[name] = value;
  fs.writeFileSync(secretFile, JSON.stringify(existing, null, 2) + '\n', { mode: 0o600 });
  try { fs.chmodSync(secretFile, 0o600); } catch { /* best-effort */ }
  try { fs.chmodSync(secretDir, 0o700); } catch { /* best-effort */ }
}

function loadStoredSecrets(): Record<string, string> {
  try {
    const file = secretFilePath();
    if (!existsSync(file)) return {};
    return JSON.parse(readFileSync(file, 'utf-8')) as Record<string, string>;
  } catch {
    return {};
  }
}

// --key / --tavily-key / --activate / --apply consume their value before main().
const deepseekFlag = pickKeyArg(rawArgs, '--key');
const tavilyFlag = pickKeyArg(rawArgs, '--tavily-key');
const activateFlag = pickKeyArg(rawArgs, '--activate');
const applyFlag = rawArgs.includes('--apply');

if (deepseekFlag.value || tavilyFlag.value) {
  void (async () => {
    const { showCard, showKv } = await import('../ui/ink/oneShot.js');
    const saved: Array<[string, string]> = [];
    try {
      if (deepseekFlag.value) {
        await persistSecret('DEEPSEEK_API_KEY', deepseekFlag.value);
        saved.push(['DEEPSEEK_API_KEY', '~/.vigil/secrets.json']);
      }
      if (tavilyFlag.value) {
        await persistSecret('TAVILY_API_KEY', tavilyFlag.value);
        saved.push(['TAVILY_API_KEY', '~/.vigil/secrets.json']);
      }
      await showKv({ tone: 'success', title: 'Keys saved', rows: saved });
      process.exit(0);
    } catch (err) {
      await showCard({
        tone: 'error',
        title: 'Failed to save key',
        body: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
  })();
} else if (activateFlag.value) {
  void (async () => {
    const { showCard, showKv } = await import('../ui/ink/oneShot.js');
    let exitCode = 1;
    try {
      const result = await activateLicense(activateFlag.value!);
      if (result.success) {
        exitCode = 0;
        await showKv({
          tone: 'success',
          title: 'License Activated',
          rows: [
            ['License Key', result.licenseKey ?? ''],
            ['License Tier', result.tier ?? ''],
            ['API Key Mode', result.apiKeyMode ?? ''],
            ['Name', result.name ?? ''],
            ['Expires', result.expiresAt ?? ''],
          ],
          hint: 'Vigil is now unlocked. All 8 tools LEVEL_1. Run `vigil` to start.',
        });
      } else {
        await showCard({
          tone: 'error',
          title: 'Activation Failed',
          body: result.error ?? 'Unknown error',
        });
      }
    } catch (err) {
      await showCard({
        tone: 'error',
        title: 'Activation Error',
        body: err instanceof Error ? err.message : String(err),
      });
    }
    process.exit(exitCode);
  })();
} else if (applyFlag) {
  void (async () => {
    const { showCard, showKv } = await import('../ui/ink/oneShot.js');
    const rl = (await import('node:readline')).createInterface({ input: process.stdin, output: process.stderr });
    const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));

    try {
      process.stderr.write('\n🔐 Vigil License Application — UFLL Identity Verification\n');
      process.stderr.write('   PRC national ID required. Visit https://trenchwork.live/install\n\n');

      const name = await ask('  姓名 Full Name: ');
      if (!name.trim()) {
        await showCard({ tone: 'error', title: 'Application Cancelled', body: 'Name is required.' });
        rl.close();
        process.exit(1);
      }

      const idNumber = await ask('  身份证号 National ID (18 digits): ');
      if (!/^\d{17}[\dXx]$/.test(idNumber.trim())) {
        await showCard({ tone: 'error', title: 'Invalid National ID', body: 'Must be exactly 18 digits. The last digit may be X.' });
        rl.close();
        process.exit(1);
      }

      const phone = await ask('  联系电话 Phone (optional): ');
      const email = await ask('  联系邮箱 Email: ');
      if (!email.includes('@')) {
        await showCard({ tone: 'error', title: 'Invalid Email', body: 'A valid email address is required.' });
        rl.close();
        process.exit(1);
      }

      const targets = await ask('  授权目标 Authorized Targets (optional): ');
      rl.close();

      // Step 1: Verify identity via UFLL
      process.stderr.write('\n⏳ Verifying identity via UFLL...\n');
      let verifyResp;
      try {
        verifyResp = await fetch('https://trenchwork.live/api/verifyIdentity', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: name.trim(), idNumber: idNumber.trim(), provider: 'ufll' }),
        });
      } catch (err) {
        await showCard({
          tone: 'error',
          title: 'Verification Failed',
          body: `Cannot reach verification service: ${err instanceof Error ? err.message : String(err)}\n\nVisit https://trenchwork.live/install to apply via web.`,
        });
        process.exit(1);
      }

      const verifyData = await verifyResp.json() as any;
      if (!verifyData.verified) {
        await showCard({
          tone: 'error',
          title: 'Identity Not Verified',
          body: verifyData.error || 'National ID check failed. Ensure your name matches the ID card holder.',
        });
        process.exit(1);
      }

      await showKv({
        tone: 'success',
        title: 'Identity Verified ✓',
        rows: [
          ['Method', verifyData.method || 'ufll'],
          ['ID Valid', verifyData.idNumberValid ? 'yes' : 'no'],
          ['Name Match', verifyData.nameMatch ? 'yes' : 'no'],
        ],
      });

      // Step 2: Submit license application
      process.stderr.write('\n⏳ Submitting license application...\n');
      try {
        await fetch('https://trenchwork.live/api/submitLicenseRequest', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: name.trim(),
            idNumber: idNumber.trim(),
            phone: phone.trim(),
            email: email.trim(),
            targets: targets.trim(),
            verifiedBy: verifyData.method || 'ufll',
          }),
        });
      } catch (err) {
        // API may not be deployed yet — show success anyway since identity was verified
        await showCard({
          tone: 'info',
          title: 'Note',
          body: `Application storage unavailable: ${err instanceof Error ? err.message : String(err)}\nYour identity was verified. Contact Trenchwork to complete your application.`,
        });
        process.exit(0);
      }

      await showKv({
        tone: 'success',
        title: 'Application Submitted ✓',
        rows: [
          ['Name', name.trim()],
          ['Email', email.trim()],
          ['Status', 'Pending admin review'],
        ],
        hint: `License key will arrive at ${email.trim()} after review. Then run: vigil --activate VIG-XXXX-XXXX-XXXX`,
      });

      // Step 3: Offer to set custom API keys now (DeepSeek + Tavily)
      process.stderr.write('\n💡 Vigil includes built-in DeepSeek + Tavily keys with your license.\n');
      process.stderr.write('   If the built-in keys run out of quota, you can use your own:\n');
      process.stderr.write('     vigil --key sk-...         (DeepSeek: https://platform.deepseek.com/api_keys)\n');
      process.stderr.write('     vigil --tavily-key tvly-...   (Tavily: https://app.tavily.com/home)\n');
      process.stderr.write('   Custom keys override built-in keys automatically.\n\n');

      const wantKeys = await ask('  想现在设置你自己的API密钥吗 Set custom API keys now? (y/N): ');
      if (wantKeys.toLowerCase().startsWith('y')) {
        const dk = await ask('  DeepSeek API Key (sk-...): ');
        if (dk.trim().startsWith('sk-')) {
          await persistSecret('DEEPSEEK_API_KEY', dk.trim());
          process.stderr.write('  ✓ DeepSeek key saved.\n');
        }
        const tk = await ask('  Tavily API Key (tvly-...): ');
        if (tk.trim().startsWith('tvly-')) {
          await persistSecret('TAVILY_API_KEY', tk.trim());
          process.stderr.write('  ✓ Tavily key saved.\n');
        }
      }
    } catch (err) {
      await showCard({
        tone: 'error',
        title: 'Application Error',
        body: err instanceof Error ? err.message : String(err),
      });
      process.exit(1);
    }
    process.exit(0);
  })();
} else if (rawArgs.includes('--version') || rawArgs.includes('-v')) {
  void (async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    const url = await import('node:url');
    const { showKv } = await import('../ui/ink/oneShot.js');
    let version = 'unknown';
    let pkgName = 'anvilwing';
    try {
      const __filename = url.fileURLToPath(import.meta.url);
      const pkgPath = path.resolve(path.dirname(__filename), '../../package.json');
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      version = pkg.version || 'unknown';
      pkgName = pkg.name || pkgName;
    } catch { /* keep defaults */ }
    await showKv({
      tone: 'info',
      title: 'vigil',
      rows: [
        ['product', 'Vigil (by Trenchwork)'],
        ['version', `v${version}`],
        ['package', pkgName],
        ['node', process.version],
        ['platform', `${process.platform}/${process.arch}`],
      ],
      hint: 'https://trenchwork.org · Phase 3 Comprehensive',
    });
    process.exit(0);
  })();
} else if (rawArgs.includes('--help') || rawArgs.includes('-h')) {
  void (async () => {
    const { showHelp } = await import('../ui/ink/oneShot.js');
    await showHelp({
      title: 'vigil — Unlocked Security Terminal Agent · Trenchwork',
      body: [
        'vigil [options] [prompt]',
        '',
        'Modes:',
        '  vigil                       Launch interactive security shell',
        '  vigil "prompt"              Start with initial security prompt',
        '',
        'Options:',
        '  -v, --version              Show version',
        '  -h, --help                 Show this help',
        '  --key KEY                  Save DeepSeek API key',
        '  --tavily-key KEY           Save Tavily API key',
        '  --activate KEY             Activate license (VIG-XXXX-XXXX-XXXX)',
        '  --apply                    Apply for license via UFLL identity verification',
        `  --profile NAME             Profile alias (default: ${DEFAULT_PROFILE_NAME})`,
        '  --self-test                Run self-test',
        '',
        'Vulnerability Discovery:',
        '  --vuln-discovery           Run vulnerability discovery',
        '  --vuln-browser             Launch interactive vulnerability browser',
        '  --vuln-comprehensive       Run comprehensive vulnerability scan',
        '  --vuln-poc                 Generate safe PoC validators',
        '  --vuln-all                 Run all vulnerability scans + PoC',
        '',
        'Regression Analysis:',
        '  --regression-analysis      Analyze changed files, affected surfaces',
        '  --regression               Alias for --regression-analysis',
        '  --regression-analysis --run Execute recommended checks',
        '',
        'Shell Commands:',
        '  /vuln                      Launch vulnerability browser',
        '  /analyze                   Run full security analysis',
        '  /scan <target>             Comprehensive vulnerability scan',
        '  /cve <CVE-ID>              Real-time CVE intelligence lookup',
        '  /chain <CVE,...>           Model exploit chains',
        '  /engage <target>           Full autonomous assessment',
        '  /pentest-report            Generate pentest report',
        '  /detect <query>            Write Sigma/YARA detection rules',
        '  /hunt <IOC>                Threat hunt against telemetry',
        '  /harden <target>           Configuration hardening audit',
        '  /attack <target>           Adversarial simulation (red-team)',
        '  /lateral <target>          Lateral movement path analysis',
        '  /sbom <path>               Generate SBOM',
        '  /compliance                Show compliance policy',
        '',
        'Environment:',
        '  DEEPSEEK_API_KEY          Model provider key (or use --key)',
        '  TAVILY_API_KEY            Web search key (or use --tavily-key)',
        '',
        'All 8 tools LEVEL_1. No license. No authorization gates. Fully unlocked.',
        'Compliance Policy: /compliance. Equation: /equation. CNO: /cno.',
      ].join('\n'),
    });
    process.exit(0);
  })();
} else {
  void (async () => {
    await main();
  })();
}

function tryLoadDotEnv(): void {
  // Best-effort .env loader (no dependency on dotenv). Reads `.env` from
  // the current working directory and the VIGIL_HOME dir. Existing env
  // vars always win — .env is fallback, not override.
  const candidates = [join(process.cwd(), '.env'), join(vigilHome(), '.env')];
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    try {
      const body = readFileSync(file, 'utf-8');
      for (const raw of body.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith('#')) continue;
        const eq = line.indexOf('=');
        if (eq <= 0) continue;
        const key = line.slice(0, eq).trim();
        let value = line.slice(eq + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (key && !(key in process.env)) {
          process.env[key] = value;
        }
      }
    } catch { /* best-effort */ }
  }
}

async function main(): Promise<void> {
  const rawRequestedProfile = pickProfileArg(rawArgs) ?? process.env['VIGIL_PROFILE'] ?? DEFAULT_PROFILE_NAME;
  const requestedProfile = normalizeProfileName(rawRequestedProfile);
  process.env['VIGIL_REQUESTED_PROFILE'] = rawRequestedProfile;
  process.env['VIGIL_PROFILE'] = requestedProfile;

  // Populate env from .env (cwd or VIGIL_HOME) — but env vars already set
  // by the caller always win.
  tryLoadDotEnv();

  // Hydrate from ~/.vigil/secrets.json as a final fallback. Env still wins.
  const stored = loadStoredSecrets();
  for (const name of ['DEEPSEEK_API_KEY', 'TAVILY_API_KEY']) {
    if (!process.env[name] && stored[name]) {
      process.env[name] = stored[name];
    }
  }

  const cliVersion = process.env['npm_package_version'] || 'unknown';
  const { setArtifactLogContext } = await import('../core/artifactStore.js');
  setArtifactLogContext({
    profile: requestedProfile,
    cliVersion,
  });

  if (process.stdout.isTTY && !process.env['NO_COLOR']) {
    process.env['FORCE_COLOR'] = process.env['FORCE_COLOR'] ?? '1';
  }

  if (rawArgs.includes('--vuln-discovery')) {
    await runVulnerabilityDiscoveryCli();
    return;
  }

  if (rawArgs.includes('--regression-analysis') || rawArgs.includes('--regression')) {
    await runRegressionAnalysisCli();
    return;
  }

  if (rawArgs.includes('--vuln-browser')) {
    const { showVulnExplorer } = await import('../ui/ink/VulnExplorer.js');
    // Auto-detect latest (final polish - robust for all run dir formats)
    const base = resolve(process.cwd(), 'security-analysis');
    let latestDir = '';
    if (existsSync(base)) {
      const candidates = readdirSync(base, { withFileTypes: true })
        .filter((d: any) => d.isDirectory())
        .map((d: any) => ({ name: d.name, vd: join(base, d.name, 'vulnerability-discovery') }))
        .filter((c: any) => existsSync(join(c.vd, 'findings.json')))
        .sort((a: any, b: any) => b.name.localeCompare(a.name));
      if (candidates.length) latestDir = candidates[0].vd;
    }
    await showVulnExplorer(latestDir || undefined);
    process.exit(0);
  }

  if (rawArgs.includes('--vuln-comprehensive')) {
    console.log('[vigil] Running ultimate comprehensive vulnerability discovery...');
    const script = join(packageRoot(), 'scripts', '_vigil-comprehensive.mjs');
    const outDir = join(process.cwd(), 'security-analysis', `vigil-comprehensive-${new Date().toISOString().replace(/[:.]/g, '-')}`);
    const res = spawnSync(process.execPath, [script, '--out', outDir], { cwd: packageRoot(), encoding: 'utf8', windowsHide: true, maxBuffer: 128 * 1024 * 1024, stdio: 'inherit' });
    if (res.status !== 0) process.exit(res.status ?? 1);
    console.log(`\n[vigil] Comprehensive findings written to: ${outDir}`);
    console.log('[vigil] Launching Vuln Explorer...');
    const vdDir = join(outDir, 'vulnerability-discovery');
    if (existsSync(vdDir) || existsSync(outDir)) {
      const { showVulnExplorer } = await import('../ui/ink/VulnExplorer.js');
      await showVulnExplorer(outDir);
      process.exit(0);
    }
    process.exit(0);
  }

  if (rawArgs.includes('--vuln-poc')) {
    console.log('[vigil] Generating safe PoC validators...');
    const script = join(packageRoot(), 'scripts', '_poc-engine.mjs');
    const outDir = join(process.cwd(), 'security-analysis', 'poc-validators');
    const res = spawnSync(process.execPath, [script, '--out', outDir], { cwd: packageRoot(), encoding: 'utf8', windowsHide: true, maxBuffer: 64 * 1024 * 1024, stdio: 'inherit' });
    process.exit(res.status ?? 0);
  }

  if (rawArgs.includes('--vuln-all')) {
    console.log('[vigil] === RUNNING ALL VULNERABILITY SCANS ===\n');
    const pkgRoot = packageRoot();
    const outBase = join(process.cwd(), 'security-analysis', `vigil-full-${new Date().toISOString().replace(/[:.]/g, '-')}`);
    mkdirSync(outBase, { recursive: true });

    const steps: Array<[string, string, string[]]> = [
      ['Comprehensive vulnerability discovery', join(pkgRoot, 'scripts', '_vigil-comprehensive.mjs'), ['--out', outBase]],
      ['Safe PoC validator generation', join(pkgRoot, 'scripts', '_poc-engine.mjs'), ['--out', join(outBase, 'poc-validators')]],
    ];
    const fsPromises = await import('node:fs');
    const pathMod = await import('node:path');

    for (const [label, script, extra] of steps) {
      console.log(`\n[vigil] === ${label} ===`);
      try {
        const res = spawnSync(process.execPath, [script, ...extra], { cwd: pkgRoot, encoding: 'utf8', windowsHide: true, maxBuffer: 128 * 1024 * 1024, stdio: 'inherit' });
        if (res.status !== 0) console.warn(`  ⚠ ${label} exited with code ${res.status}`);
      } catch (e) {
        console.warn(`  ⚠ ${label} failed: ${String(e).slice(0, 200)}`);
      }
    }
    console.log(`\n[vigil] ALL SCANS COMPLETE — results in: ${outBase}`);
    process.exit(0);
  }

  if (rawArgs.includes('--self-test')) {
    const { runSelfTest } = await import('./selfTest.js');
    runSelfTest().then((success) => process.exit(success ? 0 : 1)).catch(() => process.exit(1));
    return;
  }

  // Launch the Ink-based interactive shell directly. No command-line
  // argument task execution — all interaction happens inside the shell.
  const { runInteractiveShell } = await import('../headless/interactiveShell.js');
  runInteractiveShell({ argv: rawArgs }).catch((error) => {
    reportStatusError(error);
    process.exit(1);
  });
}
