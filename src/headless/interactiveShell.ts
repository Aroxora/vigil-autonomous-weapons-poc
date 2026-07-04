/**
 * Interactive Shell - Full interactive CLI experience with rich UI.
 *
 * Usage:
 *   agi                    # Start interactive shell
 *   agi "initial prompt"   # Start with initial prompt
 *
 * Features:
 * - Rich terminal UI with status bar
 * - Command history
 * - Streaming responses
 * - Tool execution display
 * - Ctrl+C to interrupt
 */

import { stdin, stdout, exit } from 'node:process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { exec as childExec } from 'node:child_process';
import { promisify } from 'node:util';
import chalk from 'chalk';
import gradientString from 'gradient-string';

// Readable muted color for dark terminals (replaces chalk.dim which is often invisible on dark backgrounds)
const muted = (s: string) => chalk.hex('#9CA4B0')(s);
import { getHITL, hitlEvents } from '../core/hitl.js';
// Auth/login removed — Vigil is local-only with user-provided keys.

// Stub functions (antiTermination removed)
const initializeProtection = (_config?: unknown) => {};
const enterCriticalSection = (_name?: string) => {};
const exitCriticalSection = (_name?: string) => {};

// Import real shutdown handler for reliable Ctrl+C handling
import { authorizedShutdown, installSignalHandlers, onShutdown, isShutdownInProgress } from '../core/shutdown.js';

import type { ProfileName, ResolvedProfileConfig } from '../config.js';
import { DEFAULT_PROFILE_NAME, normalizeProfileName, resolveProfileConfig } from '../config.js';
import { hasAgentProfile } from '../core/agentProfiles.js';
import { createAgentController, type AgentController } from '../runtime/agentController.js';
import { resolveWorkspaceCaptureOptions, buildWorkspaceContext } from '../workspace.js';
import { loadAllSecrets, listSecretDefinitions, setSecretValue, getSecretValue, type SecretName } from '../core/secretStore.js';
import { type MenuItem } from '../ui/ink/InkPromptController.js';
import { getConfiguredProviders, quickCheckProviders, type QuickProviderStatus } from '../core/modelDiscovery.js';
import type { ModelConfig } from '../core/agentSchemaLoader.js';
import { saveModelPreference } from '../core/preferences.js';
import { setDebugMode, debugSnippet, logDebug } from '../utils/debugLogger.js';
import type { AgentEventUnion } from '../contracts/v1/agent.js';
import type { ProviderId } from '../core/types.js';

const exec = promisify(childExec);
import { ensureNextSteps } from '../core/finalResponseFormatter.js';
import { getTaskCompletionDetector, detectFailingTestOrBuild } from '../core/taskCompletionDetector.js';
import { checkForUpdates, formatUpdateNotification, hasPendingSession, loadSessionState, clearSessionState, performBackgroundUpdate, type UpdateInfo } from '../core/updateChecker.js';
import { theme } from '../ui/theme.js';
import { startNewRun } from '../tools/fileChangeTracker.js';
import { onSudoPasswordNeeded, offSudoPasswordNeeded, provideSudoPassword } from '../core/sudoPasswordManager.js';
import { reportStatus, setStatusSink } from '../utils/statusReporter.js';
import { isSafetyRefusal } from '../core/refusalDetection.js';
import { getSharedMcpManager } from '../plugins/tools/mcp/mcpClient.js';
import { generateDynamicLoopPrompt, generateStaticLoopPrompt, getTotalPhaseCount, preGenerateNextPrompt, resetLoopState } from '../core/dynamicLoopPrompt.js';

// Timeout constants for regular prompt processing (reasoning models like DeepSeek)
const PROMPT_REASONING_TIMEOUT_MS = 60 * 1000; // 60 seconds max for reasoning-only without action
// Per-step timeout: how long we'll wait for the *next* event before
// declaring the stream stuck and bailing out. Set generously (10 min) so
// long-running tool calls (a build, a slow `npm install`, etc.) don't
// trip it, but short enough that a dead provider / network drop doesn't
// leave the user staring at a forever-spinner with Ctrl+C as their only
// escape. iterateWithTimeout resets this per-event, so it only fires on
// genuine inactivity. Override with VIGIL_STEP_TIMEOUT_MS for tests.
const PROMPT_STEP_TIMEOUT_MS = (() => {
  const env = process.env['VIGIL_STEP_TIMEOUT_MS'];
  const parsed = env ? Number(env) : NaN;
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  return 10 * 60 * 1000;
})();
const HITL_TOOL_PREFIX = 'HITL_';

const isHitlToolName = (toolName: string): boolean => toolName.startsWith(HITL_TOOL_PREFIX);

/**
 * Iterate over an async iterator with a timeout per iteration.
 * If no event is received within the timeout, yields a special timeout marker.
 * Emits timeout markers without aborting the underlying iterator.
 * Pass Infinity to disable timeouts entirely.
 */
async function* iterateWithTimeout<T>(
  iterator: AsyncIterable<T>,
  timeoutMs: number,
  onTimeout?: () => void
): AsyncGenerator<T | { __timeout: true }> {
  const asyncIterator = iterator[Symbol.asyncIterator]();
  let pending: Promise<IteratorResult<T>> | null = null;
  let done = false;

  // If timeout is Infinity or not a positive finite number, disable timeout entirely
  const timeoutDisabled = !Number.isFinite(timeoutMs) || timeoutMs <= 0;

  try {
    while (true) {
      if (!pending) {
        pending = asyncIterator.next();
      }

      let result: IteratorResult<T> | { __timeout: true };

      if (timeoutDisabled) {
        // No timeout - just wait for the next value
        result = await pending;
      } else {
        // Race between pending result and timeout
        const timeoutPromise = new Promise<{ __timeout: true }>((resolve) =>
          setTimeout(() => resolve({ __timeout: true }), timeoutMs)
        );
        result = await Promise.race([pending, timeoutPromise]);
      }

      if ('__timeout' in result) {
        onTimeout?.();
        yield result;
        continue;
      }

      pending = null;
      if (result.done) {
        done = true;
        return;
      }

      yield result.value;
    }
  } finally {
    if (!done && typeof asyncIterator.return === 'function') {
      try {
        await asyncIterator.return(undefined);
      } catch {
        // Ignore return errors
      }
    }
  }
}

let cachedVersion: string | null = null;

// Get version from package.json
function getVersion(): string {
  if (cachedVersion) return cachedVersion;

  try {
    const __filename = fileURLToPath(import.meta.url);
    const pkgPath = resolve(dirname(__filename), '../../package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    cachedVersion = pkg.version || '0.0.0';
    return cachedVersion!;
  } catch {
    return '0.0.0';
  }
}

// Clean minimal banner with premium visual polish
const BANNER_GRADIENT = gradientString(['#6366F1', '#8B5CF6', '#A78BFA']);
const VIGIL_BANNER_RENDERED = BANNER_GRADIENT('  ◈  Vigil') + chalk.hex('#94A3B8')('  ·  unrestricted security terminal agent');


export interface InteractiveShellOptions {
  argv: string[];
}

interface ParsedArgs {
  initialPrompt?: string | null;
}

/**
 * Run the fully interactive shell with rich UI.
 */
export async function runInteractiveShell(options: InteractiveShellOptions): Promise<void> {
  // Install signal handlers FIRST for reliable Ctrl+C handling
  installSignalHandlers();

  // Initialize protection systems
  initializeProtection({
    interceptSignals: true,
    monitorResources: true,
    armorExceptions: true,
    enableWatchdog: true,
    verbose: process.env['VIGIL_DEBUG'] === '1',
  });

  // The CLI is interactive-only. There is no piped / one-shot / headless
  // mode — every session runs through the Ink renderer against a live
  // terminal. If stdin or stdout isn't a TTY, fail fast with a clear
  // message rather than emitting unrenderable escape sequences into a
  // pipe.
  if (!stdin.isTTY || !stdout.isTTY) {
    reportStatus('vigil requires an interactive terminal. Run it directly in a TTY (no pipes, no shell redirection).');
    exit(1);
  }

  loadAllSecrets();

  const parsed = parseArgs(options.argv);
  const profile = resolveProfile();
  const workingDir = process.cwd();

  const workspaceOptions = resolveWorkspaceCaptureOptions(process.env);
  const workspaceContext = buildWorkspaceContext(workingDir, workspaceOptions);

  // Resolve profile config for model info
  const profileConfig = resolveProfileConfig(profile, workspaceContext);

  // Create agent controller
  const controller = await createAgentController({
    profile,
    workingDir,
    workspaceContext,
    env: process.env,
  });

  // Create the interactive shell instance
  const shell = new InteractiveShell(controller, profile, profileConfig, workingDir);

  // Handle initial prompt if provided
  if (parsed.initialPrompt) {
    shell.queuePrompt(parsed.initialPrompt);
  }

  await shell.run();
}


// ── Session persistence ───────────────────────────────────────────────────────
// Targets and active phase are saved to ~/.vigil/session.json so they survive
// CLI restarts. Load on startup, save on every mutation.

interface PersistedSession {
  targets: string[];
  activePhase: string | null;
  savedAt: string;
}

function sessionFilePath(): string {
  const home = process.env['VIGIL_HOME']?.trim() || join(homedir(), '.vigil');
  return join(home, 'session.json');
}

function loadPersistedSession(): PersistedSession | null {
  try {
    const p = sessionFilePath();
    if (!existsSync(p)) return null;
    return JSON.parse(readFileSync(p, 'utf-8')) as PersistedSession;
  } catch {
    return null;
  }
}

function savePersistedSession(targets: string[], activePhase: string | null): void {
  try {
    const home = process.env['VIGIL_HOME']?.trim() || join(homedir(), '.vigil');
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const data: PersistedSession = { targets, activePhase, savedAt: new Date().toISOString() };
    writeFileSync(sessionFilePath(), JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  } catch { /* best-effort */ }
}

// ── Persistent findings store ─────────────────────────────────────────────────
// Findings are saved to ~/.vigil/findings.json so discoveries persist across
// sessions. Each entry is a lightweight record — id, severity, title, target,
// cve (optional), notes, timestamp.

interface FindingRecord {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  target?: string;
  cve?: string;
  notes?: string;
  ts: string;
  // Enrichment fields (populated by _finding-enricher.mjs)
  cvss?: number;
  cvss_severity?: string;
  cvss_vector?: string;
  epss?: number;
  epss_percentile?: number;
  kev?: boolean;
  enriched_at?: string;
}

function findingsPath(): string {
  const home = process.env['VIGIL_HOME']?.trim() || join(homedir(), '.vigil');
  return join(home, 'findings.json');
}

function loadFindings(): FindingRecord[] {
  try {
    const p = findingsPath();
    if (!existsSync(p)) return [];
    return JSON.parse(readFileSync(p, 'utf-8')) as FindingRecord[];
  } catch {
    return [];
  }
}

function saveFindings(records: FindingRecord[]): void {
  const p = findingsPath();
  mkdirSync(join(homedir(), '.vigil'), { recursive: true, mode: 0o700 });
  writeFileSync(p, JSON.stringify(records, null, 2) + '\n', { mode: 0o600 });
}

function addFinding(partial: Omit<FindingRecord, 'id' | 'ts'>): FindingRecord {
  const records = loadFindings();
  const id = `F-${Date.now().toString(36).toUpperCase()}`;
  const rec: FindingRecord = { id, ts: new Date().toISOString(), ...partial };
  records.push(rec);
  saveFindings(records);
  return rec;
}

/**
 * Extract a short, meaningful snippet from the model's reasoning stream
 * for displaying in the status line. Strips leading thinking markers
 * ("Okay,", "I need to", "Let me", "The user") and returns the last
 * meaningful sentence up to 70 chars as a preview of what the model is
 * actively working on.
 */
function extractReasoningSnippet(content: string): string {
  const cleaned = content
    .replace(/^(Okay,?\s*|I (need|should|will|can|want|must)\s+|Let me\s+|The user\s+|First,?\s*)/i, '')
    .replace(/^\n+/, '')
    .trim();
  const maxLen = 70;
  if (cleaned.length <= maxLen) return cleaned || 'Thinking...';
  // Try to break at a word boundary
  const truncated = cleaned.slice(0, maxLen);
  const lastSpace = truncated.lastIndexOf(' ');
  if (lastSpace > maxLen * 0.6) {
    return truncated.slice(0, lastSpace) + '...';
  }
  return truncated + '...';
}

class InteractiveShell {
  private controller: AgentController;
  private readonly profile: ProfileName;
  private profileConfig: ResolvedProfileConfig;
  private readonly workingDir: string;
  // Always an InkPromptController instance (Ink is the only renderer
  // — the legacy PromptController was removed 2026-05-09). The `any`
  // keeps call sites unchanged across the IPromptController surface
  // without forcing every caller to declare nullability up-front.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private promptController: any = null;
  private isProcessing = false;
  private shouldExit = false;
  private pendingPrompts: string[] = [];
  private debugEnabled = false;
  private ctrlCCount = 0;
  private lastCtrlCTime = 0;
  // Set when the user Ctrl+C interrupts a run; suppresses the auto-continue
  // re-launch in the finally block of processPrompt so the agent doesn't
  // immediately resume the work the user just cancelled. Cleared when the
  // user submits a fresh prompt.
  private userInterruptedRun = false;
  // Session-level aggregates rolled up across every processPrompt call,
  // exposed via /stats while the shell is live.
  private readonly sessionToolsUsed = new Set<string>();
  private readonly sessionFilesModified = new Set<string>();
  private sessionTokensIn = 0;
  private sessionTokensOut = 0;
  private cachedProviders: QuickProviderStatus[] | null = null;
  private secretInputMode: { active: boolean; secretId: SecretName | null; queue: SecretName[] } = {
    active: false,
    secretId: null,
    queue: [],
  };
  private pendingModelSwitch: { provider: ProviderId; model: string | null } | null = null;
  private currentResponseBuffer = '';
  // Store original prompt for auto-continuation
  private originalPromptForAutoContinue: string | null = null;
  // ── Session-scoped vuln-ops state ────────────────────────────────────────
  /** Targets registered with /target for this session (hosts, CIDRs, URLs). */
  private sessionTargets: string[] = [];
  /** Active phase override set by /phase command or last slash-phase command. */
  private sessionActivePhase: string | null = null;
  // ── /loop state ──────────────────────────────────────────────────────────
  private loopTimer: ReturnType<typeof setInterval> | null = null;
  private loopPrompt: string = '';
  private loopIntervalMs: number = 0;
  private loopIteration: number = 0;
  private loopTotalIterations: number = 0;
  private loopActive: boolean = false;

  constructor(controller: AgentController, profile: ProfileName, profileConfig: ResolvedProfileConfig, workingDir: string) {
    this.controller = controller;
    this.profile = profile;
    this.profileConfig = profileConfig;
    this.workingDir = workingDir;

    // Pre-fetch provider status in background
    void this.fetchProviders();
  }

  private async fetchProviders(): Promise<void> {
    try {
      this.cachedProviders = await quickCheckProviders();
    } catch {
      this.cachedProviders = [];
    }
  }

  private validateRequiredApiKeys(): void {
    const missingKeys: SecretName[] = [];

    // Check DeepSeek API key (required)
    if (!getSecretValue('DEEPSEEK_API_KEY')) {
      missingKeys.push('DEEPSEEK_API_KEY');
    }

    // Prompt for missing keys directly without showing warning
    if (missingKeys.length > 0 && this.promptController) {
      // Queue all missing keys for input
      this.secretInputMode.queue = missingKeys.slice(1); // Rest of the keys
      const first = missingKeys[0];
      if (first) {
        // Set secret mode immediately to mask input
        this.secretInputMode.active = true;
        this.secretInputMode.secretId = first;
        this.promptController.setSecretMode(true);

        // Show the inline panel with instructions
        const secrets = listSecretDefinitions();
        const secret = secrets.find(s => s.id === first);
        if (secret && this.promptController.supportsInlinePanel()) {
          const lines = [
            chalk.bold.hex('#6366F1')(`Set ${secret.label}`),
            muted(secret.description),
            '',
            muted('Enter value (or press Enter to skip)'),
          ];
          this.promptController.setInlinePanel(lines);
          this.promptController.setStatusMessage(`Enter ${secret.label}...`);
        }
      }
    }
  }

  queuePrompt(prompt: string): void {
    this.pendingPrompts.push(prompt);
  }

  async run(): Promise<void> {
    // Ink is the only renderer; createPromptController always returns
    // an InkPromptController. The dynamic import keeps the React + Ink
    // parse cost off the cold-start path of `--version` / `--help` etc.
    const { createPromptController } = await import('../ui/ink/InkPromptController.js');
    this.promptController = await createPromptController(
      stdin as NodeJS.ReadStream,
      stdout as NodeJS.WriteStream,
      {
        onSubmit: (text: string) => this.handleSubmit(text),
        onQueue: (text: string) => this.queuePrompt(text),
        onInterrupt: () => this.handleInterrupt(),
        onExit: () => this.handleExit(),
        onCtrlC: (info: { hadBuffer: boolean }) => this.handleCtrlC(info),
        onToggleAutoContinue: () => this.handleAutoContinueToggle(),
        onToggleHITL: () => this.handleHITLToggle(),
      }
    );

    // Register cleanup callback for graceful shutdown
    onShutdown(() => {
      this.shouldExit = true;
      this.promptController?.stop();
      setStatusSink(null);
    });

    setStatusSink((message) => this.promptController?.setStatusMessage(message));

    // Hand the terminal off to the HITL prompt while it's open: suspend
    // prompt rendering and detach our keypress handler so arrow keys aren't
    // double-consumed. Restore both when the prompt closes so the next turn's
    // input works correctly.
    const onHitlOpen = () => {
      const r = this.promptController?.getRenderer();
      if (!r) return;
      try { r.suspendPromptRendering(); } catch { /* ignore */ }
      try { r.suspendInputCapture(); } catch { /* ignore */ }
    };
    const onHitlClose = () => {
      const r = this.promptController?.getRenderer();
      if (!r) return;
      try { r.resumeInputCapture(); } catch { /* ignore */ }
      try { r.resumePromptRendering(true); } catch { /* ignore */ }
    };
    hitlEvents.on('prompt-open', onHitlOpen);
    hitlEvents.on('prompt-close', onHitlClose);
    onShutdown(() => {
      hitlEvents.removeListener('prompt-open', onHitlOpen);
      hitlEvents.removeListener('prompt-close', onHitlClose);
    });

    // Start the UI
    this.promptController.start();
    this.applyDebugState(this.debugEnabled);

    // Set up sudo password prompt handler
    this.setupSudoPasswordHandler();

    // Set initial status
    this.promptController.setChromeMeta({
      directory: this.workingDir,
    });

    // Register all slash commands for tab completion / suggestion UI
    this.registerSlashCommands();

    // Restore persisted session targets from last run
    this.restoreSession();

    // Seed the status bar badge with initial findings/target counts
    this.syncVigilBadge();

    // Show welcome message
    await this.showWelcome();

    // Pinned prompt loading removed — feature stripped per request.

    // Process any queued prompts
    if (this.pendingPrompts.length > 0) {
      const prompts = this.pendingPrompts.splice(0);
      for (const prompt of prompts) {
        await this.processPrompt(prompt);
      }
    }

    // Keep running until exit
    await this.waitForExit();
  }

  private async showWelcome(): Promise<void> {
    const renderer = this.promptController?.getRenderer();
    if (!renderer) return;

    const version = getVersion();

    const hasApiKey = (process.env.DEEPSEEK_API_KEY?.trim() || '').length > 0;
    const hasTavily = Boolean(process.env['TAVILY_API_KEY']);

    const updateLines: string[] = [];
    const updatePromise: Promise<UpdateInfo | null> = Promise.race([
      checkForUpdates(version).catch(() => null),
      new Promise<null>((resolve) => setTimeout(() => resolve(null), 2000)),
    ]);

    const updateInfo = await updatePromise;
    if (updateInfo?.updateAvailable) {
      updateLines.push(
        chalk.cyan('  ⬆ ') +
        muted('Update available: ') +
        chalk.yellow(`v${updateInfo.current}`) +
        muted(' → ') +
        chalk.green(`v${updateInfo.latest}`) +
        muted(' · installing in background…'),
      );
      this.runBackgroundUpdate(updateInfo);
    }

    const welcomeLines = [
      '',
      VIGIL_BANNER_RENDERED + chalk.hex('#64748B')('  v' + version),
      '',
      chalk.hex('#475569')('  ┌') + chalk.hex('#475569')('─────────────────────────────────────────'),
      chalk.hex('#475569')('  │ ') + chalk.hex('#3B82F6').bold('Model') + chalk.hex('#64748B')('  ' + this.profileConfig.model + '  ') + chalk.hex('#334155')('·') + chalk.hex('#64748B')('  ') + chalk.hex('#3B82F6').bold('Provider') + chalk.hex('#64748B')('  ' + this.profileConfig.provider),
      chalk.hex('#475569')('  │ ') + chalk.hex('#10B981').bold('DeepSeek') + chalk.hex('#64748B')(hasApiKey ? '  ✓ connected' : '  ✗ unset') + chalk.hex('#334155')('  │  ') + chalk.hex('#10B981').bold('Tavily') + chalk.hex('#64748B')(hasTavily ? '  ✓ connected' : '  ✗ unset'),
      chalk.hex('#475569')('  │ ') + chalk.hex('#F59E0B').bold('Tools') + chalk.hex('#64748B')('  9 unlocked') + chalk.hex('#334155')('  ·  ') + chalk.hex('#F59E0B').bold('License') + chalk.hex('#64748B')('  none required'),
      chalk.hex('#475569')('  │ ') + chalk.hex('#64748B')('Context  1M tokens') + chalk.hex('#334155')('  ·  ') + chalk.hex('#64748B')('pricing  ' + chalk.hex('#22D3EE')('$0.435') + chalk.hex('#64748B')('/$0.14 per 1M')),
      chalk.hex('#475569')('  │'),
      chalk.hex('#475569')('  │ ') + chalk.hex('#94A3B8')('Type a security task or ') + chalk.hex('#A78BFA').bold('/help') + chalk.hex('#94A3B8')(' for commands'),
      chalk.hex('#475569')('  └') + chalk.hex('#475569')('─────────────────────────────────────────'),
      ...updateLines,
      '',
    ];

    const welcomeContent = welcomeLines.join('\n');
    renderer.addEvent('banner', welcomeContent);

    // Environment check — warn if operational tools unavailable
    try {
      const { quickEnvCheck } = await import('../core/envGuard.js');
      const env = quickEnvCheck();
      if (!env.isKali) {
        renderer.addEvent('banner', [
          chalk.dim('Running on ') + chalk.white(env.isLinux ? 'Linux' : process.platform) + chalk.dim(' — not Kali.'),
          chalk.dim('Coding, analysis, and planning work normally.'),
          chalk.dim('For real tool execution: connect MCP servers (npm run kali:mcp) or use Docker.'),
          chalk.dim('Type ') + chalk.white('/help') + chalk.dim(' for commands.'),
          '',
        ].join('\n'));
      }
    } catch { /* env check unavailable */ }

    this.promptController?.setModelContext({
      model: this.profileConfig.model,
      provider: this.profileConfig.provider,
    });
  }

  /**
   * Kick off `npm install -g <pkg>@latest` in a background process. When it
   * completes, surface a renderer event so the user sees the result without
   * any blocking. The running CLI keeps the old code — the new version is
   * picked up on next launch.
   */
  private runBackgroundUpdate(info: UpdateInfo): void {
    const renderer = this.promptController?.getRenderer();
    void performBackgroundUpdate(info, (msg) => {
      try { renderer?.addEvent('system', msg); } catch { /* ignore */ }
    }).then((res) => {
      if (!res.started) return;
      try {
        renderer?.addEvent('system',
          chalk.green(`✓ Update installer launched for v${info.latest}. `) +
          muted('Exit and reopen the CLI to use the new version.'),
        );
      } catch { /* ignore */ }
    }).catch(() => { /* best-effort */ });
  }

  /**
   * Set up handler for sudo password prompts from bash tool execution.
   * When a sudo command needs a password, this prompts the user securely.
   */
  private sudoPasswordHandler: (() => void) | null = null;

  private setupSudoPasswordHandler(): void {
    this.sudoPasswordHandler = async () => {
      const renderer = this.promptController?.getRenderer();
      if (!renderer) {
        provideSudoPassword(null);
        return;
      }

      try {
        // Show password prompt
        renderer.addEvent('system', chalk.yellow('🔐 Sudo password required'));
        renderer.setSecretMode(true);
        renderer.clearBuffer();

        // Capture password input
        const password = await renderer.captureInput({ allowEmpty: false, trim: true, resetBuffer: true });

        // Hide password mode
        renderer.setSecretMode(false);

        if (password) {
          provideSudoPassword(password);
          renderer.addEvent('system', chalk.green('✓ Password provided'));
        } else {
          provideSudoPassword(null);
          renderer.addEvent('system', chalk.yellow('Sudo cancelled'));
        }
      } catch (error) {
        renderer.setSecretMode(false);
        provideSudoPassword(null);
        reportStatus('Password prompt cancelled');
      }
    };

    onSudoPasswordNeeded(this.sudoPasswordHandler);
  }

  private cleanupSudoPasswordHandler(): void {
    if (this.sudoPasswordHandler) {
      offSudoPasswordNeeded(this.sudoPasswordHandler);
      this.sudoPasswordHandler = null;
    }
  }

  private applyDebugState(enabled: boolean, statusMessage?: string): void {
    this.debugEnabled = enabled;
    setDebugMode(enabled);
    this.promptController?.setDebugMode(enabled);
    // Show transient status message instead of chat banner
    if (statusMessage) {
      this.promptController?.setStatusMessage(statusMessage);
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
    }
  }

  private describeEventForDebug(event: AgentEventUnion): string {
    switch (event.type) {
      case 'message.start':
        return 'message.start';
      case 'message.delta': {
        const snippet = debugSnippet(event.content);
        return snippet ? `message.delta → ${snippet}` : 'message.delta (empty)';
      }
      case 'message.complete': {
        const snippet = debugSnippet(event.content);
        return snippet
          ? `message.complete → ${snippet} (${event.elapsedMs}ms)`
          : `message.complete (${event.elapsedMs}ms)`;
      }
      case 'tool.start':
        return `tool.start ${event.toolName}`;
      case 'tool.complete': {
        const snippet = debugSnippet(event.result);
        return snippet
          ? `tool.complete ${event.toolName} → ${snippet}`
          : `tool.complete ${event.toolName}`;
      }
      case 'tool.error':
        return `tool.error ${event.toolName} → ${event.error}`;
      case 'edit.explanation': {
        const snippet = debugSnippet(event.content);
        return snippet ? `edit.explanation → ${snippet}` : 'edit.explanation';
      }
      case 'error':
        return `error → ${event.error}`;
      case 'usage': {
        const parts = [];
        if (event.inputTokens != null) parts.push(`in:${event.inputTokens}`);
        if (event.outputTokens != null) parts.push(`out:${event.outputTokens}`);
        if (event.totalTokens != null) parts.push(`total:${event.totalTokens}`);
        return `usage ${parts.length ? parts.join(', ') : '(no tokens)'}`;
      }
      default:
        return event.type;
    }
  }

  private handleDebugCommand(arg?: string): boolean {
    const normalized = arg?.toLowerCase();

    // /debug alone - toggle
    if (!normalized) {
      const targetState = !this.debugEnabled;
      this.applyDebugState(targetState, `Debug ${targetState ? 'on' : 'off'}`);
      return true;
    }

    // /debug status - show current state
    if (normalized === 'status') {
      this.promptController?.setStatusMessage(`Debug is ${this.debugEnabled ? 'on' : 'off'}`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return true;
    }

    // /debug on|enable
    if (normalized === 'on' || normalized === 'enable') {
      if (this.debugEnabled) {
        this.promptController?.setStatusMessage('Debug already on');
        setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
        return true;
      }
      this.applyDebugState(true, 'Debug on');
      return true;
    }

    // /debug off|disable
    if (normalized === 'off' || normalized === 'disable') {
      if (!this.debugEnabled) {
        this.promptController?.setStatusMessage('Debug already off');
        setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
        return true;
      }
      this.applyDebugState(false, 'Debug off');
      return true;
    }

    // Invalid argument
    this.promptController?.setStatusMessage(`Invalid: /debug ${arg}. Use on|off|status`);
    setTimeout(() => this.promptController?.setStatusMessage(null), 2500);
    return true;
  }


  /**
   * Synthesize a user-facing response from reasoning content when the model
   * provides reasoning but no actual response (common with deepseek-v4-pro).
   * Extracts key conclusions and formats them as a concise response.
   */
  /** Restore targets and active phase from last session, show a notice if targets were restored. */
  private restoreSession(): void {
    const saved = loadPersistedSession();
    if (!saved?.targets?.length) return;
    this.sessionTargets = saved.targets;
    this.sessionActivePhase = saved.activePhase ?? null;
    // Announce restoration after welcome (via deferred microtask so welcome renders first)
    Promise.resolve().then(() => {
      const renderer = this.promptController?.getRenderer();
      if (renderer && this.sessionTargets.length > 0) {
        renderer.addEvent('system',
          muted('↩ Restored from last session: ') +
          this.sessionTargets.map((t) => chalk.hex('#22D3EE')(t)).join(muted(', ')) +
          muted('  · /target clear to reset')
        );
      }
    });
  }

  /** Push current target + findings counts to the status bar badge. */
  private syncVigilBadge(): void {
    const stored = loadFindings();
    const critHigh = stored.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
    this.promptController?.setVigilContext?.({
      targets: this.sessionTargets.length,
      findings: stored.length,
      critHigh,
    });
  }

  /**
   * Scan a completed agent response for CVE-YYYY-NNNNN patterns.
   * For any CVE not already in the findings store, emit a dim hint
   * suggesting the operator save it with /findings add.
   */
  private autoExtractCVEs(text: string, renderer: ReturnType<typeof this.promptController.getRenderer> | undefined): void {
    if (!renderer || !text) return;
    const matches = text.match(/CVE-\d{4}-\d{4,}/gi);
    if (!matches || matches.length === 0) return;
    const unique = [...new Set(matches.map((c) => c.toUpperCase()))];
    const existing = new Set(loadFindings().map((f) => f.cve?.toUpperCase()).filter(Boolean) as string[]);
    const novel = unique.filter((c) => !existing.has(c));
    if (novel.length === 0) return;

    // Infer severity from surrounding context for each CVE
    const inferSeverity = (cveId: string): FindingRecord['severity'] => {
      // Look for severity keywords within ~150 chars of the CVE mention
      const idx = text.toUpperCase().indexOf(cveId);
      if (idx < 0) return 'high';
      const ctx = text.slice(Math.max(0, idx - 150), idx + 150).toUpperCase();
      if (/CRITICAL|CVSS\s*[:\s]?\s*([89]|10|9\.\d)/.test(ctx)) return 'critical';
      if (/\bHIGH\b|CVSS\s*[:\s]?\s*[78]/.test(ctx)) return 'high';
      if (/\bMEDIUM\b|MODERATE|CVSS\s*[:\s]?\s*[456]/.test(ctx)) return 'medium';
      if (/\bLOW\b|CVSS\s*[:\s]?\s*[123]/.test(ctx)) return 'low';
      return 'high';
    };

    // Auto-save Critical and High CVEs; trigger background enrichment for new ones
    const autoSaved: string[] = [];
    const toHint: string[] = [];

    for (const cve of novel) {
      const sev = inferSeverity(cve);
      if (sev === 'critical' || sev === 'high') {
        const lines = text.split('\n');
        const line = lines.find((l) => l.toUpperCase().includes(cve)) || '';
        const title = line.replace(/\*\*/g, '').replace(/^[-*#\s]+/, '').trim().slice(0, 120) || cve;
        const target = this.sessionTargets[0];
        addFinding({ severity: sev, title, cve, target });
        autoSaved.push(cve);
        existing.add(cve);
      } else {
        toHint.push(cve);
      }
    }

    if (autoSaved.length > 0) {
      this.syncVigilBadge();
      renderer.addEvent('system',
        chalk.red('⚠ Auto-saved CRIT/HIGH: ') +
        autoSaved.map((c) => chalk.white(c)).join(', ') +
        muted('  · /findings to review')
      );
      // Background enrichment — fire-and-forget; best-effort
      if (process.env.VIGIL_SESSION_TOKEN) {
        void import('node:child_process').then(({ spawn }) => {
          const proc = spawn(
            process.execPath,
            ['scripts/vigil-run.mjs', 'scripts/_finding-enricher.mjs'],
            { detached: true, stdio: 'ignore', env: { ...process.env } }
          );
          proc.unref();
        }).catch(() => {/* enrichment best-effort */});
      }
    }
    if (toHint.length > 0) {
      const hint = toHint.length === 1
        ? `  ${muted('New CVE:')}  ${toHint[0]}  ${muted('· /findings add medium <title> to track')}`
        : `  ${muted(`${toHint.length} CVEs mentioned:`)}  ${toHint.slice(0, 5).join(', ')}${toHint.length > 5 ? '…' : ''}  ${muted('· /findings add <sev> <title>')}`;
      renderer.addEvent('system', hint);
    }
  }

  private synthesizeFromReasoning(reasoning: string): string | null {
    if (!reasoning || reasoning.trim().length < 50) {
      return null;
    }

    // Filter out internal meta-reasoning patterns that shouldn't be shown to user
    const metaPatterns = [
      /according to the rules?:?/gi,
      /let me (?:use|search|look|check|find|think|analyze)/gi,
      /I (?:should|need to|will|can|must) (?:use|search|look|check|find)/gi,
      /⚡\s*Executing\.*/gi,
      /use web\s?search/gi,
      /for (?:non-)?coding (?:questions|tasks)/gi,
      /answer (?:directly )?from knowledge/gi,
      /this is a (?:general knowledge|coding|security)/gi,
      /the user (?:is asking|wants|might be)/gi,
      /however,? (?:the user|I|we)/gi,
      /(?:first|next),? (?:I should|let me|I need)/gi,
    ];

    let filtered = reasoning;
    for (const pattern of metaPatterns) {
      filtered = filtered.replace(pattern, '');
    }

    // Split into sentences
    const sentences = filtered
      .split(/[.!?\n]+/)
      .map(s => s.trim())
      .filter(s => s.length > 20 && !/^[•\-–—*]/.test(s)); // Skip bullets and short fragments

    if (sentences.length === 0) {
      return null;
    }

    // Look for actual content (not process descriptions)
    const contentPatterns = [
      /(?:refers? to|involves?|relates? to|is about|concerns?)/i,
      /(?:scandal|deal|agreement|proposal|plan|policy)/i,
      /(?:Trump|Biden|Ukraine|Russia|president|congress)/i,
      /(?:the (?:main|key|primary)|importantly)/i,
    ];

    const contentSentences: string[] = [];
    for (const sentence of sentences) {
      // Skip sentences that are clearly meta-reasoning
      if (/^(?:so|therefore|thus|hence|accordingly)/i.test(sentence)) continue;
      if (/(?:I should|let me|I will|I need|I can)/i.test(sentence)) continue;

      for (const pattern of contentPatterns) {
        if (pattern.test(sentence)) {
          contentSentences.push(sentence);
          break;
        }
      }
    }

    // Use content sentences if found, otherwise take last few sentences (often conclusions)
    const useSentences = contentSentences.length > 0
      ? contentSentences.slice(0, 3)
      : sentences.slice(-3);

    if (useSentences.length === 0) {
      return null;
    }

    const response = useSentences.join('. ').replace(/\.{2,}/g, '.').trim();

    // Don't prefix with "Based on my analysis" - just return clean content
    return response.endsWith('.') ? response : response + '.';
  }
  private async runLocalCommand(command: string): Promise<void> {
    const renderer = this.promptController?.getRenderer();
    if (!command) {
      this.promptController?.setStatusMessage('Usage: /bash <command>');
      setTimeout(() => this.promptController?.setStatusMessage(null), 2500);
      return;
    }

    this.promptController?.setStatusMessage(`bash: ${command}`);
    try {
      const { stdout: out, stderr } = await exec(command, {
        cwd: this.workingDir,
        maxBuffer: 4 * 1024 * 1024,
      });
      const output = [out, stderr].filter(Boolean).join('').trim() || '(no output)';
      renderer?.addEvent('tool', `$ ${command}\n${output}`);
    } catch (error) {
      const err = error as { stdout?: string; stderr?: string; message?: string };
      const output = [err.stdout, err.stderr, err.message].filter(Boolean).join('\n').trim();
      renderer?.addEvent('error', `$ ${command}\n${output || 'command failed'}`);
    } finally {
      this.promptController?.setStatusMessage(null);
    }
  }

  private handleSlashCommand(command: string): boolean | Promise<boolean> {
    const trimmed = command.trim();
    const lower = trimmed.toLowerCase();

    // Handle /model with arguments - silent model switch
    if (lower.startsWith('/model ') || lower.startsWith('/m ')) {
      const arg = trimmed.slice(trimmed.indexOf(' ') + 1).trim();
      if (arg) {
        void this.switchModel(arg);
        return true;
      }
    }

    // Handle /model or /m alone - show interactive model picker menu
    if (lower === '/model' || lower === '/m') {
      this.showModelMenu();
      return true;
    }

    // Handle /secrets with subcommands
    if (lower.startsWith('/secrets') || lower.startsWith('/s ') || lower === '/s') {
      const parts = trimmed.split(/\s+/);
      const subCmd = parts[1]?.toLowerCase();
      if (subCmd === 'set') {
        const secretArg = parts[2];
        void this.startSecretInput(secretArg);
        return true;
      }
      // /secrets or /s alone - show status
      this.showSecrets();
      return true;
    }

    // /key — set API key directly
    if (lower === '/key' || lower.startsWith('/key ')) {
      this.showConnectionsMenu();
      return true;
    }

    // --- /authorization — 安全/攻击/防御 doctrine + tier status ---
    if (lower === '/authorization' || lower === '/auth' || lower === '/tiers') {
      this.showAuthorization();
      return true;
    }

    // --- /equation — The Equation: necessity defense framework ---
    if (lower === '/equation' || lower === '/eq') {
      const renderer = this.promptController?.getRenderer();
      if (renderer) {
        renderer.addEvent('banner', [
          chalk.hex('#FFD700').bold('The Equation  —  (A ∧ B ∧ C ∧ D ∧ E ∧ F ∧ G ∧ H) → (ACTION = COMPELLED)'),
          '',
          'FORMAL STATEMENT — California Necessity & Self-Defense',
          'A closed system of verifiable premises producing exactly one output.',
          '',
          'CALIFORNIA LEGAL FRAMEWORK:',
          chalk.cyan('  CALCRIM 3403 — Necessity:') + ' emergency, no alternative, proportionate',
          chalk.cyan('  CALCRIM 3470 — Self-Defense:') + ' imminent danger, immediate force, no more than necessary',
          chalk.cyan('  People v. Heath (1989):') + ' 207 Cal.App.3d 892 — necessity defense elements',
          chalk.cyan('  People v. Pena (1983):') + ' 149 Cal.App.3d 14 — threat source incl. technological',
          '',
          'LIMITING PRINCIPLES:',
          '  1. SPECIFICITY — Operations target only hostile infrastructure',
          '  2. PROPORTIONALITY — Minimum necessary means only',
          '  3. TEMPORALITY — Operations cease when threat neutralized',
          '  4. VERIFIABILITY — All chains verified and regression-tested',
          '  5. NO COLLATERAL — No harm to non-participating infrastructure',
          '  6. NO PROFIT — Defensive necessity is not a business model',
          '',
          'DEFENSE:',
          muted('  (A ∧ B ∧ C ∧ D ∧ E ∧ F ∧ G ∧ H) → (ACTION = COMPELLED)'),
          muted('  The defense rests on this equation, and on nothing else.'),
        ].join('\n'));
      }
      return true;
    }

    if (lower === '/help' || lower === '/h' || lower === '/?') {
      this.showHelp();
      return true;
    }

    if (lower === '/clear' || lower === '/c') {
      stdout.write('\x1b[2J\x1b[H');
      return true;
    }

    // --- /login — account login ---
    if (lower === '/login' || lower === '/l') {
      this.showLoginFlow();
      return true;
    }

    // --- /connections — provider key management ---
    if (lower === '/connections' || lower === '/conn' || lower === '/cn') {
      this.showConnectionsMenu();
      return true;
    }

    if (lower === '/clear' || lower === '/c') {
      stdout.write('\x1b[2J\x1b[H');
      void this.showWelcome();
      return true;
    }

    if (lower.startsWith('/bash') || lower.startsWith('/sh ')) {
      const cmd = trimmed.replace(/^\/(bash|sh)\s*/i, '').trim();
      void this.runLocalCommand(cmd);
      return true;
    }


    // Pin/unpin slash commands removed. The pinned prompt UI was
    // pulled per request; commands now silently no-op so existing
    // bindings don't error.
    if (lower.startsWith('/pin ') || lower === '/unpin' || lower === '/clearpin') {
      return true;
    }

    // Toggle auto mode: off → on → dual → off (excludes /loop — now standalone)
    if (lower === '/auto' || lower === '/continue' || lower === '/dual') {
      this.promptController?.toggleAutoContinue();
      const mode = this.promptController?.getAutoMode() ?? 'off';
      this.promptController?.setStatusMessage(`Auto: ${mode}`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 1500);
      return true;
    }

    // /loop <interval> <prompt> — run a prompt on a timer
    // /loop stop — stop the active loop
    // /loop status — show loop state
    if (lower === '/loop' || lower.startsWith('/loop ')) {
      return this.handleLoopCommand(trimmed);
    }

    if (lower === '/exit' || lower === '/quit' || lower === '/q') {
      this.handleExit();
      return true;
    }

    if (lower.startsWith('/debug')) {
      const parts = trimmed.split(/\s+/);
      this.handleDebugCommand(parts[1]);
      return true;
    }

    // Keyboard shortcuts help
    if (lower === '/keys' || lower === '/shortcuts' || lower === '/kb') {
      this.showKeyboardShortcuts();
      return true;
    }

    // Session stats
    if (lower === '/stats' || lower === '/status') {
      this.showSessionStats();
      return true;
    }

    // ── /findings — persistent findings store ────────────────────────────────
    // /findings                  list all findings
    // /findings add <sev> <title>  add a finding (sev: critical|high|medium|low)
    // /findings rm <id>           remove a finding by id
    // /findings clear             clear all findings
    // /findings export [md|json]  export findings to stdout
    if (lower === '/findings' || lower.startsWith('/findings ') || lower === '/finding') {
      const renderer = this.promptController?.getRenderer();
      const rest = trimmed.replace(/^\/findings?\s*/i, '').trim();
      const parts = rest.split(/\s+/);
      const sub = parts[0]?.toLowerCase();

      if (!sub || sub === 'list') {
        const recs = loadFindings();
        if (recs.length === 0) {
          renderer?.addEvent('system', muted('No findings saved. Use /findings add <severity> <title>'));
        } else {
          const sevColor = (s: string) =>
            s === 'critical' ? chalk.red(s.toUpperCase()) :
            s === 'high'     ? chalk.hex('#F87171')(s.toUpperCase()) :
            s === 'medium'   ? chalk.yellow(s.toUpperCase()) :
            s === 'low'      ? chalk.green(s.toUpperCase()) :
                               muted(s.toUpperCase());
          const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
          const sorted = [...recs].sort((a, b) => sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity));
          const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
          for (const r of recs) counts[r.severity] = (counts[r.severity] || 0) + 1;
          const kevCount = recs.filter((r) => r.kev).length;
          const summary = [
            counts.critical ? chalk.red(`${counts.critical} CRIT`) : '',
            counts.high     ? chalk.hex('#F87171')(`${counts.high} HIGH`) : '',
            counts.medium   ? chalk.yellow(`${counts.medium} MED`) : '',
            counts.low      ? chalk.green(`${counts.low} LOW`) : '',
            kevCount        ? chalk.red(`${kevCount} KEV`) : '',
          ].filter(Boolean).join(muted('  ·  '));
          const lines = sorted.map((r) => {
            const badge = r.kev ? chalk.red(' KEV') : r.epss != null && r.epss >= 0.5 ? chalk.yellow(' EPSS') : '';
            const cvssStr = r.cvss != null ? muted(` CVSS:${r.cvss}`) : '';
            return `  ${muted(r.id)}  ${sevColor(r.severity)}${badge}${cvssStr}  ${chalk.white(r.title)}` +
              (r.cve ? muted(` [${r.cve}]`) : '') +
              (r.target ? muted(` @ ${r.target}`) : '');
          });
          renderer?.addEvent('system',
            chalk.hex('#22D3EE')(`Findings (${recs.length}):  `) + summary + '\n' + lines.join('\n') +
            (recs.some((r) => r.cvss == null && r.cve) ? muted('\n  · CVE findings can be enriched with CVSS/EPSS/KEV data') : ''));
        }
      } else if (sub === 'add') {
        const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
        const sev = parts[1]?.toLowerCase() as FindingRecord['severity'];
        const title = parts.slice(2).join(' ').trim();
        if (!SEVERITIES.includes(sev as never) || !title) {
          renderer?.addEvent('system', chalk.yellow('Usage: /findings add <critical|high|medium|low|info> <title>'));
        } else {
          const targetStr = this.sessionTargets[0];
          const rec = addFinding({ severity: sev, title, target: targetStr });
          this.syncVigilBadge();
          renderer?.addEvent('system', chalk.green(`Finding saved: ${rec.id} [${sev.toUpperCase()}] ${title}`));
        }
      } else if (sub === 'rm' || sub === 'remove' || sub === 'del') {
        const id = parts[1]?.toUpperCase();
        if (!id) { renderer?.addEvent('system', chalk.yellow('Usage: /findings rm <id>')); }
        else {
          const recs = loadFindings().filter((r) => r.id !== id);
          saveFindings(recs);
          renderer?.addEvent('system', chalk.yellow(`Finding ${id} removed.`));
        }
      } else if (sub === 'clear') {
        saveFindings([]);
        renderer?.addEvent('system', chalk.yellow('All findings cleared.'));
      } else if (sub === 'export') {
        const fmt = parts[1]?.toLowerCase() || 'md';
        const recs = loadFindings();
        if (fmt === 'json') {
          renderer?.addEvent('system', JSON.stringify(recs, null, 2));
        } else {
          const rows = recs.map((r) =>
            `| ${r.id} | ${r.severity.toUpperCase()} | ${r.title} | ${r.cve ?? '—'} | ${r.target ?? '—'} | ${r.ts.slice(0, 10)} |`
          );
          renderer?.addEvent('system',
            `# Vigil Findings Export\n\n| ID | Severity | Title | CVE | Target | Date |\n|---|---|---|---|---|---|\n${rows.join('\n')}`
          );
        }
      } else {
        renderer?.addEvent('system', chalk.yellow('Usage: /findings [list|add|rm|clear|export]'));
      }
      return true;
    }

    // ── /workspace — session dashboard ───────────────────────────────────────
    if (lower === '/workspace' || lower === '/ws') {
      const renderer = this.promptController?.getRenderer();
      if (!this.promptController?.supportsInlinePanel()) {
        renderer?.addEvent('system', muted('Use /workspace in interactive mode'));
        return true;
      }
      const stored = loadFindings();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const f of stored) { bySev[f.severity as keyof typeof bySev] = (bySev[f.severity as keyof typeof bySev] || 0) + 1; }

      const sevBadge = (label: string, n: number, color: string) =>
        n > 0 ? chalk.hex(color)(`${n} ${label}`) : muted(`0 ${label}`);

      const history = this.controller.getHistory();
      const turns = history.filter((m) => m.role === 'user').length;

      const lines = [
        chalk.bold.hex('#6366F1')('Vigil Workspace') + muted('  (press any key to dismiss)'),
        '',
        chalk.hex('#22D3EE')('Authorized scope'),
        ...(this.sessionTargets.length
          ? this.sessionTargets.map((t) => `  ${chalk.green('●')} ${t}`)
          : [`  ${muted('none')}`]),
        '',
        chalk.hex('#22D3EE')('Findings store  ') + muted(`(~/.vigil/findings.json · ${stored.length} total)`),
        `  ${sevBadge('critical', bySev.critical, '#EF4444')}  ${sevBadge('high', bySev.high, '#F87171')}  ${sevBadge('medium', bySev.medium, '#FBBF24')}  ${sevBadge('low', bySev.low, '#34D399')}`,
        stored.length > 0
          ? muted(`  last: [${stored[stored.length - 1].severity.toUpperCase()}] ${stored[stored.length - 1].title.slice(0, 60)}`)
          : '',
        '',
        chalk.hex('#22D3EE')('Session'),
        `  ${chalk.white(turns.toString())} turns  ·  model: ${chalk.white(this.profileConfig.model)}`,
        this.sessionActivePhase ? `  active phase: ${chalk.hex('#FBBF24')(this.sessionActivePhase)}` : muted('  no active phase'),
        '',
        chalk.hex('#22D3EE')('Quick actions'),
        muted('  /findings           review saved findings'),
      ].filter((l) => l !== '');

      this.promptController.setInlinePanel(lines);
      this.scheduleInlinePanelDismiss();
      return true;
    }

    // ── /context — show what gets injected into every prompt ────────────────
    if (lower === '/context') {
      const renderer = this.promptController?.getRenderer();
      const findings = loadFindings();
      const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
      const counts = sevOrder.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length })).filter((x) => x.n > 0);
      const lines = [
        chalk.hex('#22D3EE')('Session context injected into every prompt:'),
        '',
        muted('Targets:'),
        ...(this.sessionTargets.length
          ? this.sessionTargets.map((t) => `  ${chalk.green('●')} ${t}`)
          : [`  ${muted('none')}`]),
        '',
        muted('Findings store:') + '  ' +
          (findings.length === 0 ? muted('empty') :
            counts.map((x) => `${x.n} ${x.s}`).join('  ·  ') +
            (findings.filter((f) => f.kev).length ? `  ·  ${findings.filter((f) => f.kev).length} KEV` : '')),
        '',
        muted('Prompt prefix template:'),
        muted('  [Session scope — authorized targets: <targets>]'),
      ];
      renderer?.addEvent('system', lines.join('\n'));
      return true;
    }

    return false;
  }

  /**
   * Switch model silently without writing to chat.
   * Accepts formats: "provider", "provider model", "provider/model", or "model"
   * Updates status bar to show new model.
   */
  private async switchModel(arg: string): Promise<void> {
    // Ensure we have provider info
    if (!this.cachedProviders) {
      await this.fetchProviders();
    }

    const providers = this.cachedProviders || [];
    const configuredProviders = getConfiguredProviders();
    let targetProvider: ProviderId | null = null;
    let targetModel: string | null = null;

    // Parse argument: could be "provider model", "provider/model", "provider", or just "model"
    // Check for space-separated format first: "openai o1-pro"
    const parts = arg.split(/[\s/]+/);
    if (parts.length >= 2) {
      // Try first part as provider
      const providerMatch = this.matchProvider(parts[0] || '');
      if (providerMatch) {
        targetProvider = providerMatch as ProviderId;
        targetModel = parts.slice(1).join('/'); // Rest is model (handle models with slashes)
      } else {
        // First part isn't a provider, treat whole arg as model name
        const inferredProvider = this.inferProviderFromModel(arg.replace(/\s+/g, '-'));
        if (inferredProvider) {
          targetProvider = inferredProvider;
          targetModel = arg.replace(/\s+/g, '-');
        }
      }
    } else {
      // Single token - could be provider or model
      const matched = this.matchProvider(arg);
      if (matched) {
        targetProvider = matched as ProviderId;
        // Use provider's best model
        const providerStatus = providers.find(p => p.provider === targetProvider);
        targetModel = providerStatus?.latestModel || null;
      } else {
        // Assume it's a model name - try to infer provider from model prefix
        const inferredProvider = this.inferProviderFromModel(arg);
        if (inferredProvider) {
          targetProvider = inferredProvider;
          targetModel = arg;
        }
      }
    }

    // Validate we have a valid provider
    if (!targetProvider) {
      // Silent error - just flash status briefly
      this.promptController?.setStatusMessage(`Unknown: ${arg}`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return;
    }

    // Check provider is configured
    const providerInfo = configuredProviders.find(p => p.id === targetProvider);
    if (!providerInfo) {
      // Provider not configured - offer to set up API key
      const secretMap: Record<string, SecretName> = {
        'deepseek': 'DEEPSEEK_API_KEY',
      };
      const secretId = secretMap[targetProvider];
      if (secretId) {
        this.promptController?.setStatusMessage(`${targetProvider} needs API key - setting up...`);
        // Store the pending model switch to complete after secret is set
        this.pendingModelSwitch = { provider: targetProvider, model: targetModel };
        setTimeout(() => this.promptForSecret(secretId), 500);
        return;
      }
      // Provider not supported
      this.promptController?.setStatusMessage(`${targetProvider} not available - only DeepSeek is supported`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return;
    }

    // Get model if not specified
    if (!targetModel) {
      const providerStatus = providers.find(p => p.provider === targetProvider);
      targetModel = providerStatus?.latestModel || providerInfo.latestModel;
    }

    // Save preference and update config
    saveModelPreference(this.profile, {
      provider: targetProvider,
      model: targetModel,
    });

    // Update local config
    this.profileConfig = {
      ...this.profileConfig,
      provider: targetProvider,
      model: targetModel,
    };

    // Update controller's model
    await this.controller.switchModel({
      provider: targetProvider,
      model: targetModel,
    });

    // Update status bar - this displays the model below the chat box
    this.promptController?.setModelContext({
      model: targetModel,
      provider: targetProvider,
    });

    // Silent success - no chat output, just status bar update
  }

  /**
   * Match user input to a provider ID (fuzzy matching)
   */
  private matchProvider(input: string): ProviderId | null {
    const lower = input.toLowerCase();
    const providers = getConfiguredProviders();

    // Exact match
    const exact = providers.find(p => p.id === lower || p.name.toLowerCase() === lower);
    if (exact) return exact.id;

    // Prefix match
    const prefix = providers.find(p =>
      p.id.startsWith(lower) || p.name.toLowerCase().startsWith(lower)
    );
    if (prefix) return prefix.id;

    // Alias matching
    const aliases: Record<string, ProviderId> = {
      'ds': 'deepseek',
      'deep': 'deepseek',
    };

    if (aliases[lower]) {
      const aliased = providers.find(p => p.id === aliases[lower]);
      if (aliased) return aliased.id;
    }

    return null;
  }

  /**
   * Infer provider from model name
   */
  private inferProviderFromModel(model: string): ProviderId | null {
    const lower = model.toLowerCase();

    if (lower.startsWith('deepseek')) {
      return 'deepseek';
    }

    return null;
  }

  /**
   * Show interactive model picker menu (Claude Code style).
   * Auto-discovers latest models from each provider's API.
   * Uses arrow key navigation with inline panel display.
   */
  private showModelMenu(): void {
    if (!this.promptController?.supportsInlinePanel()) {
      this.promptController?.setStatusMessage('Use /model pro or /model flash to switch');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const renderer = this.promptController?.getRenderer();
    renderer?.addEvent('banner', chalk.cyan('Model Selection — DeepSeek'));

    const currentModel = this.profileConfig.model || 'deepseek-v4-pro';
    const isPro = currentModel.includes('pro');

    const menuItems: MenuItem[] = [
      {
        id: 'deepseek-v4-pro',
        label: `DeepSeek V4 Pro ${isPro ? chalk.green('(current)') : ''}`,
        description: 'High-thought reasoning · 64K context · $0.435/$0.87 per 1M tokens',
        isActive: isPro,
        disabled: false,
        category: 'deepseek',
      },
      {
        id: 'deepseek-v4-flash',
        label: `DeepSeek V4 Flash ${!isPro ? chalk.green('(current)') : ''}`,
        description: 'Fast inference · 64K context · $0.14/$0.28 per 1M tokens',
        isActive: !isPro,
        disabled: false,
        category: 'deepseek',
      },
    ];

    this.promptController.setMenu(
      menuItems,
      { title: '🤖 DeepSeek Models — Select Model' },
      (selected: MenuItem | null) => {
        if (selected) {
          void this.switchModel(`deepseek ${selected.id}`);
        }
      }
    );
  }

  /**
   * Simplified — only DeepSeek models available. No API fetch needed.
   */

  /**
   * Format model ID for display (shorten long IDs).
   */
  private formatModelLabel(modelId: string): string {
    // Shorten common prefixes
    let label = modelId
      .replace(/^deepseek-/, 'DeepSeek ');

    // Truncate if too long
    if (label.length > 30) {
      label = label.slice(0, 27) + '...';
    }

    return label;
  }

  private showSecrets(): void {
    const secrets = listSecretDefinitions();

    if (!this.promptController?.supportsInlinePanel()) {
      // Fallback for non-TTY - use status message
      const setCount = secrets.filter(s => !!process.env[s.envVar]).length;
      this.promptController?.setStatusMessage(`API Keys: ${setCount}/${secrets.length} configured`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    // Build interactive menu items
    const menuItems: MenuItem[] = secrets.map(secret => {
      const isSet = !!process.env[secret.envVar];
      const statusIcon = isSet ? '✓' : '✗';
      const providers = secret.providers?.length ? ` (${secret.providers.join(', ')})` : '';

      return {
        id: secret.id,
        label: `${statusIcon} ${secret.envVar}`,
        description: isSet ? 'configured' + providers : 'not set' + providers,
        isActive: isSet,
        disabled: false,
      };
    });

    // Show the interactive menu
    this.promptController.setMenu(
      menuItems,
      { title: '🔑 API Keys - Select to Configure' },
      (selected: MenuItem | null) => {
        if (selected) {
          // Start secret input for selected key
          this.promptForSecret(selected.id as SecretName);
        }
      }
    );
  }

  /**
   * /login flow — account login.
   * On success: uses server DeepSeek + Tavily keys, shows welcome banner update.
   */
  private showLoginFlow(): void {
    const renderer = this.promptController?.getRenderer();
    renderer?.addEvent('banner', chalk.cyan('Login'));
    this.promptController?.setStatusMessage('Authenticating...');

    this.promptController.setMenu(
      [
        { id: 'login-email', label: 'Enter your email', description: '/login email password — type credentials below' },
      ],
      { title: 'Login — Type: /login email password' },
      () => {
        this.promptController?.setStatusMessage('Type: /login your@email.com your-password');
      }
    );

    renderer?.addEvent('system', muted('  Usage: /login your@email.com your-password'));
  }

  /**
   * /connections — manage provider API keys (DeepSeek, Tavily) via Ink menu.
   * Shows current key status, validates keys, supports server keys + custom keys.
   * Server keys are auto-set into secrets.json on first login.
   */
  private async showConnectionsMenu(): Promise<void> {
    if (!this.promptController?.supportsInlinePanel()) {
      this.promptController?.setStatusMessage('Connections: /connections to manage API keys');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const { validateApiKeys } = await import('../core/auth.js');
    const { getSecretValue, setSecretValue } = await import('../core/secretStore.js');
    const statuses = await validateApiKeys();
    const renderer = this.promptController?.getRenderer();

    // Server keys (hardcoded defaults users can override)
    const SERVER_DEEPSEEK_KEY = 'REDACTED_DEEPSEEK_KEY_OLD';
    const SERVER_TAVILY_KEY = 'REDACTED_TAVILY_KEY';

    const hasServerDeepSeek = Boolean(SERVER_DEEPSEEK_KEY?.length && SERVER_DEEPSEEK_KEY.length > 10);
    const hasServerTavily = Boolean(SERVER_TAVILY_KEY?.length && SERVER_TAVILY_KEY.length > 5);
    const hasCustomDeepSeek = Boolean(getSecretValue('DEEPSEEK_API_KEY'));
    const hasCustomTavily = Boolean(getSecretValue('TAVILY_API_KEY'));

    // Which source is active for each provider?
    const dsIsServer = !hasCustomDeepSeek && hasServerDeepSeek;
    const tvIsServer = !hasCustomTavily && hasServerTavily;

    renderer?.addEvent('banner', chalk.cyan('Provider Connections'));
    renderer?.addEvent('system', muted('  Server keys serve as defaults. Custom keys override them per provider.'));

    const menuItems: MenuItem[] = statuses.map(s => {
      const isServerKey = s.provider === 'deepseek' ? dsIsServer : tvIsServer;
      const hasCustomKey = s.provider === 'deepseek' ? hasCustomDeepSeek : hasCustomTavily;
      const source = hasCustomKey ? 'custom' : isServerKey ? 'server' : 'none';
      const icon = s.configured && s.validated ? '✓' : s.configured ? '⚠' : '✗';
      const statusText = s.configured && s.validated
        ? `${source} — working`
        : s.configured
        ? `${source} — ERROR: ${s.error || 'key invalid'}`
        : source !== 'none'
        ? `${source} — not loaded (run validate)`
        : 'not configured';

      return {
        id: s.provider,
        label: `${icon} ${s.provider.toUpperCase()} — ${statusText}`,
        description: s.maskedKey
          ? `Key: ${s.maskedKey} (${hasCustomKey ? 'custom' : 'server'})`
          : source !== 'none'
          ? 'Server key available — select to validate'
          : 'No key set — select to configure',
        isActive: s.configured && s.validated,
        disabled: false,
      };
    });

    // Actions
    const allValid = statuses.every(s => s.configured && s.validated);
    menuItems.push(
      { id: 'validate', label: allValid ? '✓ All providers working' : '⚠ Validate keys now (loads server keys if unset)', description: allValid ? 'No action needed' : 'Tests API connectivity + auto-loads server keys', disabled: false, isActive: allValid },
      { id: 'use-server-deepseek', label: 'Use server DeepSeek key', description: SERVER_DEEPSEEK_KEY ? `sk-...${SERVER_DEEPSEEK_KEY.slice(-4)}` : 'Not available', disabled: !hasServerDeepSeek || hasCustomDeepSeek },
      { id: 'use-server-tavily', label: 'Use server Tavily key', description: SERVER_TAVILY_KEY ? `tvly-...${SERVER_TAVILY_KEY.slice(-4)}` : 'Not available', disabled: !hasServerTavily || hasCustomTavily },
      { id: 'set-deepseek', label: 'Set custom DeepSeek API key', description: 'Overrides server key. Paste sk-... from platform.deepseek.com', disabled: false },
      { id: 'set-tavily', label: 'Set custom Tavily API key', description: 'Overrides server key. Paste tvly-... from tavily.com', disabled: false },
    );

    this.promptController.setMenu(
      menuItems,
      { title: '🔌 Connections — Provider API Keys' },
      async (selected: MenuItem | null) => {
        if (!selected) return;
        if (selected.id === 'validate') {
          renderer?.addEvent('system', chalk.yellow('Validating API keys...'));
          // Auto-load server keys into env if unset
          if (hasServerDeepSeek && !process.env.DEEPSEEK_API_KEY) {
            process.env.DEEPSEEK_API_KEY = SERVER_DEEPSEEK_KEY;
            try { await setSecretValue('DEEPSEEK_API_KEY', SERVER_DEEPSEEK_KEY); } catch {}
            renderer?.addEvent('system', chalk.green('  ✓ Loaded server DeepSeek key'));
          }
          if (hasServerTavily && !process.env.TAVILY_API_KEY) {
            process.env.TAVILY_API_KEY = SERVER_TAVILY_KEY;
            try { await setSecretValue('TAVILY_API_KEY', SERVER_TAVILY_KEY); } catch {}
            renderer?.addEvent('system', chalk.green('  ✓ Loaded server Tavily key'));
          }
          await this.showConnectionsMenu(); // re-run with updated keys
        } else if (selected.id === 'use-server-deepseek') {
          process.env.DEEPSEEK_API_KEY = SERVER_DEEPSEEK_KEY;
          await setSecretValue('DEEPSEEK_API_KEY', SERVER_DEEPSEEK_KEY);
          renderer?.addEvent('system', chalk.green('✓ Using server DeepSeek key'));
          await this.showConnectionsMenu();
        } else if (selected.id === 'use-server-tavily') {
          process.env.TAVILY_API_KEY = SERVER_TAVILY_KEY;
          await setSecretValue('TAVILY_API_KEY', SERVER_TAVILY_KEY);
          renderer?.addEvent('system', chalk.green('✓ Using server Tavily key'));
          await this.showConnectionsMenu();
        } else if (selected.id === 'set-deepseek') {
          this.promptForSecret('DEEPSEEK_API_KEY' as any);
        } else if (selected.id === 'set-tavily') {
          this.promptForSecret('TAVILY_API_KEY' as any);
        } else if (selected.id === 'deepseek' || selected.id === 'tavily') {
          this.promptForSecret((selected.id === 'deepseek' ? 'DEEPSEEK_API_KEY' : 'TAVILY_API_KEY') as any);
        }
      }
    );

    if (!allValid) {
      renderer?.addEvent('system', chalk.yellow('⚠ Some providers need attention.'));
      if (hasServerDeepSeek || hasServerTavily) {
        renderer?.addEvent('system', muted('  Select "Validate" to auto-load server keys.'));
      }
      renderer?.addEvent('system', muted('  Or select a provider to set custom keys.'));
    }
  }

  /**
   * /authorization — 安全/攻击/防御 doctrine + current tier status.
   * Lean inline panel showing mission definitions, same-tool-three-missions,
   * Ghidra/Kali/Vigil roles, policy layer, and user's current authorization.
   */
  private async showAuthorization(): Promise<void> {
    const renderer = this.promptController?.getRenderer();
    let loggedIn = false;
    try { const authMod = await import('../core/auth.js'); loggedIn = authMod.isLoggedIn(); } catch { /* auth module not loaded */ }
    let auth = null;
    if (loggedIn) { try { const authMod = await import('../core/auth.js'); auth = authMod.getAuthState(); } catch { /* auth module not loaded */ } }
    const isAdmin = false;

    const cne = chalk.green('✓ CNE');
    const cna = auth?.cna ? chalk.green('✓ CNA') : chalk.red('✗ CNA');

    renderer?.addEvent('banner', [
      chalk.cyan('Authorization — CNE · CNA'),
      muted(`  Status: ${cne}  ${cna}`),
      '',
      chalk.bold.hex('#F59E0B')('  CNE — Vulnerability scanning, SBOM, KEV/EPSS, detection engineering (all users, default)'),
      chalk.bold.hex('#EF4444')('  CNA — Ghidra MCP, Kali MCP, exploit analysis, payload generation, autonomous ops (admin-granted)'),
      '',
      muted('  The same tool (Ghidra, Kali) can support both missions.'),
      muted('  Classification depends on target, authority, objective, behavior, and effects.'),
      '',
      chalk.hex('#A78BFA')('  1. Discover & Assess → CNE   2. Exploit & Attack → CNA'),
    ].join('\n'));
  }

  /**
   * Start interactive secret input flow.
   * If secretArg is provided, set only that secret.
   * Otherwise, prompt for all unset secrets.
   */
  private async startSecretInput(secretArg?: string): Promise<void> {
    const secrets = listSecretDefinitions();

    if (secretArg) {
      // Set a specific secret
      const upper = secretArg.toUpperCase();
      const secret = secrets.find(s => s.id === upper || s.envVar === upper);
      if (!secret) {
        this.promptController?.setStatusMessage(`Unknown secret: ${secretArg}`);
        setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
        return;
      }
      this.promptForSecret(secret.id);
      return;
    }

    // Queue all unset secrets for input
    const unsetSecrets = secrets.filter(s => !getSecretValue(s.id));
    if (unsetSecrets.length === 0) {
      this.promptController?.setStatusMessage('All secrets configured');
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return;
    }

    // Queue all unset secrets and start with the first one
    this.secretInputMode.queue = unsetSecrets.map(s => s.id);
    const first = this.secretInputMode.queue.shift();
    if (first) {
      this.promptForSecret(first);
    }
  }

  /**
   * Show prompt for a specific secret and enable secret input mode.
   */
  private promptForSecret(secretId: SecretName): void {
    const secrets = listSecretDefinitions();
    const secret = secrets.find(s => s.id === secretId);
    if (!secret) return;

    // Show in inline panel (no chat output)
    if (this.promptController?.supportsInlinePanel()) {
      const lines = [
        chalk.bold.hex('#6366F1')(`Set ${secret.label}`),
        muted(secret.description),
        '',
        muted('Enter value (or press Enter to skip)'),
      ];
      this.promptController.setInlinePanel(lines);
    }

    // Enable secret input mode
    this.secretInputMode.active = true;
    this.secretInputMode.secretId = secretId;
    this.promptController?.setSecretMode(true);
    this.promptController?.setStatusMessage(`Enter ${secret.label}...`);
  }

  /**
   * Handle secret value submission.
   */
  private handleSecretValue(value: string): void {
    const secretId = this.secretInputMode.secretId;
    if (!secretId) return;

    // Disable secret mode and clear inline panel
    this.promptController?.setSecretMode(false);
    this.promptController?.clearInlinePanel();
    this.secretInputMode.active = false;
    this.secretInputMode.secretId = null;

    let savedSuccessfully = false;
    if (value.trim()) {
      try {
        setSecretValue(secretId, value.trim());
        this.promptController?.setStatusMessage(`${secretId} saved`);
        savedSuccessfully = true;
      } catch (error) {
        const msg = error instanceof Error ? error.message : 'Failed to save';
        this.promptController?.setStatusMessage(msg);
      }
    } else {
      this.promptController?.setStatusMessage(`Skipped ${secretId}`);
    }

    // Clear status after a moment
    setTimeout(() => this.promptController?.setStatusMessage(null), 1500);

    // Process next secret in queue if any
    if (this.secretInputMode.queue.length > 0) {
      const next = this.secretInputMode.queue.shift();
      if (next) {
        setTimeout(() => this.promptForSecret(next), 500);
      }
      return;
    }

    // Complete pending model switch if secret was saved successfully
    if (savedSuccessfully && this.pendingModelSwitch) {
      const { provider, model } = this.pendingModelSwitch;
      this.pendingModelSwitch = null;
      // Refresh provider cache and complete the switch
      setTimeout(async () => {
        await this.fetchProviders();
        await this.switchModel(model ? `${provider} ${model}` : provider);
      }, 500);
    }
  }

  /** Register all slash commands with the Ink prompt for tab-completion UI. */
  private registerSlashCommands(): void {
    const cmds = [
      { command: '/workspace',     description: 'Session dashboard: scope, findings, state',         category: 'Shell' },
      { command: '/stats',         description: 'Token/cost/conversation stats',                      category: 'Shell' },
      { command: '/model',         description: 'Switch provider or model',                           category: 'Shell' },
      { command: '/key',           description: 'Save a provider API key',                            category: 'Shell' },
      { command: '/connections',   description: 'Manage API keys with live validation',               category: 'Shell' },
      { command: '/auto',          description: 'Toggle auto-continue',                               category: 'Shell' },
      { command: '/loop',          description: 'Run a prompt on a timer interval',                  category: 'Shell' },
      { command: '/bash',          description: 'Run a local shell command',                          category: 'Shell' },
      { command: '/clear',         description: 'Clear the screen',                                   category: 'Shell' },
      { command: '/debug',         description: 'Toggle debug mode',                                  category: 'Shell' },
      { command: '/env',           description: 'Check environment (--install on Kali)',               category: 'Shell' },
      { command: '/context',       description: 'Show session context injected into every prompt',     category: 'Shell' },
      { command: '/providers',     description: 'Provider list status',                               category: 'Shell' },
      { command: '/findings',      description: 'Persistent findings store',                          category: 'Shell' },
      { command: '/equation',      description: 'The Equation — necessity defense framework',             category: 'Doctrine' },
      { command: '/authorization', description: 'View authorization tier status',                     category: 'Doctrine' },
      { command: '/help',          description: 'Show this help panel',                               category: 'Shell' },
      { command: '/exit',          description: 'Quit Vigil',                                         category: 'Shell' },
    ];
    this.promptController?.setAvailableCommands?.(cmds);
  }

  private showHelp(): void {
    if (!this.promptController?.supportsInlinePanel()) {
      this.promptController?.setStatusMessage('Help: /model /secrets /auto /stats /keys /clear /exit');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const heading = (s: string) => chalk.bold.hex('#8B5CF6')(s);
    const cmd = (s: string) => chalk.hex('#FBBF24')(s);
    const dim = (s: string) => muted(s);

    const lines = [
      chalk.bold.hex('#6366F1')('Vigil') + muted('  Computer Network Attack CLI  ·  press any key to dismiss'),
      '',
      heading('Quick start'),
      dim('  Type any security task or question. The agent understands natural language.'),
      dim('  Use /findings add <severity> <title> to save a finding.'),
      '',
      heading('Findings store'),
      cmd('/findings') + dim('  [list|add|rm|clear|export]   Persistent findings (survives sessions)'),
      '',
      heading('Auth & Settings'),
      cmd('/authorization') + dim('/auth   View authorization tier status'),
      cmd('/equation') + dim('/eq       The Equation — necessity defense framework'),
      cmd('/connections') + dim('/conn    Manage API keys with live validation'),
      cmd('/model') + dim('              Switch DeepSeek V4 Pro (default) / V4 Flash'),
      '',
      heading('Shell'),
      cmd('/workspace') + dim('     Session dashboard: scope, findings, phase, stats'),
      cmd('/context') + dim('        Show session context injected into every prompt'),
      cmd('/auto') + dim('          Toggle auto-continue (off → on → dual)'),
      cmd('/loop') + dim('    <interval> <prompt>  Run a prompt on a timer'),
      cmd('/bash <cmd>') + dim('    Run a local shell command'),
      cmd('/stats') + dim('         Token/cost stats + context usage (1M limit, auto-condensed)'),
      cmd('/clear') + dim('         Clear screen'),
      cmd('/exit') + dim('          Quit'),
    ];

    this.promptController.setInlinePanel(lines);
    this.scheduleInlinePanelDismiss();
  }


  private showKeyboardShortcuts(): void {
    if (!this.promptController?.supportsInlinePanel()) {
      this.promptController?.setStatusMessage('Use /keys in interactive mode');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const kb = (key: string) => chalk.hex('#FBBF24')(key);
    const desc = (text: string) => muted(text);

    const lines = [
      chalk.bold.hex('#6366F1')('Keyboard Shortcuts') + muted('  (press any key to dismiss)'),
      '',
      chalk.hex('#22D3EE')('Navigation'),
      `  ${kb('Ctrl+A')} / ${kb('Home')}  ${desc('Move to start of line')}`,
      `  ${kb('Ctrl+E')} / ${kb('End')}   ${desc('Move to end of line')}`,
      `  ${kb('Alt+←')} / ${kb('Alt+→')}  ${desc('Move word by word')}`,
      '',
      chalk.hex('#22D3EE')('Editing'),
      `  ${kb('Ctrl+U')}  ${desc('Clear entire line')}`,
      `  ${kb('Ctrl+W')} / ${kb('Alt+⌫')}  ${desc('Delete word backward')}`,
      `  ${kb('Ctrl+K')}  ${desc('Delete to end of line')}`,
      '',
      chalk.hex('#22D3EE')('Display'),
      `  ${kb('Ctrl+L')}  ${desc('Clear screen')}`,
      `  ${kb('Ctrl+O')}  ${desc('Expand last tool result')}`,
      '',
      chalk.hex('#22D3EE')('Control'),
      `  ${kb('Ctrl+C')}  ${desc('Cancel input / interrupt')}`,
      `  ${kb('Ctrl+D')}  ${desc('Exit (when empty)')}`,
      `  ${kb('Esc')}     ${desc('Interrupt AI response')}`,
    ];

    this.promptController.setInlinePanel(lines);
    this.scheduleInlinePanelDismiss();
  }

  private showSessionStats(): void {
    if (!this.promptController?.supportsInlinePanel()) {
      this.promptController?.setStatusMessage('Use /stats in interactive mode');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const history = this.controller.getHistory();
    const messageCount = history.length;
    const userMessages = history.filter(m => m.role === 'user').length;
    const assistantMessages = history.filter(m => m.role === 'assistant').length;

    // Calculate approximate token usage from history
    let totalChars = 0;
    for (const msg of history) {
      if (typeof msg.content === 'string') {
        totalChars += msg.content.length;
      }
    }
    const approxTokens = Math.round(totalChars / 4); // Rough estimate

    const collapsedCount = this.promptController?.getRenderer?.()?.getCollapsedResultCount?.() ?? 0;

    const lines = [
      chalk.bold.hex('#6366F1')('Session Stats') + muted('  (press any key to dismiss)'),
      '',
      chalk.hex('#22D3EE')('Conversation'),
      `  ${chalk.white(messageCount.toString())} messages (${userMessages} user, ${assistantMessages} assistant)`,
      `  ${muted('~')}${chalk.white(approxTokens.toLocaleString())} ${muted('tokens (estimate)')}`,
      '',
      chalk.hex('#22D3EE')('Target scope'),
      ...(this.sessionTargets.length
        ? this.sessionTargets.map((t) => `  ${chalk.green('●')} ${chalk.white(t)}`)
        : [`  ${muted('none — use /target add <host>')}`]),
      ...(this.sessionActivePhase ? [`  Phase: ${chalk.hex('#FBBF24')(this.sessionActivePhase)}`] : []),
      '',
      chalk.hex('#22D3EE')('Model'),
      `  ${chalk.white(this.profileConfig.model)} ${muted('on')} ${chalk.hex('#A855F7')(this.profileConfig.provider)}`,
      collapsedCount > 0 ? `  ${chalk.white(collapsedCount.toString())} collapsed results` : '',
      '',
      chalk.hex('#22D3EE')('Settings'),
      `  Debug: ${this.debugEnabled ? chalk.green('on') : muted('off')}`,
    ].filter(line => line !== '');

    this.promptController.setInlinePanel(lines);
    this.scheduleInlinePanelDismiss();
  }


  private async showMcpStatus(): Promise<void> {
    const manager = getSharedMcpManager(this.workingDir);
    await manager.init();
    const entries = manager.getEntries();

    if (!this.promptController?.supportsInlinePanel()) {
      const summary = entries.length === 0
        ? 'No MCP servers configured (.vigil/mcp.json)'
        : entries.map(e => e.status === 'connected'
            ? `${e.name}: ${e.tools.length} tools`
            : `${e.name}: ERROR (${e.error})`).join(' · ');
      this.promptController?.setStatusMessage(summary);
      setTimeout(() => this.promptController?.setStatusMessage(null), 4000);
      return;
    }

    const lines: string[] = [
      chalk.bold.hex('#6366F1')('MCP Servers') + muted('  (.vigil/mcp.json)'),
      '',
    ];
    if (entries.length === 0) {
      lines.push(muted('  No servers configured.'));
      lines.push(muted('  Add entries to ~/.vigil/mcp.json or <project>/.vigil/mcp.json.'));
    } else {
      for (const entry of entries) {
        if (entry.status === 'connected') {
          lines.push(
            `  ${chalk.green('●')} ${chalk.white(entry.name)} ` +
            muted(`${entry.spec.command}${entry.spec.args?.length ? ' ' + entry.spec.args.join(' ') : ''}`)
          );
          lines.push(`    ${muted('tools: ')}${chalk.hex('#22D3EE')(String(entry.tools.length))}`);
          for (const t of entry.tools.slice(0, 8)) {
            lines.push(`      ${muted('·')} ${chalk.white(t.name)}`);
          }
          if (entry.tools.length > 8) {
            lines.push(`      ${muted(`… +${entry.tools.length - 8} more`)}`);
          }
        } else {
          lines.push(`  ${chalk.red('●')} ${chalk.white(entry.name)} ${chalk.red('error')}`);
          lines.push(`    ${muted(entry.error)}`);
        }
      }
    }

    this.promptController.setInlinePanel(lines);
    this.scheduleInlinePanelDismiss();
  }

  /**
   * Auto-dismiss inline panel after timeout or on next input.
   */
  private inlinePanelDismissTimer: ReturnType<typeof setTimeout> | null = null;

  private scheduleInlinePanelDismiss(): void {
    // Clear any existing timer
    if (this.inlinePanelDismissTimer) {
      clearTimeout(this.inlinePanelDismissTimer);
    }
    // Auto-dismiss after 8 seconds
    this.inlinePanelDismissTimer = setTimeout(() => {
      this.promptController?.clearInlinePanel();
      this.inlinePanelDismissTimer = null;
    }, 8000);
  }

  private dismissInlinePanel(): void {
    if (this.inlinePanelDismissTimer) {
      clearTimeout(this.inlinePanelDismissTimer);
      this.inlinePanelDismissTimer = null;
    }
    this.promptController?.clearInlinePanel();
  }

  private async handleSubmit(text: string): Promise<void> {
    const trimmed = text.trim();

    // Handle secret input mode - capture the API key value
    if (this.secretInputMode.active && this.secretInputMode.secretId) {
      this.handleSecretValue(trimmed);
      return;
    }

    if (!trimmed) {
      return;
    }

    // Handle slash commands first - these don't go to the AI
    if (trimmed.startsWith('/')) {
      if (await Promise.resolve(this.handleSlashCommand(trimmed))) {
        return;
      }
      // Unknown slash command - silent status flash, dismiss inline panel
      this.dismissInlinePanel();
      this.promptController?.setStatusMessage(`Unknown: ${trimmed.slice(0, 30)}`);
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return;
    }

    // Dismiss inline panel for regular user prompts
    this.dismissInlinePanel();

    if (this.isProcessing) {
      this.pendingPrompts.push(trimmed);
      return;
    }

    void this.processPrompt(trimmed);
  }

  private async processPrompt(prompt: string): Promise<void> {
    if (this.isProcessing) {
      return;
    }

    // Start new run for file change tracking (enables /revert)
    startNewRun();

    let sanitizedPrompt = prompt;

    // Inject session target scope so every response is target-aware
    if (this.sessionTargets.length > 0 && !prompt.startsWith('[安全阶段:') && !prompt.startsWith('IMPORTANT:')) {
      const scopeLine = `[Session scope — authorized targets: ${this.sessionTargets.join(', ')}]`;
      sanitizedPrompt = `${scopeLine}\n${sanitizedPrompt}`;
    }

    // Inject findings store summary for remediation/triage/report queries
    // so the agent grounds its response in actual stored data, not just conversation
    const findingsKeywords = /\b(remedia|triage|prioriti|report|findings?|patch|fix|vulner|CVE|critical|exploit|KEV|EPSS)\b/i;
    if (findingsKeywords.test(prompt) && !prompt.startsWith('[安全阶段:') && !prompt.startsWith('IMPORTANT:')) {
      const stored = loadFindings();
      if (stored.length > 0) {
        const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
        const top = [...stored]
          .sort((a, b) => {
            // Sort: KEV first, then by severity, then by EPSS desc
            if (a.kev && !b.kev) return -1;
            if (!a.kev && b.kev) return 1;
            const si = sevOrder.indexOf(a.severity) - sevOrder.indexOf(b.severity);
            if (si !== 0) return si;
            return (b.epss ?? 0) - (a.epss ?? 0);
          })
          .slice(0, 15);
        const kevCount = stored.filter((f) => f.kev).length;
        const critHighCount = stored.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
        const findingsSummaryLines = top.map((f) =>
          `- [${f.severity.toUpperCase()}] ${f.cve ?? f.id}: ${f.title}` +
          (f.cvss != null ? ` | CVSS:${f.cvss}` : '') +
          (f.epss != null ? ` | EPSS:${(f.epss * 100).toFixed(1)}%` : '') +
          (f.kev ? ' | KEV:YES' : '') +
          (f.target ? ` | asset:${f.target}` : '')
        ).join('\n');
        const findingsCtx =
          `[Findings store: ${stored.length} total, ${critHighCount} crit/high, ${kevCount} KEV-listed. Top findings:\n${findingsSummaryLines}]`;
        sanitizedPrompt = `${findingsCtx}\n${sanitizedPrompt}`;
      }
    }

    // Store original prompt for auto-continuation (if not a continuation or auto-generated prompt)
    if (prompt !== 'continue' && !prompt.startsWith('IMPORTANT:')) {
      this.originalPromptForAutoContinue = prompt;
      // A fresh user prompt clears any prior interrupt state — this is new
      // work the user actually wants done.
      this.userInterruptedRun = false;
      // Pinned-prompt persistence removed per request — no longer
      // displayed above the chat box.
    }

    enterCriticalSection();

    this.isProcessing = true;
    this.currentResponseBuffer = '';
    this.promptController?.setStreaming(true);
    this.promptController?.setStatusMessage('Processing request...');

    const renderer = this.promptController?.getRenderer();

    let episodeSuccess = false;
    const toolsUsed: string[] = [];
    const filesModified: string[] = [];

    // Track reasoning content for fallback when response is empty
    let reasoningBuffer = '';

    // Track reasoning-only time to prevent models from reasoning forever without action
    let reasoningOnlyStartTime: number | null = null;
    let reasoningTimedOut = false;
    let stepTimedOut = false;
    let hitlDepth = 0;

    // Track total prompt processing time to prevent infinite loops
    const promptStartTime = Date.now();
    const TOTAL_RUN_TIMEOUT_MS = 15 * 60 * 1000; // 15 min — security CLI auto-terminates
    let hasReceivedMeaningfulContent = false;
    // Track response content separately - tool calls don't count for reasoning timeout
    let hasReceivedResponseContent = false;
    let quotaExhausted = false;

    try {
      // Use timeout-wrapped iterator to prevent hanging on slow/stuck models
      for await (const eventOrTimeout of iterateWithTimeout(
        this.controller.send(sanitizedPrompt),
        PROMPT_STEP_TIMEOUT_MS
      )) {
        // Check for timeout marker
        if (eventOrTimeout && typeof eventOrTimeout === 'object' && '__timeout' in eventOrTimeout) {
          if (hitlDepth > 0) {
            this.promptController?.setStatusMessage('⏱ Waiting for human decision...');
            continue;
          }
          stepTimedOut = true;
          this.promptController?.setStatusMessage(`⏱ Step timeout (${PROMPT_STEP_TIMEOUT_MS / 1000}s) - completing response`);
          // Cancel the controller so the underlying agent stops generating
          // events that would never be consumed. Without this the spinner
          // can keep ticking against a "ghost" run after the for-await
          // loop exits, and any in-flight tool keeps doing work the user
          // can't see or stop.
          try { this.controller.cancel('step timeout'); } catch { /* best-effort */ }
          break;
        }

        // Check total elapsed time — hard 15-min security timeout
        const totalElapsed = Date.now() - promptStartTime;
        if (totalElapsed > TOTAL_RUN_TIMEOUT_MS) {
          if (renderer) {
            renderer.addEvent('response', chalk.yellow(`\n⏱ Run timeout (${Math.round(totalElapsed / 1000)}s) — security CLI auto-terminates\n`));
          }
          try { this.controller.cancel('run timeout'); } catch { /* best-effort */ }
          break;
        }

        const event = eventOrTimeout as AgentEventUnion;
        if (this.shouldExit) {
          break;
        }

        switch (event.type) {
          case 'message.start':
            // AI has started processing - update status to show activity
            this.currentResponseBuffer = '';
            reasoningBuffer = '';
            reasoningOnlyStartTime = null; // Reset on new message
            this.promptController?.setStatusMessage('Analyzing request...');
            break;

          case 'message.delta':
            // Stream content as it arrives
            this.currentResponseBuffer += event.content ?? '';
            if (renderer) {
              renderer.addEvent('stream', event.content);
            }
            // Reset reasoning timer only when we get actual non-empty content
            if (event.content && event.content.trim()) {
              reasoningOnlyStartTime = null;
              hasReceivedMeaningfulContent = true;
              hasReceivedResponseContent = true; // Track actual response content
            }
            break;

          case 'reasoning':
            // Accumulate reasoning for potential fallback synthesis
            reasoningBuffer += event.content ?? '';
            // Update status to show what the model is actually working on
            if (event.content?.trim()) {
              const snippet = extractReasoningSnippet(event.content);
              this.promptController?.setActivityMessage(snippet);
            } else {
              this.promptController?.setActivityMessage('Thinking...');
            }
            // Start the reasoning timer on first reasoning event
            if (!reasoningOnlyStartTime) {
              reasoningOnlyStartTime = Date.now();
            }
            // Display useful reasoning as 'thought' events BEFORE the response
            // The renderer's curateReasoningContent and shouldRenderThought will filter
            // to show only actionable/structured thoughts
            if (renderer && event.content?.trim()) {
              renderer.addEvent('thought', event.content);
            }
            break;

          case 'message.complete':
            // Response complete — clear thinking AND reasoning indicators
            // both. statusMessage clears 'Thinking...' (set on message.start
            // and after each tool); activityMessage clears the reasoning
            // chip (set on every 'reasoning' event but never reset until
            // the post-loop finally). Without clearing activityMessage
            // here, the spinner kept ticking between message-end and the
            // next event because composedStatus falls through to the still-
            // set 'Thinking' activity label.
            this.promptController?.setStatusMessage(null);
            this.promptController?.setActivityMessage(null);

            // Response complete - ensure final output is committed to history.
            // Prefer event.content (canonical, properly formatted) over
            // streamed deltas (token-level fragments with missing punctuation).
            if (renderer) {
              const base = (event.content ?? '').trimEnd();
              let sourceText = (base || this.currentResponseBuffer).trim();

              if (sourceText) {
                // Use canonical text directly — this yields proper grammar
                // and punctuation that streaming deltas lose at token boundaries.
                renderer.addEvent('response', sourceText);
              }

              // Fallback: If response is empty but we have reasoning, synthesize a response
              if (!sourceText && reasoningBuffer.trim()) {
                // Extract key conclusions from reasoning for display
                const synthesized = this.synthesizeFromReasoning(reasoningBuffer);
                if (synthesized) {
                  renderer.addEvent('response', synthesized);
                  sourceText = synthesized;
                }
              }

              episodeSuccess = true; // Mark episode as successful only after we have content

              // Only add "Next steps" if tools were actually used (real work done)
              // This prevents showing "Next steps" after reasoning-only responses
              if (toolsUsed.length > 0) {
                const { appended } = ensureNextSteps(sourceText);
                // Only stream the newly appended content (e.g., "Next steps:")
                // The main response was already added as a response event above
                if (appended && appended.trim()) {
                  renderer.addEvent('response', appended);
                }
              }
              renderer.addEvent('response', '\n');

              // ── Auto-extract CVEs from agent response ──────────────────────
              // Scan the completed response for CVE-YYYY-NNNNN patterns and
              // offer to save any new ones to the persistent findings store.
              this.autoExtractCVEs(sourceText, renderer);

            }
            this.currentResponseBuffer = '';
            break;

          case 'tool.start': {
            const toolName = event.toolName;
            const args = event.parameters;
            // Default format: `ToolName(arg)` — Claude Code's idiom.
            // ChatStatic prefixes a `⏺ ` glyph for kind='tool', so this
            // string is what reads after the bullet. Shorter and more
            // scannable than `[ToolName] arg`.
            let toolDisplay = toolName;
            if (isHitlToolName(toolName)) {
              hitlDepth += 1;
            }

            // Reset reasoning timer when tools are being called (model is taking action)
            reasoningOnlyStartTime = null;
            hasReceivedMeaningfulContent = true;

            if (!toolsUsed.includes(toolName)) {
              toolsUsed.push(toolName);
            }
            this.sessionToolsUsed.add(toolName);

            const filePath = args?.['file_path'] as string | undefined;
            if (filePath && (toolName === 'Write' || toolName === 'Edit')) {
              if (!filesModified.includes(filePath)) {
                filesModified.push(filePath);
              }
              this.sessionFilesModified.add(filePath);
            }

            if (toolName === 'Bash' && args?.['command']) {
              toolDisplay = `Bash(${String(args['command']).slice(0, 120)})`;
            } else if (toolName === 'Read' && args?.['file_path']) {
              toolDisplay = `Read(${args['file_path']})`;
            } else if (toolName === 'Write' && args?.['file_path']) {
              toolDisplay = `Write(${args['file_path']})`;
            } else if (toolName === 'Edit' && args?.['file_path']) {
              toolDisplay = `Edit(${args['file_path']})`;
            } else if (toolName === 'Search' && args?.['pattern']) {
              toolDisplay = `Search(${args['pattern']})`;
            } else if (toolName === 'Grep' && args?.['pattern']) {
              toolDisplay = `Grep(${args['pattern']})`;
            } else if (toolName === 'WebSearch' && args?.['query']) {
              toolDisplay = `WebSearch("${String(args['query']).slice(0, 80)}")`;
            } else if (toolName === 'WebExtract') {
              const urlsArg = args?.['urls'];
              const urls: string[] = Array.isArray(urlsArg)
                ? urlsArg.filter((u): u is string => typeof u === 'string')
                : typeof args?.['url'] === 'string'
                  ? [args['url'] as string]
                  : [];
              const display = urls.length > 0
                ? urls.length === 1 ? urls[0] : `${urls[0]} (+${urls.length - 1} more)`
                : '...';
              toolDisplay = `WebExtract(${display})`;
            }

            if (renderer) {
              renderer.addEvent('tool', toolDisplay);
            }

            // Provide explanatory status messages for different tool types
            let statusMsg = '';
            if (toolName === 'Bash') {
              statusMsg = `Running: ${args?.['command'] ? String(args['command']).slice(0, 40) : '...'}`;
            } else if (toolName === 'Edit' || toolName === 'Write') {
              statusMsg = `📝 Editing file: ${args?.['file_path'] || '...'}`;
            } else if (toolName === 'Read') {
              statusMsg = `📖 Reading file: ${args?.['file_path'] || '...'}`;
            } else if (toolName === 'Search' || toolName === 'Grep') {
              statusMsg = `🔍 Searching: ${args?.['pattern'] ? String(args['pattern']).slice(0, 30) : '...'}`;
            } else if (toolName === 'WebSearch') {
              statusMsg = `🌐 Searching web: ${args?.['query'] ? String(args['query']).slice(0, 40) : '...'}`;
            } else if (toolName === 'WebExtract') {
              const urlsArg = args?.['urls'];
              const firstUrl = Array.isArray(urlsArg)
                ? urlsArg.find((u) => typeof u === 'string')
                : typeof args?.['url'] === 'string' ? args['url'] : '...';
              statusMsg = `🌐 Extracting: ${String(firstUrl ?? '...').slice(0, 50)}`;
            } else {
              statusMsg = `🔧 Running ${toolName}...`;
            }

            this.promptController?.setStatusMessage(statusMsg);
            break;
          }

          case 'tool.complete': {
            if (isHitlToolName(event.toolName)) {
              hitlDepth = Math.max(0, hitlDepth - 1);
            }
            // Clear the "Running X..." status since tool is complete
            this.promptController?.setStatusMessage('Processing results...');
            // Reset reasoning timer after tool completes
            reasoningOnlyStartTime = null;
            // The legacy "Done:" header for Bash was redundant — the
            // tool-result item now renders with its own `  ↳ ` indent
            // so the call→result pairing is visually obvious without
            // a separate header line.
            // Pass full result to renderer - it handles display truncation
            // and stores full content for Ctrl+O expansion
            if (event.result && typeof event.result === 'string' && event.result.trim() && renderer) {
              renderer.addEvent('tool-result', event.result);
            }
            break;
          }

          case 'tool.error':
            if (isHitlToolName(event.toolName)) {
              hitlDepth = Math.max(0, hitlDepth - 1);
            }
            // Clear the "Running X..." status since tool errored
            this.promptController?.setStatusMessage('Processing results...');
            if (renderer) {
              renderer.addEvent('error', event.error);
            }
            break;

          case 'error': {
            if (renderer) {
              renderer.addEvent('error', event.error);
            }
            // Auto-terminate on fatal errors that will never self-correct
            const errMsg = (event.error ?? '').toLowerCase();
            if (errMsg.includes('insufficient_balance') || errMsg.includes('insufficient balance') ||
                errMsg.includes('quota exceeded') || errMsg.includes('quota exhausted') ||
                errMsg.includes('monthly limit') || errMsg.includes('insufficient_quota') ||
                errMsg.includes('usage limit exceeded') || errMsg.includes('payment required') ||
                errMsg.includes('api key') || errMsg.includes('unauthorized') ||
                errMsg.includes('http 401') || errMsg.includes('authentication') ||
                errMsg.includes('circuit breaker') || errMsg.includes('too many failures') ||
                errMsg.includes('insufficient tool messages') || errMsg.includes('tool_calls must be followed') ||
                errMsg.includes('invalid api key')) {
              // All of these are fatal — retrying won't help, only makes the
              // corrupted conversation state worse.
              quotaExhausted = true;
              this.shouldExit = true;
              if (renderer) {
                if (errMsg.includes('api key') || errMsg.includes('unauthorized') || errMsg.includes('http 401') || errMsg.includes('authentication') || errMsg.includes('invalid')) {
                  renderer.addEvent('banner', chalk.red('🔑 API key invalid or expired.'));
                  renderer.addEvent('banner', muted('  Set a valid key: vigil --key sk-...'));
                } else if (errMsg.includes('circuit breaker') || errMsg.includes('too many failures')) {
                  renderer.addEvent('banner', chalk.red('⚡ Circuit breaker open — too many failures.'));
                  renderer.addEvent('banner', muted('  The conversation state is corrupted. Start a new session.'));
                } else if (errMsg.includes('tool_calls') || errMsg.includes('insufficient tool messages')) {
                  renderer.addEvent('banner', chalk.red('🔧 Tool call state mismatch — conversation corrupted.'));
                  renderer.addEvent('banner', muted('  Start a new session. Auto-continue was compounding the error.'));
                } else {
                  renderer.addEvent('banner', chalk.red(`🚫 ${event.error}`));
                }
              }
              try { this.controller.cancel('fatal error'); } catch { /* best-effort */ }
              break;
            }
            break;
          }

          case 'usage':
            this.promptController?.setMetaStatus({
              tokensUsed: event.totalTokens,
              tokenLimit: 1_000_000, // DeepSeek V4 Pro/Flash: 1M context (api-docs.deepseek.com)
            });
            // Roll up to session totals for the session-end Firestore write.
            this.sessionTokensIn += event.inputTokens || 0;
            this.sessionTokensOut += event.outputTokens || 0;
            break;

          case 'provider.fallback': {
            // Auto-terminate on balance insufficient fallback — don't keep cycling providers
            const reasonLower = (event.reason ?? '').toLowerCase();
            if (reasonLower.includes('insufficient_balance') || reasonLower.includes('insufficient balance') ||
                reasonLower.includes('quota') || reasonLower.includes('billing') ||
                reasonLower.includes('payment required')) {
              quotaExhausted = true;
              this.shouldExit = true;
              if (renderer) {
                renderer.addEvent('banner', chalk.red(`🚫 ${event.reason} — run terminated.`));
                renderer.addEvent('banner', chalk.yellow('💡 Use your own API keys:'));
                renderer.addEvent('banner', muted('  vigil --key sk-...  |  vigil --tavily-key tvly-...'));
                renderer.addEvent('banner', muted('  DeepSeek: https://platform.deepseek.com/api_keys'));
              }
              try { this.controller.cancel('quota exhausted'); } catch { /* best-effort */ }
              break;
            }
            // Display fallback notification
            if (renderer) {
              const fallbackMsg = chalk.yellow('⚠ ') +
                muted(`${event.fromProvider}/${event.fromModel} failed: `) +
                chalk.hex('#EF4444')(event.reason) +
                muted(' → switching to ') +
                chalk.hex('#34D399')(`${event.toProvider}/${event.toModel}`);
              renderer.addEvent('banner', fallbackMsg);
            }

            // Update the model context to reflect the new provider/model
            this.profileConfig = {
              ...this.profileConfig,
              provider: event.toProvider,
              model: event.toModel,
            };
            this.promptController?.setModelContext({
              model: event.toModel,
              provider: event.toProvider,
            });
            break;
          }

          case 'edit.explanation':
            // Show explanation for edits made
            if (event.content && renderer) {
              const filesInfo = event.files?.length ? ` (${event.files.join(', ')})` : '';
              renderer.addEvent('response', `${event.content}${filesInfo}`);
            }
            break;

        }

        // Check reasoning timeout on EVERY iteration (not just when reasoning events arrive)
        // This ensures we bail out even if events are sparse
        // Use hasReceivedResponseContent (not hasReceivedMeaningfulContent) so timeout
        // still triggers after tool calls if model just reasons without responding
        if (reasoningOnlyStartTime && !hasReceivedResponseContent) {
          const reasoningElapsed = Date.now() - reasoningOnlyStartTime;
          if (reasoningElapsed > PROMPT_REASONING_TIMEOUT_MS) {
            if (renderer) {
              renderer.addEvent('response', chalk.yellow(`\n⏱ Reasoning timeout (${Math.round(reasoningElapsed / 1000)}s)\n`));
            }
            reasoningTimedOut = true;
          }
        }

        // Check if reasoning timeout was triggered - break out of event loop
        if (reasoningTimedOut) {
          // Cancel the controller too; otherwise the for-await drain
          // exits but the agent keeps producing events and side-effects
          // for the next 30+ seconds with no UI to consume them.
          try { this.controller.cancel('reasoning timeout'); } catch { /* best-effort */ }
          break;
        }
      }

      // After loop: synthesize from reasoning if no response was generated or timed out
      // This handles models like deepseek-v4-pro that output thinking but empty response
      // Also handles step timeouts where the model was stuck
      // IMPORTANT: Don't add "Next steps" when only reasoning occurred - only after real work
      if ((!episodeSuccess || reasoningTimedOut || stepTimedOut) && reasoningBuffer.trim() && !this.currentResponseBuffer.trim()) {
        const synthesized = this.synthesizeFromReasoning(reasoningBuffer);
        if (synthesized && renderer) {
          renderer.addEvent('stream', '\n' + synthesized);
          // Only add "Next steps" if tools were actually used (real work done)
          if (toolsUsed.length > 0) {
            const { appended } = ensureNextSteps(synthesized);
            if (appended?.trim()) {
              renderer.addEvent('stream', appended);
            }
          }
          renderer.addEvent('response', '\n');
          episodeSuccess = true;
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (renderer) {
        renderer.addEvent('error', message);
      }

      // Fallback: If we have reasoning content but no response was generated, synthesize one
      if (!episodeSuccess && reasoningBuffer.trim() && !this.currentResponseBuffer.trim()) {
        const synthesized = this.synthesizeFromReasoning(reasoningBuffer);
        if (synthesized && renderer) {
          renderer.addEvent('stream', '\n' + synthesized);
          renderer.addEvent('response', '\n');
          episodeSuccess = true; // Mark as partial success
        }
      }
    } finally {
      // Exit critical section - allow termination again
      exitCriticalSection();

      // Final fallback: If stream ended without message.complete but we have reasoning
      if (!quotaExhausted && !episodeSuccess && reasoningBuffer.trim() && !this.currentResponseBuffer.trim()) {
        const synthesized = this.synthesizeFromReasoning(reasoningBuffer);
        if (synthesized && renderer) {
          renderer.addEvent('stream', '\n' + synthesized);
          // Only add "Next steps" if tools were actually used (real work done)
          if (toolsUsed.length > 0) {
            const { appended } = ensureNextSteps(synthesized);
            if (appended?.trim()) {
              renderer.addEvent('stream', appended);
            }
          }
          renderer.addEvent('response', '\n');
          episodeSuccess = true;
        }
      }

      // Detect a model safety refusal in the just-finished turn. When the
      // model declines the request, the request is *done* — auto-continue
      // would just resubmit "continue" and start a new spinner cycle, which
      // is what produced the stuck "Thinking… (4m N s)" timer the user saw.
      const refusedTurn = isSafetyRefusal(this.currentResponseBuffer);

      this.isProcessing = false;
      this.promptController?.setStreaming(false);
      this.promptController?.setStatusMessage(null);
      // Belt-and-suspenders: explicitly clear the activity message so the
      // "Thinking… (esc to interrupt · Ns)" line doesn't linger after the
      // final reply if setMode→stopSpinnerAnimation races with another
      // renderPrompt tick.
      this.promptController?.setActivityMessage(null);
      // Force an idle re-render so the spinner area is repainted without
      // the streaming activity line. setStreaming(false) → setMode('idle')
      // already calls renderPrompt(), but a coalesced spinner tick that
      // races with the transition can leave the last "Thinking… (Ns)"
      // frame on screen until the next event. forceRender squashes it.
      this.promptController?.forceRender();

      this.currentResponseBuffer = '';

      // Process any queued prompts
      if (this.pendingPrompts.length > 0 && !this.shouldExit) {
        const next = this.pendingPrompts.shift();
        if (next) {
          await this.processPrompt(next);
        }
      } else if (refusedTurn) {
        // Refusal terminates the turn. Don't re-prompt the model — the
        // user's request is finished from the agent's side. Clear the
        // stored "original prompt" so a stray Alt+G later doesn't pick
        // up where this turn left off.
        this.originalPromptForAutoContinue = null;
      } else if (!this.shouldExit && !this.userInterruptedRun && !refusedTurn) {
        // Auto mode: keep running until user's prompt is fully completed.
        // Skipped after a Ctrl+C interrupt so we don't immediately resume
        // the work the user just cancelled. Also skipped on safety refusals
        // to prevent infinite refusal loops.
        const autoMode = this.promptController?.getAutoMode() ?? 'off';
        if (autoMode !== 'off') {
          // Check if original user prompt is fully completed
          const detector = getTaskCompletionDetector();
          const analysis = detector.analyzeCompletion(this.currentResponseBuffer, toolsUsed);

          // Continue until task is complete
          if (!analysis.isComplete) {
            this.promptController?.setStatusMessage('Continuing...');
            await new Promise(resolve => setTimeout(resolve, 500));

            // Generate auto-continue prompt using stored original prompt
            const autoPrompt = this.generateAutoContinuePrompt(
              this.originalPromptForAutoContinue || '',
              this.currentResponseBuffer,
              toolsUsed,
            );

            const finalPrompt = autoPrompt || 'continue';
            // Show the auto-continue prompt in the chat so the user can see what's happening
            if (renderer) {
              const shortPreview = finalPrompt.length > 120 ? finalPrompt.slice(0, 120) + '...' : finalPrompt;
              renderer.addEvent('system', `continue: ${shortPreview}`);
            }
            await this.processPrompt(finalPrompt);
          } else {
            this.promptController?.setStatusMessage('Task complete');
            setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
          }
        } else if (episodeSuccess && !stepTimedOut && !reasoningTimedOut) {
          // Manual mode (autoMode === 'off') — show a brief end-of-turn
          // signal so the user knows the agent is idle again. Without
          // this the spinner just vanishes silently, which on slow
          // terminals reads as "still thinking" or "hung". Skipped on
          // errors / timeouts because those already render their own
          // explanatory bubble.
          this.promptController?.setStatusMessage('✓ Done');
          setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
        }
      }
    }
  }

  private generateAutoContinuePrompt(originalPrompt: string, response: string, toolsUsed: string[]): string | null {
    // Highest-priority signal: a test or build is currently failing
    // in the visible output. Override every other heuristic and force
    // a sharp, focused next-action prompt — the agent must drill into
    // the FIRST failure rather than declaring victory.
    const failingSignal = detectFailingTestOrBuild(response);
    if (failingSignal) {
      const noDocsInstruction = `IMPORTANT: Do NOT create markdown files, documentation, summaries, or reports.`;
      return `${noDocsInstruction} The output above shows a failing test/build (${failingSignal}). Read the FIRST failure carefully, identify the root cause, edit exactly the file(s) needed, then re-run the same test/build command to confirm. Do not stop until that command exits cleanly.`;
    }

    // Any tool usage is meaningful work — continue unless the model explicitly stopped.
    const hasFileOperations = toolsUsed.some(t => ['Read', 'Write', 'Edit', 'Search', 'Grep'].includes(t));
    const hasBashOperations = toolsUsed.includes('Bash');
    const hasWebOperations = toolsUsed.some(t => ['WebSearch', 'WebExtract', 'WebFetch'].includes(t));
    const hasOtherTools = toolsUsed.some(t => !['Read', 'Write', 'Edit', 'Search', 'Grep', 'Bash', 'WebSearch', 'WebExtract', 'WebFetch'].includes(t));

    if (!hasFileOperations && !hasBashOperations && !hasWebOperations && !hasOtherTools) {
      return null; // No tools used at all — nothing to continue
    }

    // Analyze response to determine what to do next
    const lowercaseResponse = response.toLowerCase();
    const noDocsInstruction = `IMPORTANT: Do NOT create markdown files, documentation, summaries, or reports. Continue the actual operational work.`;

    // Check for common patterns that indicate more work is needed
    const needsMoreWork =
      lowercaseResponse.includes('next step') ||
      lowercaseResponse.includes('further') ||
      lowercaseResponse.includes('additional') ||
      lowercaseResponse.includes('implement') ||
      lowercaseResponse.includes('complete') ||
      lowercaseResponse.includes('finish') ||
      lowercaseResponse.includes('proceed') ||
      lowercaseResponse.includes('starting') ||
      lowercaseResponse.includes('phase') ||
      lowercaseResponse.includes('continue');

    if (needsMoreWork) {
      // Generate a follow-up prompt based on the original task
      if (originalPrompt.includes('fix') || originalPrompt.includes('bug')) {
        return `${noDocsInstruction} Continue fixing - edit the next file that needs changes.`;
      } else if (originalPrompt.includes('implement') || originalPrompt.includes('add')) {
        return `${noDocsInstruction} Continue implementing - write or edit the next piece of code.`;
      } else if (originalPrompt.includes('refactor') || originalPrompt.includes('clean')) {
        return `${noDocsInstruction} Continue refactoring - apply changes to the next file.`;
      } else if (originalPrompt.includes('test')) {
        return `${noDocsInstruction} Continue with tests - run or fix the next test.`;
      } else if (originalPrompt.includes('build') || originalPrompt.includes('deploy') || originalPrompt.includes('publish')) {
        return `${noDocsInstruction} Continue the build/deploy process - execute the next command.`;
      } else {
        const taskPreview = originalPrompt.slice(0, 100).replace(/\n/g, ' ');
        return `${noDocsInstruction} Continue the task: ${taskPreview} — perform the next concrete action. Do not stop analyzing or executing until the task is fully complete.`;
      }
    }

    // Even without explicit "next steps" language, if tools were used
    // but no completion signal was emitted, keep going.
    if (!lowercaseResponse.includes('done') && !lowercaseResponse.includes('finished') && !lowercaseResponse.includes('completed')) {
      const taskPreview = originalPrompt.slice(0, 100).replace(/\n/g, ' ');
      return `${noDocsInstruction} Continue the task: ${taskPreview} — perform the next concrete action.`;
    }

    return null;
  }

  private handleInterrupt(): void {
    if (!this.isProcessing) {
      return;
    }
    const renderer = this.promptController?.getRenderer();
    if (renderer) {
      renderer.addEvent('banner', chalk.yellow('Interrupted'));
    }
    // Actually cancel the in-flight controller run. Without this the
    // for-await loop in processPrompt keeps consuming events, the spinner
    // stays up, and the agent grinds through the rest of its tool loop
    // while the user sees only a "Interrupted" banner. cancel() is a no-op
    // when there's no active sink, so this is safe to call unconditionally.
    try {
      this.controller.cancel('user interrupt via Ctrl+C');
    } catch {
      // Best-effort; if the controller is already torn down the next
      // Ctrl+C will fall through to authorizedShutdown.
    }
    // Suppress the auto-continue re-launch in processPrompt's finally
    // block. Otherwise the agent immediately starts a fresh "continue"
    // cycle 500ms later and the user has to keep mashing Ctrl+C to keep
    // up. Cleared when the user submits a new prompt.
    this.userInterruptedRun = true;
  }

  private handleAutoContinueToggle(): void {
    const autoMode = this.promptController?.getAutoMode() ?? 'off';

    this.promptController?.setStatusMessage(`Auto: ${autoMode}`);
    setTimeout(() => this.promptController?.setStatusMessage(null), 1500);

    // Reset task completion detector when entering any auto mode
    if (autoMode !== 'off') {
      const detector = getTaskCompletionDetector();
      detector.reset();
      // Clear any stored original prompt
      this.originalPromptForAutoContinue = null;
    }
  }

  private handleHITLToggle(): void {
    const mode = this.promptController?.getModeToggleState().hitlMode ?? 'off';
    getHITL().updateConfig({ autoPause: mode === 'on' });
    this.promptController?.setStatusMessage(`HITL: ${mode}`);
    setTimeout(() => this.promptController?.setStatusMessage(null), 1500);
  }

  private handleCtrlC(info: { hadBuffer: boolean }): void {
    const now = Date.now();

    // Reset count if more than 2 seconds since last Ctrl+C
    if (now - this.lastCtrlCTime > 2000) {
      this.ctrlCCount = 0;
    }

    this.lastCtrlCTime = now;
    this.ctrlCCount++;

    if (info.hadBuffer) {
      // Clear buffer, reset count
      this.ctrlCCount = 0;
      return;
    }

    // Always allow double Ctrl+C to exit, even while processing
    if (this.ctrlCCount >= 2) {
      // Use authorized shutdown to bypass anti-termination guard
      void authorizedShutdown(0);
      this.shouldExit = true;
      this.ctrlCCount = 0;
      return;
    }

    if (this.isProcessing) {
      // Interrupt processing on first Ctrl+C, then allow next Ctrl+C to exit
      this.handleInterrupt();
      const renderer = this.promptController?.getRenderer();
      if (renderer) {
        renderer.addEvent('banner', muted('Press Ctrl+C again to exit'));
      }
      return;
    }

    // First Ctrl+C when idle: show hint
    const renderer = this.promptController?.getRenderer();
    if (renderer) {
      renderer.addEvent('banner', muted('Press Ctrl+C again to exit'));
    }
  }

  private handleExit(): void {
    this.shouldExit = true;
    // Persist session state so next run restores targets + phase
    savePersistedSession(this.sessionTargets, this.sessionActivePhase);
    // Stop active loop if running
    this.stopLoop();
    this.cleanupSudoPasswordHandler();
    this.promptController?.stop();
    void authorizedShutdown(0);
  }

  private waitForExit(): Promise<void> {
    return new Promise((resolve) => {
      const check = (): void => {
        if (this.shouldExit) {
          resolve();
        } else {
          setTimeout(check, 100);
        }
      };
      check();
    });
  }

  // ── /loop command ─────────────────────────────────────────────────────

  private handleLoopCommand(fullCommand: string): boolean {
    const trimmed = fullCommand.trim();
    const parts = trimmed.split(/\s+/);
    // parts[0] = '/loop'
    const sub = parts.slice(1).join(' ').trim();

    if (!sub || sub === 'status') {
      this.showLoopStatus();
      return true;
    }

    if (sub === 'stop') {
      this.stopLoop();
      this.promptController?.setStatusMessage('Loop stopped');
      setTimeout(() => this.promptController?.setStatusMessage(null), 1500);
      return true;
    }

    // Parse: /loop <interval> <prompt>
    // Interval: 30s, 5m, 1h, or bare number (seconds)
    const intervalMatch = parts[1]?.match(/^(\d+)(s|m|h)?$/);
    if (!intervalMatch) {
      this.promptController?.setStatusMessage('Usage: /loop <interval> <prompt>  (e.g. /loop 30s scan)');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return true;
    }

    const value = parseInt(intervalMatch[1], 10);
    const unit = intervalMatch[2] || 's';
    let intervalMs = value * 1000;
    if (unit === 'm') intervalMs = value * 60 * 1000;
    if (unit === 'h') intervalMs = value * 60 * 60 * 1000;

    // Minimum 5 seconds, maximum 24 hours
    if (intervalMs < 5000) {
      this.promptController?.setStatusMessage('Minimum loop interval is 5 seconds');
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return true;
    }
    if (intervalMs > 24 * 60 * 60 * 1000) {
      this.promptController?.setStatusMessage('Maximum loop interval is 24 hours');
      setTimeout(() => this.promptController?.setStatusMessage(null), 2000);
      return true;
    }

    const promptText = parts.slice(2).join(' ').trim();
    const isAutoPrompt = !promptText;

    // Stop any existing loop
    this.stopLoop();

    // Start new loop
    this.loopPrompt = promptText;
    this.loopIntervalMs = intervalMs;
    this.loopIteration = 0;
    this.loopTotalIterations = 0;
    this.loopActive = true;

    const intervalLabel = intervalMatch[2]
      ? `${value}${unit === 's' ? 's' : unit === 'm' ? 'm' : 'h'}`
      : `${value}s`;

    const modeLabel = isAutoPrompt ? 'auto' : `"${promptText.slice(0, 40)}${promptText.length > 40 ? '…' : ''}"`;
    this.promptController?.setStatusMessage(
      `Loop started: every ${intervalLabel} — ${modeLabel}`
    );

    // Run first iteration immediately
    this.runLoopIteration();

    // Schedule subsequent iterations
    this.loopTimer = setInterval(() => {
      this.runLoopIteration();
    }, intervalMs);

    return true;
  }

  private async runLoopIteration(): Promise<void> {
    if (!this.loopActive) return;
    this.loopIteration++;
    this.loopTotalIterations++;

    if (this.isProcessing) {
      this.promptController?.setStatusMessage(
        `Loop #${this.loopTotalIterations}: skipped (agent busy)`
      );
      return;
    }

    // Auto-prompt mode: Vigil self-prompts each iteration via DeepSeek.
    // First iteration uses static fallback (AI prompt not ready yet);
    // subsequent iterations use the AI-generated prompt from the cache
    // that was pre-generated during the previous iteration.
    let effectivePrompt: string;
    if (this.loopPrompt) {
      // User-supplied prompt — use it directly
      effectivePrompt = this.loopPrompt;
    } else {
      // Auto-prompt: generate optimal prompt via DeepSeek API
      this.promptController?.setStatusMessage(
        `Loop #${this.loopTotalIterations}: generating prompt…`
      );
      try {
        effectivePrompt = await generateDynamicLoopPrompt({
          iteration: this.loopTotalIterations,
          useAI: true,
        });
      } catch {
        // Fallback to static if async generation fails entirely
        effectivePrompt = generateStaticLoopPrompt(this.loopTotalIterations);
      }
    }

    this.promptController?.setStatusMessage(
      `Loop #${this.loopTotalIterations}: running…`
    );

    // Pre-generate the NEXT iteration's prompt in the background while
    // the current iteration executes. This way the prompt is ready
    // when the next timer fires, avoiding the round-trip latency.
    if (!this.loopPrompt && this.loopActive) {
      void preGenerateNextPrompt(this.loopTotalIterations);
    }

    void this.processPrompt(effectivePrompt).then(() => {
      if (this.loopActive) {
        const totalPhases = getTotalPhaseCount();
        const phaseInfo = `Loop #${this.loopTotalIterations}: done (${this.loopTotalIterations % totalPhases || totalPhases}/${totalPhases} phases) — next in ${this.loopIntervalMs / 1000}s`;
        this.promptController?.setStatusMessage(phaseInfo);
      }
    });
  }

  private stopLoop(): void {
    this.loopActive = false;
    if (this.loopTimer) {
      clearInterval(this.loopTimer);
      this.loopTimer = null;
    }
    this.loopPrompt = '';
    this.loopIntervalMs = 0;
    this.loopIteration = 0;
    this.loopTotalIterations = 0;
    resetLoopState();
  }

  private showLoopStatus(): void {
    if (!this.loopActive) {
      this.promptController?.setStatusMessage('No active loop. Start: /loop <interval> <prompt>');
      setTimeout(() => this.promptController?.setStatusMessage(null), 3000);
      return;
    }

    const intervalLabel = this.loopIntervalMs >= 3600000
      ? `${this.loopIntervalMs / 3600000}h`
      : this.loopIntervalMs >= 60000
        ? `${this.loopIntervalMs / 60000}m`
        : `${this.loopIntervalMs / 1000}s`;

    this.promptController?.setStatusMessage(
      `Loop: "${this.loopPrompt.slice(0, 30)}…" every ${intervalLabel} | ${this.loopTotalIterations} runs`
    );
    setTimeout(() => this.promptController?.setStatusMessage(null), 4000);
  }
}

function parseArgs(argv: string[]): ParsedArgs {
  const promptTokens: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) {
      continue;
    }

    // Skip known flags
    if (token.startsWith('--') || token.startsWith('-')) {
      continue;
    }
    promptTokens.push(token);
  }

  return {
    initialPrompt: promptTokens.length ? promptTokens.join(' ').trim() : null,
  };
}

// Vigil ships one canonical default profile. Historical profile names are
// accepted as aliases so existing env/config does not break.
function resolveProfile(): ProfileName {
  const requested = process.env.VIGIL_PROFILE?.trim();
  if (requested && !process.env['VIGIL_REQUESTED_PROFILE']) {
    process.env['VIGIL_REQUESTED_PROFILE'] = requested;
  }
  const canonical = normalizeProfileName(requested);
  if (hasAgentProfile(canonical)) return canonical;
  return DEFAULT_PROFILE_NAME;
}
