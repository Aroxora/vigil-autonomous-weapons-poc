/**
 * Environment guard — prevents LLM hallucination by enforcing Kali Linux + MCP connectivity.
 *
 * Without a proper Kali environment and connected MCP servers providing ground-truth
 * tool output, the LLM will hallucinate penetration test results — it invents CVE IDs,
 * fabricates exploit scripts, and generates fictional engagement deliverables.
 * This module enforces that operational tools only execute when real tooling is available.
 */

import { existsSync } from 'node:fs';
import { platform, release } from 'node:os';

// ── Required tools for operational readiness ─────────────────────────────
const REQUIRED_TOOLS = [
  'nmap',           // Network reconnaissance
  'msfvenom',       // Payload generation (Forge requires this)
  'msfconsole',     // Metasploit framework
  'sqlmap',         // Database exploitation
  'hydra',          // Credential attacks
  'searchsploit',   // Exploit-DB lookup
  'nikto',          // Web server scanner
  'dirb',           // Directory enumeration
  'john',           // Password cracking
  'hashcat',        // GPU-accelerated cracking
  'responder',      // LLMNR/NBT-NS/mDNS poisoner
  'impacket-secretsdump',  // Credential dumping
  'netcat',         // Network utility
  'curl',           // HTTP client
  'wget',           // Download utility
  'git',            // Version control
  'python3',        // Script runtime
  'gcc',            // C compiler (for payload compilation)
];

const REQUIRED_TOOL_CHECK_COMMANDS: Record<string, string[]> = {
  nmap: ['nmap', '--version'],
  msfvenom: ['msfvenom', '--version'],
  msfconsole: ['msfconsole', '--version'],
  sqlmap: ['sqlmap', '--version'],
  hydra: ['hydra', '-h'],
  searchsploit: ['searchsploit', '--version'],
  nikto: ['nikto', '-Version'],
  dirb: ['dirb', '--help'],
  john: ['john', '--version'],
  hashcat: ['hashcat', '--version'],
  responder: ['responder', '--version'],
  'impacket-secretsdump': ['secretsdump.py', '--version'],
  netcat: ['nc', '-h'],
  curl: ['curl', '--version'],
  wget: ['wget', '--version'],
  git: ['git', '--version'],
  python3: ['python3', '--version'],
  gcc: ['gcc', '--version'],
};

// ── Required MCP servers for operational tooling ──────────────────────────
const REQUIRED_MCP_SERVERS = [
  { name: 'kali-tools',     description: 'Kali Linux tool orchestration' },
  { name: 'ghidra',         description: 'Binary reverse engineering' },
  { name: 'network-defense', description: 'Network defense operations' },
];

// ── Kali detection ────────────────────────────────────────────────────────
function isKaliLinux(): boolean {
  // Check platform
  if (platform() !== 'linux') return false;

  // Check for Kali-specific files
  const kaliIndicators = [
    '/etc/kali-release',
    '/etc/os-release',             // Check contents for Kali
    '/usr/share/kali-defaults',
    '/usr/bin/kali-undercover',
  ];

  const hasKaliFile = kaliIndicators.some(p => existsSync(p));

  // Check os-release contents for Kali
  try {
    const { readFileSync } = require('fs');
    const osRelease = readFileSync('/etc/os-release', 'utf-8');
    if (osRelease.includes('kali') || osRelease.includes('Kali')) return true;
  } catch { /* not kali */ }

  return hasKaliFile;
}

function isLinux(): boolean {
  return platform() === 'linux';
}

// ── Tool availability check ───────────────────────────────────────────────
async function checkTool(tool: string): Promise<{ available: boolean; path?: string; error?: string }> {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execFileAsync = promisify(execFile);

  const commands = REQUIRED_TOOL_CHECK_COMMANDS[tool] || [tool, '--version'];

  for (const cmd of [tool, ...commands]) {
    try {
      const args = cmd === tool ? ['--version'] : commands.slice(1);
      const binary = cmd === tool ? tool : commands[0];
      await execFileAsync(binary, ['--version'], { timeout: 5000 });
      return { available: true, path: binary };
    } catch {
      try {
        // Try which/whereis
        const { stdout } = await execFileAsync('which', [tool], { timeout: 3000 });
        if (stdout.trim()) return { available: true, path: stdout.trim() };
      } catch { /* not found */ }
    }
  }

  return { available: false, error: `${tool} not found in PATH or not executable` };
}

// ── MCP connectivity check ────────────────────────────────────────────────
async function checkMcpServer(serverName: string): Promise<{ connected: boolean; error?: string }> {
  try {
    const { getSharedMcpManager } = await import('../plugins/tools/mcp/mcpClient.js');
    const manager = getSharedMcpManager();
    if (!manager.isInitialized()) {
      return { connected: false, error: 'MCP manager not initialized' };
    }
    const status = manager.getServerStatus?.(serverName);
    const connected = typeof status === 'object' && (status as Record<string, unknown>)?.connected === true;
    return {
      connected,
      error: connected ? undefined : `MCP server '${serverName}' not connected`,
    };
  } catch {
    return { connected: false, error: 'MCP manager not available' };
  }
}

// ── Environment status type ───────────────────────────────────────────────
export interface ToolStatus {
  name: string;
  available: boolean;
  path?: string;
  error?: string;
}

export interface McpServerStatus {
  name: string;
  description: string;
  connected: boolean;
  error?: string;
}

export interface EnvironmentStatus {
  isKali: boolean;
  isLinux: boolean;
  platform: string;
  release: string;
  tools: ToolStatus[];
  mcps: McpServerStatus[];
  isOperational: boolean;
  failingTools: string[];
  failingMcps: string[];
  recommendations: string[];
}

// ── Main check ────────────────────────────────────────────────────────────
export async function checkEnvironment(): Promise<EnvironmentStatus> {
  const kali = isKaliLinux();
  const linux = isLinux();
  const currentPlatform = platform();
  const osRelease = release();

  // Check tools
  const toolResults: ToolStatus[] = [];
  for (const tool of REQUIRED_TOOLS) {
    const result = await checkTool(tool);
    toolResults.push({ name: tool, ...result });
  }

  // Check MCP servers
  const mcpResults: McpServerStatus[] = [];
  for (const server of REQUIRED_MCP_SERVERS) {
    const result = await checkMcpServer(server.name);
    mcpResults.push({ ...server, ...result });
  }

  const failingTools = toolResults.filter(t => !t.available).map(t => t.name);
  const failingMcps = mcpResults.filter(m => !m.connected).map(m => m.name);

  const recommendations: string[] = [];

  if (!kali) {
    if (!linux) {
      recommendations.push(
        `Not running Linux (current: ${currentPlatform}). Kali Linux is required for operational tooling.`,
        'Option 1: Run in Docker: docker run -it kalilinux/kali-rolling',
        'Option 2: Run on Kali Linux VM or bare-metal installation',
        'Running on non-Linux will cause LLM hallucination — all offensive tool output will be fabricated.'
      );
    } else {
      recommendations.push(
        'Running Linux but not Kali. Install Kali tools: sudo apt install kali-linux-headless',
        'Or run in Docker: docker run -it kalilinux/kali-rolling'
      );
    }
  }

  if (failingTools.length > 0) {
    recommendations.push(
      `Missing tools: ${failingTools.join(', ')}`,
      'Install: sudo apt install ' + failingTools.join(' ') + ' (or equivalent package names)',
      `Without these tools, the LLM cannot produce real output — it will hallucinate results.`
    );
  }

  if (failingMcps.length > 0) {
    recommendations.push(
      `MCP servers not connected: ${failingMcps.join(', ')}`,
      'Start MCP servers: npm run kali:mcp, npm run ghidra:mcp, npm run netdef:mcp',
      'Without MCP connectivity, the LLM has no access to real tool orchestration.'
    );
  }

  const toolsOperational = failingTools.length === 0;
  const mcpsOperational = failingMcps.length === 0;

  return {
    isKali: kali,
    isLinux: linux,
    platform: currentPlatform,
    release: osRelease,
    tools: toolResults,
    mcps: mcpResults,
    isOperational: kali && toolsOperational,
    failingTools,
    failingMcps,
    recommendations,
  };
}

/**
 * Quick sync check — does the environment meet minimum requirements?
 * Non-blocking; used for startup messages and /env command.
 */
export function quickEnvCheck(): { isKali: boolean; isLinux: boolean } {
  return {
    isKali: isKaliLinux(),
    isLinux: isLinux(),
  };
}

/**
 * Operational gate — call before executing any CNE/CNA tool.
 * Returns true if the environment can produce real (non-hallucinated) output.
 */
export function isOperational(env: EnvironmentStatus): boolean {
  return env.isKali && env.failingTools.length === 0;
}

/**
 * Format environment status as human-readable text (for /env command).
 */
export function formatEnvStatus(env: EnvironmentStatus): string {
  const lines: string[] = [];

  lines.push(`Platform: ${env.platform} (${env.release})`);
  lines.push(`Kali Linux: ${env.isKali ? 'YES' : 'NO ⚠️'}`);
  lines.push('');

  lines.push('Tools:');
  for (const tool of env.tools) {
    const status = tool.available ? '✓' : '✗ MISSING';
    lines.push(`  ${status}  ${tool.name}${tool.path ? ` (${tool.path})` : ''}`);
  }

  lines.push('');
  lines.push('MCP Servers:');
  for (const mcp of env.mcps) {
    const status = mcp.connected ? '✓' : '✗ NOT CONNECTED';
    lines.push(`  ${status}  ${mcp.name} — ${mcp.description}`);
  }

  if (env.recommendations.length > 0) {
    lines.push('');
    lines.push('Recommendations:');
    for (const rec of env.recommendations) {
      lines.push(`  • ${rec}`);
    }
  }

  lines.push('');
  if (env.isOperational) {
    lines.push('Status: OPERATIONAL — tooling can produce real output');
  } else {
    lines.push('Status: NOT OPERATIONAL — LLM WILL HALLUCINATE TOOL OUTPUT');
    lines.push('Without Kali Linux and installed tools, all offensive tool results are fabricated.');
  }

  return lines.join('\n');
}
