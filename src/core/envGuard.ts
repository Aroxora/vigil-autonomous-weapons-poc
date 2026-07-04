/**
 * Environment guard — prevents LLM hallucination by enforcing real tooling.
 *
 * Without actual tools providing ground-truth output, the LLM invents
 * CVE IDs, fabricates exploit scripts, and generates fictional engagement
 * deliverables. On Kali Linux: auto-install missing tools. On other
 * platforms: route through MCP servers connected to a Kali host.
 */

import { existsSync } from 'node:fs';
import { platform, release } from 'node:os';

// ── Tool tiers ────────────────────────────────────────────────────────────
const TOOL_TIERS = {
  // Core tools — should be available everywhere
  core: ['curl', 'wget', 'git', 'python3', 'gcc'] as const,
  // Operational tools — Kali-specific, require apt install
  operational: [
    'nmap',
    'msfvenom',
    'msfconsole',
    'sqlmap',
    'hydra',
    'searchsploit',
    'nikto',
    'dirb',
    'netcat',
  ] as const,
  // Extended tools — nice to have, not gating
  extended: [
    'john',
    'hashcat',
    'responder',
    'impacket-secretsdump',
  ] as const,
};

type ToolName = string;
const ALL_TOOLS = [
  ...TOOL_TIERS.core,
  ...TOOL_TIERS.operational,
  ...TOOL_TIERS.extended,
];

// ── Apt package mappings (tool name → apt package) ────────────────────────
const APT_PACKAGES: Record<string, string> = {
  nmap: 'nmap',
  msfvenom: 'metasploit-framework',
  msfconsole: 'metasploit-framework',
  sqlmap: 'sqlmap',
  hydra: 'hydra',
  searchsploit: 'exploitdb',
  nikto: 'nikto',
  dirb: 'dirb',
  john: 'john',
  hashcat: 'hashcat',
  responder: 'responder',
  'impacket-secretsdump': 'impacket-scripts',
  netcat: 'netcat-openbsd',
  curl: 'curl',
  wget: 'wget',
  git: 'git',
  python3: 'python3',
  gcc: 'gcc',
};

const TOOL_CHECK_COMMANDS: Record<string, string[]> = {
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

const REQUIRED_MCP_SERVERS = [
  { name: 'kali-tools', description: 'Kali Linux tool orchestration' },
  { name: 'ghidra', description: 'Binary reverse engineering' },
  { name: 'network-defense', description: 'Network defense operations' },
];

// ── Kali detection ────────────────────────────────────────────────────────
function isKaliLinux(): boolean {
  if (platform() !== 'linux') return false;

  const kaliIndicators = [
    '/etc/kali-release',
    '/usr/share/kali-defaults',
    '/usr/bin/kali-undercover',
  ];

  if (kaliIndicators.some(p => existsSync(p))) return true;

  try {
    const { readFileSync } = require('fs');
    const osRelease = readFileSync('/etc/os-release', 'utf-8');
    if (osRelease.includes('kali') || osRelease.includes('Kali')) return true;
  } catch { /* not kali */ }

  return false;
}

function isLinux(): boolean {
  return platform() === 'linux';
}

// ── Tool availability check ───────────────────────────────────────────────
async function checkTool(tool: string): Promise<{ available: boolean; path?: string }> {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execFileAsync = promisify(execFile);

  const commands = TOOL_CHECK_COMMANDS[tool];
  if (!commands) return { available: false };

  const binary = commands[0];
  const args = commands.slice(1);

  try {
    await execFileAsync(binary, args, { timeout: 5000 });
    return { available: true, path: binary };
  } catch {
    try {
      const { stdout } = await execFileAsync('which', [tool], { timeout: 3000 });
      if (stdout.trim()) return { available: true, path: stdout.trim() };
    } catch { /* not found */ }
  }

  return { available: false };
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
    return { connected, error: connected ? undefined : `MCP server '${serverName}' not connected` };
  } catch {
    return { connected: false, error: 'MCP manager not available' };
  }
}

// ── Types ─────────────────────────────────────────────────────────────────
export interface ToolStatus {
  name: string;
  available: boolean;
  path?: string;
  tier: 'core' | 'operational' | 'extended';
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
  missingOperationalTools: string[];
  missingMcps: string[];
  recommendations: string[];
}

// ── Auto-install missing tools on Kali ────────────────────────────────────
export async function installMissingTools(
  missingTools: string[],
  onProgress?: (msg: string) => void,
): Promise<{ installed: string[]; failed: string[] }> {
  if (!isKaliLinux()) {
    throw new Error('Auto-install only available on Kali Linux. Run on Kali or use Docker.');
  }

  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execFileAsync = promisify(execFile);

  // Deduplicate apt packages
  const packages = [...new Set(missingTools.map(t => APT_PACKAGES[t] || t))];

  onProgress?.(`Installing ${packages.length} package(s): ${packages.join(', ')}`);

  const installed: string[] = [];
  const failed: string[] = [];

  for (const pkg of packages) {
    try {
      onProgress?.(`  sudo apt install -y ${pkg} ...`);
      const { stderr } = await execFileAsync('sudo', ['apt', 'install', '-y', pkg], {
        timeout: 300_000, // 5 min for large packages like metasploit
        env: { ...process.env, DEBIAN_FRONTEND: 'noninteractive' },
      });
      // apt outputs progress to stderr, not stdout
      if (stderr.includes('E:') || stderr.includes('Unable to locate')) {
        failed.push(pkg);
        onProgress?.(`  ✗ ${pkg} — package not found or install failed`);
      } else {
        installed.push(pkg);
        onProgress?.(`  ✓ ${pkg}`);
      }
    } catch (err) {
      failed.push(pkg);
      onProgress?.(`  ✗ ${pkg} — ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return { installed, failed };
}

// ── Main environment check ────────────────────────────────────────────────
export async function checkEnvironment(installIfMissing = false): Promise<EnvironmentStatus> {
  const kali = isKaliLinux();
  const linux = isLinux();
  const currentPlatform = platform();
  const osRelease = release();

  // Check all tools
  const toolResults: ToolStatus[] = [];
  for (const tool of ALL_TOOLS) {
    const result = await checkTool(tool);
    const tier = (TOOL_TIERS.core as readonly string[]).includes(tool) ? 'core' as const
      : (TOOL_TIERS.operational as readonly string[]).includes(tool) ? 'operational' as const
      : 'extended' as const;
    toolResults.push({ name: tool, ...result, tier });
  }

  // Check MCP servers
  const mcpResults: McpServerStatus[] = [];
  for (const server of REQUIRED_MCP_SERVERS) {
    const result = await checkMcpServer(server.name);
    mcpResults.push({ ...server, ...result });
  }

  const missingOperational = toolResults
    .filter(t => !t.available && t.tier === 'operational')
    .map(t => t.name);

  const missingCore = toolResults
    .filter(t => !t.available && t.tier === 'core')
    .map(t => t.name);

  const missingMcps = mcpResults.filter(m => !m.connected).map(m => m.name);

  // MCP can bridge operational tools even on non-Kali
  const mcpBridgeAvailable = mcpResults.some(m => m.connected);

  // Operational if: (Kali + all operational tools) OR (MCP bridge available)
  const toolsOperational = missingOperational.length === 0;
  const isOperational = (kali && toolsOperational) || mcpBridgeAvailable;

  const recommendations: string[] = [];

  if (!kali && !linux) {
    recommendations.push(
      `Not running Linux (current: ${currentPlatform}). Operational tools require Kali Linux.`,
      'The agent can still code, analyze, and plan — but cannot execute offensive tools locally.',
      'For tool execution: route through MCP servers connected to a Kali host, or:',
      '  docker run -it -v $(pwd):/workspace kalilinux/kali-rolling',
    );
  } else if (linux && !kali) {
    recommendations.push(
      'Running Linux but not Kali. Core coding/analysis works normally.',
      'Operational tools (nmap, msfvenom, etc.) not available locally.',
      'For tool execution: connect MCP servers to a Kali host or container.',
    );
  }

  if (kali && missingOperational.length > 0) {
    const aptPackages = [...new Set(missingOperational.map(t => APT_PACKAGES[t] || t))];
    recommendations.push(
      `Missing operational tools on Kali: ${missingOperational.join(', ')}`,
      `Run /env --install to auto-install: sudo apt install -y ${aptPackages.join(' ')}`,
    );
    if (installIfMissing) {
      recommendations.push('Auto-installing missing tools...');
    }
  }

  if (missingCore.length > 0) {
    recommendations.push(
      `Missing core tools: ${missingCore.join(', ')}`,
      'Install: sudo apt install ' + missingCore.join(' '),
    );
  }

  if (missingMcps.length > 0) {
    recommendations.push(
      `MCP servers not connected: ${missingMcps.join(', ')}`,
      'Start: npm run kali:mcp  (and npm run ghidra:mcp, npm run netdef:mcp)',
      'MCP servers bridge the LLM to real tools — without them, tool output hallucinates.',
    );
  }

  return {
    isKali: kali,
    isLinux: linux,
    platform: currentPlatform,
    release: osRelease,
    tools: toolResults,
    mcps: mcpResults,
    isOperational,
    missingOperationalTools: missingOperational,
    missingMcps,
    recommendations,
  };
}

// ── Quick sync check ──────────────────────────────────────────────────────
export function quickEnvCheck(): { isKali: boolean; isLinux: boolean } {
  return {
    isKali: isKaliLinux(),
    isLinux: isLinux(),
  };
}

export function isOperational(env: EnvironmentStatus): boolean {
  return env.isOperational;
}

// ── Format status as text ─────────────────────────────────────────────────
export function formatEnvStatus(env: EnvironmentStatus): string {
  const lines: string[] = [];

  lines.push(`Platform: ${env.platform} (${env.release})`);
  lines.push(`Kali Linux: ${env.isKali ? 'YES' : 'NO'}`);

  if (!env.isOperational && env.mcps.some(m => m.connected)) {
    lines.push(`MCP Bridge: ACTIVE — tools routed through connected MCP servers`);
  }

  lines.push('');

  // Core tools
  lines.push('Core:');
  for (const tool of env.tools.filter(t => t.tier === 'core')) {
    lines.push(`  ${tool.available ? '✓' : '✗'}  ${tool.name}${tool.path ? ` (${tool.path})` : ''}`);
  }

  lines.push('');
  lines.push('Operational (Kali):');
  for (const tool of env.tools.filter(t => t.tier === 'operational')) {
    lines.push(`  ${tool.available ? '✓' : '✗'}  ${tool.name}${tool.path ? ` (${tool.path})` : ''}`);
  }

  const extendedTools = env.tools.filter(t => t.tier === 'extended');
  if (extendedTools.length > 0) {
    lines.push('');
    lines.push('Extended:');
    for (const tool of extendedTools) {
      lines.push(`  ${tool.available ? '✓' : '✗'}  ${tool.name}${tool.path ? ` (${tool.path})` : ''}`);
    }
  }

  lines.push('');
  lines.push('MCP Servers:');
  for (const mcp of env.mcps) {
    const status = mcp.connected ? '✓ CONNECTED' : '✗ OFFLINE';
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
    lines.push('Status: OPERATIONAL');
    if (!env.isKali && env.mcps.some(m => m.connected)) {
      lines.push('Tools routed through MCP bridge — LLM output is ground-truthed against real tooling.');
    }
  } else {
    let reason = '';
    if (!env.isKali && !env.mcps.some(m => m.connected)) {
      reason = 'Not on Kali and no MCP bridge — operational tools unavailable.';
    } else if (env.isKali && env.missingOperationalTools.length > 0) {
      reason = `Missing ${env.missingOperationalTools.length} operational tools — run /env --install.`;
    }
    lines.push(`Status: LIMITED — ${reason}`);
    lines.push('Coding, analysis, and planning work normally.');
  }

  return lines.join('\n');
}
