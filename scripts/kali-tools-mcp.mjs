#!/usr/bin/env node
// MCP stdio server — Comprehensive Kali Linux tool orchestration.
// Exposes ~70 offensive/defensive Kali tools as read-only probes and
// parameterized scans through the Vigil MCP bridge. Every tool is
// wrapped with a hard timeout + SIGKILL guard.
//
// Authorization: VIGIL_SESSION_TOKEN must be set by the Vigil CLI.

if (!process.env.VIGIL_SESSION_TOKEN) {
  process.stderr.write('[vigil-kali-mcp] Error: VIGIL_SESSION_TOKEN is not set.\n' +
    'This server must be started by the Vigil CLI, not directly.\n');
  process.exit(1);
}

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { execSync, spawnSync } from 'node:child_process';
import { platform } from 'node:os';
import {
  assertAuthorizedTarget,
  denyIfUnsafeKaliInvocation,
  extractTargetFromArgs,
} from './lib/cne-scope.mjs';

// ──────────────────────────────
// Tool registry — all known Kali tools by category
// ──────────────────────────────
const KALI_TOOLS = {
  'information-gathering': {
    tools: ['nmap', 'masscan', 'rustscan', 'dnsrecon', 'dnsenum', 'dnsmap',
      'fierce', 'theharvester', 'recon-ng', 'maltego', 'spiderfoot',
      'amass', 'subfinder', 'assetfinder', 'sublist3r', 'gobuster',
      'dirb', 'ffuf', 'wfuzz', 'whatweb', 'wafw00f'],
    desc: 'Network scanning, DNS enumeration, OSINT, web fingerprinting',
  },
  'vulnerability-analysis': {
    tools: ['nikto', 'wpscan', 'joomscan', 'sqlmap', 'commix', 'xsser',
      'unix-privesc-check', 'lynis', 'nmap-vulners', 'searchsploit',
      'legion', 'openvas', 'gvm-cli'],
    desc: 'Vulnerability scanners, web app testing, privesc auditing',
  },
  'web-application': {
    tools: ['burpsuite', 'zaproxy', 'sqlmap', 'dirb', 'gobuster', 'wfuzz',
      'ffuf', 'commix', 'xsser', 'skipfish', 'arachni', 'w3af-console'],
    desc: 'Web proxy, fuzzing, injection testing, crawling',
  },
  'password-attacks': {
    tools: ['hydra', 'john', 'hashcat', 'medusa', 'ncrack', 'crunch',
      'cewl', 'hash-identifier', 'rainbowcrack', 'ophcrack',
      'fcrackzip', 'pdfcrack', 'rsmangler'],
    desc: 'Password cracking, wordlist generation, brute-force',
  },
  'wireless': {
    tools: ['aircrack-ng', 'reaver', 'pixiewps', 'kismet', 'wifite',
      'hcxdumptool', 'hcxtools', 'bully', 'fern-wifi-cracker'],
    desc: 'WiFi scanning, WPA/WPS attacks, packet capture',
  },
  'exploitation': {
    tools: ['metasploit-framework', 'searchsploit', 'beef-xss', 'set',
      'msfvenom', 'msfconsole'],
    desc: 'Exploit frameworks, payload generation, social engineering',
  },
  'sniffing-spoofing': {
    tools: ['wireshark', 'tcpdump', 'ettercap', 'bettercap', 'dsniff',
      'responder', 'mitmproxy', 'netsniff-ng', 'arpspoof', 'sslstrip'],
    desc: 'Packet capture, MITM, ARP spoofing, SSL interception',
  },
  'post-exploitation': {
    tools: ['powershell-empire', 'starkiller', 'covenant', 'sliver',
      'bloodhound', 'mimikatz', 'powersploit', 'evil-winrm',
      'impacket-scripts', 'crackmapexec', 'enum4linux', 'smbmap'],
    desc: 'C2 frameworks, AD enumeration, lateral movement',
  },
  'forensics': {
    tools: ['autopsy', 'sleuthkit', 'volatility', 'volatility3',
      'bulk-extractor', 'guymager', 'foremost', 'binwalk',
      'exiftool', 'steghide', 'forensics-all'],
    desc: 'Disk forensics, memory analysis, file carving, steganography',
  },
  'reverse-engineering': {
    tools: ['radare2', 'rizin', 'gdb', 'jadx', 'apktool', 'objdump', 'strings', 'ltrace', 'strace'],
    desc: 'Disassemblers, debuggers, decompilers, binary analysis (headless/CLI only)',
  },
  'reporting': {
    tools: ['faraday', 'crackmapexec', 'eyewitness', 'maltego',
      'recon-ng', 'theharvester', 'dradis', 'magictree'],
    desc: 'Pentest reporting, visualization, evidence collection',
  },
  'defensive-blue': {
    tools: ['lynis', 'chkrootkit', 'rkhunter', 'clamav', 'tiger',
      'aide', 'osquery', 'wazuh-agent', 'falco', 'openscap',
      'debsecan', 'apt-listbugs', 'unattended-upgrades'],
    desc: 'Host-based detection, rootkit scanning, HIDS, hardening',
  },
};

const TIMEOUT_MS = 45_000;
const IS_WIN = platform() === 'win32';

// ──────────────────────────────
// Helpers
// ──────────────────────────────
function haveExe(name) {
  try {
    const cmd = IS_WIN ? 'where' : 'which';
    const r = spawnSync(cmd, [name], { encoding: 'utf8', timeout: 4000, killSignal: 'SIGKILL' });
    return !!((r.stdout ?? '').split(/\r?\n/).filter(Boolean)[0]);
  } catch { return false; }
}

function safeRun(cmd, timeoutMs = TIMEOUT_MS) {
  try {
    const finalCmd = IS_WIN
      ? cmd.replaceAll('2>/dev/null', '2>$null')
      : `timeout ${Math.floor(timeoutMs / 1000)} ${cmd}`;
    return execSync(finalCmd, {
      encoding: 'utf8', timeout: timeoutMs + 5000,
      stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 16 * 1024 * 1024,
      killSignal: 'SIGKILL',
    }).trim();
  } catch { return ''; }
}

function safeSpawn(bin, args = [], timeoutMs = TIMEOUT_MS) {
  try {
    const finalArgs = IS_WIN
      ? args.map(a => String(a))
      : args.map(a => String(a));
    return spawnSync(bin, finalArgs, {
      encoding: 'utf8',
      timeout: timeoutMs + 5000,
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 16 * 1024 * 1024,
      killSignal: 'SIGKILL',
    }).stdout?.trim() || '';
  } catch { return ''; }
}

function safeSpawnLines(bin, args = [], head = Infinity, timeoutMs = TIMEOUT_MS) {
  const out = safeSpawn(bin, args, timeoutMs);
  if (!out || head >= Infinity) return out;
  return out.split('\n').slice(0, head).join('\n');
}

function safeSpawnWithInput(bin, args = [], input = '', timeoutMs = TIMEOUT_MS) {
  try {
    return spawnSync(bin, args.map(a => String(a)), {
      encoding: 'utf8',
      timeout: timeoutMs + 5000,
      input,
      stdio: ['pipe', 'pipe', 'ignore'],
      maxBuffer: 16 * 1024 * 1024,
      killSignal: 'SIGKILL',
    }).stdout?.trim() || '';
  } catch { return ''; }
}

function parseFlags(flagStr) {
  return flagStr.split(/\s+/).filter(Boolean);
}

function safeRunJson(cmd, timeoutMs = TIMEOUT_MS) {
  const raw = safeRun(cmd, timeoutMs);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch { return raw; }
}

function jsonResult(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function shellQuote(value) {
  return `'${String(value || '').replace(/'/g, `'\\''`)}'`;
}

async function guarded(fn) {
  try {
    return jsonResult(await fn());
  } catch (e) {
    return { isError: true, content: [{ type: 'text', text: String(e?.message || e) }] };
  }
}

// ──────────────────────────────
// Tool discovery / version
// ──────────────────────────────
function getToolVersion(name) {
  return safeRun(`${name} --version 2>/dev/null | head -1`, 8000) ||
    safeRun(`${name} version 2>/dev/null | head -1`, 8000) ||
    safeRun(`${name} -v 2>/dev/null | head -1`, 8000) ||
    'unknown';
}

// ──────────────────────────────
// MCP Server
// ──────────────────────────────
const server = new McpServer({
  name: 'vigil-kali-tools',
  version: '1.0.0',
});

// ── Probe all tools ──
server.registerTool(
  'kali_probe',
  {
    title: 'Probe Kali Tools',
    description: 'Discover all installed Kali Linux tools by category. Returns which tools are present on PATH and their versions. Read-only — no tools are executed beyond --version probes.',
    inputSchema: {
      category: z.string().optional().describe('Filter to a specific category. Omit to probe all.'),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    const targetCategories = args.category
      ? { [args.category]: KALI_TOOLS[args.category] }
      : KALI_TOOLS;

    if (args.category && !targetCategories[args.category]) {
      return jsonResult({ error: `Unknown category: ${args.category}`, available: Object.keys(KALI_TOOLS) });
    }

    const result = { isKali: !!safeRun('grep -qi kali /etc/os-release 2>/dev/null && echo yes || true', 5000), platform: platform(), categories: {} };
    let totalInstalled = 0;
    let totalKnown = 0;

    for (const [cat, def] of Object.entries(targetCategories)) {
      const installed = [];
      for (const tool of def.tools) {
        totalKnown++;
        if (haveExe(tool)) {
          totalInstalled++;
          installed.push({
            name: tool,
            version: getToolVersion(tool),
            path: safeRun(`which ${tool} 2>/dev/null`, 4000) || '',
            dpkg: safeRun(`dpkg -l ${tool} 2>/dev/null | grep '^ii' | awk '{print $3}'`, 5000) || null,
          });
        }
      }
      result.categories[cat] = {
        description: def.desc,
        total: def.tools.length,
        installed: installed.length,
        tools: installed,
      };
    }

    result.summary = { totalKnown, totalInstalled, coveragePercent: totalKnown > 0 ? Math.round((totalInstalled / totalKnown) * 100) : 0 };
    return jsonResult(result);
  },
);

// ── Generic tool runner ──
server.registerTool(
  'kali_run',
  {
    title: 'Run Kali Tool',
    description: 'Run any Kali Linux security tool in read-only mode with a hard timeout. The tool name and arguments are validated — only known tools from the registry are permitted. Output is captured and returned.',
    inputSchema: {
      tool: z.string().describe('Name of the Kali tool to run.'),
      args: z.string().optional().describe('Additional command-line arguments (space-separated).'),
      timeoutMs: z.number().int().positive().max(120_000).optional().describe('Override timeout in ms (max 120s).'),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    const allTools = Object.values(KALI_TOOLS).flatMap(c => c.tools);
    if (!allTools.includes(args.tool)) {
      return jsonResult({ error: `Unknown tool: ${args.tool}`, hint: 'Use kali_probe to discover installed tools' });
    }
    try {
      denyIfUnsafeKaliInvocation(args.tool, args.args || '');
      const extractedTarget = extractTargetFromArgs(args.args || '');
      if (extractedTarget) assertAuthorizedTarget(extractedTarget, 'active-scan');
    } catch (error) {
      return jsonResult({ error: String(error?.message || error), policy: 'CNE three-chain policy' });
    }
    if (!haveExe(args.tool)) {
      return jsonResult({ error: `Tool not installed: ${args.tool}`, installed: false });
    }

    const timeoutMs = args.timeoutMs || TIMEOUT_MS;
    const extraArgs = (args.args || '').trim();
    const spawnArgs = extraArgs ? parseFlags(extraArgs) : [];
    const output = safeSpawn(args.tool, spawnArgs, timeoutMs);

    return jsonResult({
      tool: args.tool,
      args: extraArgs,
      exitCode: output ? 0 : 1,
      output: output.slice(0, 50000),
      truncated: output.length > 50000,
    });
  },
);

// ── Network scanning wrappers ──
server.registerTool(
  'kali_nmap_scan',
  {
    title: 'Nmap Scan',
    description: 'Run a parameterized nmap scan. Supports service detection, OS fingerprinting, and CVE scripts. All scans use -sV -sC by default. Target must be a single host or CIDR.',
    inputSchema: {
      target: z.string().describe('Target host, IP, or CIDR range.'),
      ports: z.string().optional().describe('Port specification (e.g. 1-1000, 80,443,8080). Defaults to top 1000.'),
      scanType: z.enum(['basic', 'service', 'os', 'vuln', 'full']).optional().default('basic'),
      timeoutMs: z.number().int().positive().max(300_000).optional().default(60_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    if (!haveExe('nmap')) return jsonResult({ error: 'nmap not installed' });
    try {
      assertAuthorizedTarget(args.target, 'active-scan');
    } catch (error) {
      return jsonResult({ error: String(error?.message || error), policy: 'CNE target-bound authorization' });
    }
    const scanFlags = { basic: '-sV --top-ports 1000', service: '-sV -sC --top-ports 1000', os: '-sV -O --top-ports 2000', vuln: '-sV -sC --script vuln', full: '-sV -sC -O -p- --script vuln' };
    if (args.ports && !/^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$/.test(args.ports)) {
      return jsonResult({ error: `Invalid port expression: ${args.ports}`, policy: 'argument validation' });
    }
    const spawnArgs = [...parseFlags(scanFlags[args.scanType])];
    if (args.ports) { spawnArgs.push('-p', args.ports); }
    spawnArgs.push(args.target);
    const output = safeSpawn('nmap', spawnArgs, args.timeoutMs);
    return jsonResult({ target: args.target, scanType: args.scanType, command: `nmap ${scanFlags[args.scanType]} ${args.ports ? `-p ${args.ports}` : ''} ${args.target}`, output: output.slice(0, 100000) });
  },
);

// ── Vulnerability scan wrappers ──
server.registerTool(
  'kali_vuln_scan',
  {
    title: 'Vulnerability Scan',
    description: 'Run targeted vulnerability scans using Nikto, WPScan, or SearchSploit. Falls back gracefully if tools are not installed.',
    inputSchema: {
      scanner: z.enum(['nikto', 'wpscan', 'searchsploit', 'lynis', 'lynis-system', 'unix-privesc']),
      target: z.string().optional().describe('Target URL, IP, or path. Required for nikto/wpscan/searchsploit.'),
      timeoutMs: z.number().int().positive().max(300_000).optional().default(60_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    if (args.target && args.scanner !== 'searchsploit') {
      try {
        assertAuthorizedTarget(args.target, 'active-scan');
      } catch (error) {
        return jsonResult({ error: String(error?.message || error), policy: 'CNE target-bound authorization' });
      }
    }
    let output = '';
    const target = args.target || '';
    switch (args.scanner) {
      case 'nikto':
        output = safeSpawn('nikto', ['-h', target, '-Tuning', '1234567890'], args.timeoutMs);
        break;
      case 'wpscan':
        output = safeSpawn('wpscan', ['--url', target, '--no-banner', '--format', 'cli-no-color'], args.timeoutMs);
        break;
      case 'searchsploit':
        if (!haveExe('searchsploit')) return jsonResult({ error: 'searchsploit not installed' });
        output = safeSpawn('searchsploit', [target], args.timeoutMs);
        break;
      case 'lynis':
      case 'lynis-system':
        output = safeRun('lynis audit system --quick --no-colors', args.timeoutMs);
        break;
      case 'unix-privesc':
        output = safeRun('unix-privesc-check 2>&1', args.timeoutMs);
        break;
      default:
        return jsonResult({ error: `Unknown scanner: ${args.scanner}` });
    }
    return jsonResult({ scanner: args.scanner, target: args.target || 'localhost', output: output.slice(0, 100000) });
  },
);

// ── Blue team / defensive tools ──
server.registerTool(
  'kali_defensive_audit',
  {
    title: 'Defensive Audit',
    description: 'Run defensive security audits: rootkit detection, malware scanning, file integrity checking, and system hardening assessment. All operations are read-only.',
    inputSchema: {
      audit: z.enum(['rootkit-check', 'malware-scan', 'file-integrity', 'system-hardening', 'network-services', 'all']),
      path: z.string().optional().describe('Path to scan for malware/integrity checks. Defaults to system-critical paths.'),
      timeoutMs: z.number().int().positive().max(300_000).optional().default(90_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    const results = {};
    const which = (name) => haveExe(name);

    if (args.audit === 'rootkit-check' || args.audit === 'all') {
      if (which('rkhunter')) results.rootkit_rkhunter = safeRun('rkhunter --check --skip-keypress --report-warnings-only 2>&1 || true', args.timeoutMs).slice(0, 30000);
      if (which('chkrootkit')) results.rootkit_chkrootkit = safeRun('chkrootkit -q 2>&1 || true', args.timeoutMs).slice(0, 30000);
    }

    if (args.audit === 'malware-scan' || args.audit === 'all') {
      if (which('clamscan')) {
        if (args.path) {
          try { denyIfUnsafeKaliInvocation('clamscan', args.path); } catch (error) {
            return jsonResult({ error: String(error?.message || error), policy: 'CNE argument validation' });
          }
        }
        const scanPaths = args.path ? parseFlags(args.path) : ['/home', '/tmp', '/var/tmp'];
        results.malware_clamav = safeSpawn('clamscan', ['--no-summary', '-r', ...scanPaths], args.timeoutMs).slice(0, 30000);
      }
      if (which('tiger')) results.malware_tiger = safeRun('tiger -q 2>&1 || true', args.timeoutMs).slice(0, 30000);
    }

    if (args.audit === 'file-integrity' || args.audit === 'all') {
      if (which('aide')) results.integrity_aide = safeRun('aide --check 2>&1 || true', args.timeoutMs).slice(0, 30000);
      results.integrity_binaries = safeRun('which bash systemd sshd apache2 nginx 2>/dev/null | xargs -I{} sh -c "echo {}: $(sha256sum {} | cut -d\' \' -f1)" 2>/dev/null || true', 15000);
    }

    if (args.audit === 'system-hardening' || args.audit === 'all') {
      if (which('lynis')) results.hardening_lynis = safeRun('lynis audit system --quick --no-colors 2>&1 | tail -80', args.timeoutMs);
      results.hardening_kernel = safeRun('cat /proc/sys/kernel/randomize_va_space /proc/sys/kernel/kptr_restrict /proc/sys/kernel/dmesg_restrict 2>/dev/null', 5000);
      results.hardening_perms = safeRun('find /usr/bin /usr/sbin /bin /sbin -type f -perm /o+w 2>/dev/null | head -30', 20000);
    }

    if (args.audit === 'network-services' || args.audit === 'all') {
      results.network_listening = safeRun('ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null', 10000);
      results.network_firewall = safeRun('iptables -L -n 2>/dev/null || true', 5000);
      results.network_ufw = safeRun('ufw status verbose 2>/dev/null || true', 5000);
    }

    return jsonResult(results);
  },
);

// ── Forensic tools ──
server.registerTool(
  'kali_forensics',
  {
    title: 'Forensics Probe',
    description: 'Run read-only forensic analysis: extract metadata, carve files, scan memory, or analyze disk images. No writes to evidence.',
    inputSchema: {
      operation: z.enum(['exiftool', 'binwalk', 'foremost', 'volatility-info', 'strings', 'hash']),
      target: z.string().describe('Path to the file, image, or memory dump to analyze.'),
      timeoutMs: z.number().int().positive().max(300_000).optional().default(60_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    try {
      denyIfUnsafeKaliInvocation('exiftool', args.target);
      denyIfUnsafeKaliInvocation('binwalk', args.target);
    } catch (error) {
      return jsonResult({ error: String(error?.message || error), policy: 'CNE argument validation' });
    }
    let output = '';
    switch (args.operation) {
      case 'exiftool':
        output = safeSpawn('exiftool', [args.target], args.timeoutMs);
        break;
      case 'binwalk':
        output = safeSpawn('binwalk', ['-Me', args.target], args.timeoutMs);
        if (!output) output = safeSpawn('binwalk', [args.target], args.timeoutMs);
        break;
      case 'foremost':
        output = safeSpawn('foremost', ['-i', args.target, '-o', `/tmp/vigil-foremost-${process.pid}`], args.timeoutMs);
        break;
      case 'volatility-info': {
        output = safeSpawn('volatility3', ['-f', args.target, 'windows.info'], args.timeoutMs);
        if (!output) output = safeSpawn('volatility', ['-f', args.target, 'imageinfo'], args.timeoutMs);
        break;
      }
      case 'strings':
        output = safeSpawnLines('strings', [args.target], 500, args.timeoutMs);
        break;
      case 'hash': {
        const sha = safeSpawn('sha256sum', [args.target], args.timeoutMs);
        const md5 = safeSpawn('md5sum', [args.target], args.timeoutMs);
        output = [sha, md5].filter(Boolean).join('\n');
        break;
      }
      default:
        return jsonResult({ error: `Unknown operation: ${args.operation}` });
    }
    return jsonResult({ operation: args.operation, target: args.target, output: output.slice(0, 80000) });
  },
);

// ── Reverse engineering wrappers ──
server.registerTool(
  'kali_reverse',
  {
    title: 'Reverse Engineering',
    description: 'Run read-only reverse engineering analysis using radare2, strings, objdump, or ltrace. Ghidra is handled separately via vigil-ghidra MCP.',
    inputSchema: {
      tool: z.enum(['radare2-info', 'radare2-functions', 'objdump-headers', 'objdump-symbols', 'strings', 'checksec', 'ldd']),
      target: z.string().describe('Path to the binary to analyze.'),
      timeoutMs: z.number().int().positive().max(120_000).optional().default(30_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    try {
      denyIfUnsafeKaliInvocation('radare2', args.target);
    } catch (error) {
      return jsonResult({ error: String(error?.message || error), policy: 'CNE argument validation' });
    }
    let output = '';
    switch (args.tool) {
      case 'radare2-info': {
        const info = safeSpawn('r2', ['-q', '-c', 'iI~arch;iI~os;iI~bintype;iI~bits;iI~canary;iI~pic;iI~nx;iI~relro', args.target], args.timeoutMs);
        output = info;
        break;
      }
      case 'radare2-functions': {
        const funcs = safeSpawn('r2', ['-q', '-c', 'afl~[0]', args.target], args.timeoutMs);
        output = funcs ? funcs.split('\n').slice(0, 200).join('\n') : '';
        break;
      }
      case 'objdump-headers':
        output = safeSpawn('objdump', ['-f', '-h', args.target], args.timeoutMs);
        break;
      case 'objdump-symbols':
        output = safeSpawnLines('objdump', ['-t', args.target], 300, args.timeoutMs);
        break;
      case 'strings':
        output = safeSpawnLines('strings', [args.target], 500, args.timeoutMs);
        break;
      case 'checksec': {
        output = safeSpawn('checksec', ['--file=' + args.target], args.timeoutMs);
        if (!output) output = safeSpawn('pwn', ['checksec', args.target], args.timeoutMs);
        break;
      }
      case 'ldd':
        output = safeSpawn('ldd', [args.target], args.timeoutMs);
        break;
      default:
        return jsonResult({ error: `Unknown tool: ${args.tool}` });
    }
    return jsonResult({ tool: args.tool, target: args.target, output: output.slice(0, 50000) });
  },
);

// ── Password / hash analysis ──
server.registerTool(
  'kali_hash',
  {
    title: 'Hash Analysis',
    description: 'Identify hash types, check common passwords, and analyze cryptographic material. Read-only — no cracking or brute-force.',
    inputSchema: {
      operation: z.enum(['identify-hash', 'check-common', 'check-password', 'generate-wordlist']),
      value: z.string().optional().describe('Hash string, password, or password file path.'),
      timeoutMs: z.number().int().positive().max(120_000).optional().default(30_000),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    switch (args.operation) {
      case 'identify-hash': {
        if (!haveExe('hash-identifier')) return jsonResult({ error: 'hash-identifier not installed' });
        const val = args.value || '';
        const output = safeSpawnWithInput('hash-identifier', [], val + '\n', args.timeoutMs);
        return jsonResult({ type: 'hash-identification', output: (output || '').slice(0, 10000) });
      }
      case 'check-common': {
        const pw = String(args.value || '');
        if (!pw) return jsonResult({ error: 'value is required for check-common' });
        const wordlist = '/usr/share/wordlists/rockyou.txt';
        const grepOut = safeSpawn('grep', ['-cF', pw, wordlist], 15000);
        const count = grepOut.trim() || safeRun(`grep -c '^${pw.replace(/'/g, `'\\''`)}$' /usr/share/wordlists/rockyou.txt 2>/dev/null || echo 0`, 15000).trim();
        return jsonResult({ password: pw, inCommonWordlist: count !== '0', commonFileHits: parseInt(count) || 0 });
      }
      case 'generate-wordlist':
        return jsonResult({
          error: 'CNE policy denied wordlist generation from target content. Use approved password hygiene checks or scoped credential audits instead.',
          policy: 'data-purpose boundary',
        });
      default:
        return jsonResult({ error: `Unknown operation: ${args.operation}` });
    }
  },
);

// ── Package / software inventory ──
server.registerTool(
  'kali_package_audit',
  {
    title: 'Package Audit',
    description: 'Audit installed packages for known vulnerabilities using debsecan, apt-listbugs, and unattended-upgrades status. Read-only queries against the Debian/Kali security tracker.',
    inputSchema: {
      audit: z.enum(['debsecan', 'apt-listbugs', 'upgrade-status', 'held-packages', 'all']).default('all'),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async () => {
    const r = {};
    if (haveExe('debsecan')) r.debsecan_critical = safeRun('debsecan --suite=sid --only-fixed 2>/dev/null | head -100', 30000);
    if (haveExe('apt-listbugs')) r.apt_listbugs = safeRun('apt-listbugs list 2>/dev/null | head -50', 30000);
    r.upgrade_status = safeRun('apt list --upgradable 2>/dev/null | grep -i security | head -50', 20000);
    r.held_packages = safeRun('apt-mark showhold 2>/dev/null', 10000);
    r.unattended_status = safeRun('systemctl status unattended-upgrades 2>/dev/null || echo "unattended-upgrades service not found"', 10000);
    return jsonResult(r);
  },
);

// ── WAF / firewall detection ──
server.registerTool(
  'kali_waf_detect',
  {
    title: 'WAF Detection',
    description: 'Detect Web Application Firewalls in front of a target URL using wafw00f. Read-only — sends benign HTTP probes.',
    inputSchema: {
      target: z.string().describe('Target URL to probe for WAF presence.'),
    },
    annotations: { readOnlyHint: true, destructiveHint: false },
  },
  async (args) => {
    if (!haveExe('wafw00f')) return jsonResult({ error: 'wafw00f not installed' });
    try {
      assertAuthorizedTarget(args.target, 'active-scan');
    } catch (error) {
      return jsonResult({ error: String(error?.message || error), policy: 'CNE target-bound authorization' });
    }
    const output = safeSpawn('wafw00f', ['-a', args.target], 30000);
    return jsonResult({ target: args.target, output: output.slice(0, 20000) });
  },
);

// ──────────────────────────────
// Start server
// ──────────────────────────────
const transport = new StdioServerTransport();
await server.connect(transport);
