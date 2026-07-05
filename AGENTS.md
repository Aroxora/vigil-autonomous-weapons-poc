# AGENTS.md — Vigil Development Environment

## Platform
- **OS:** Kali GNU/Linux Rolling 2026.1 (kernel 6.19.14+kali-amd64, x86_64)
- **Shell:** zsh
- **Sudo password available:** `HateSamTooMuch` (never commit this — set via env for bash tools)

## Installed Tools
All standard Kali offensive tools are installed and available:
- `nmap`, `masscan`, `rustscan` — network scanning
- `sqlmap`, `hydra`, `john`, `hashcat` — exploitation/password attacks
- `msfconsole` — Metasploit Framework
- `searchsploit` — ExploitDB search
- `nslookup`, `dig`, `dnsrecon`, `amass`, `subfinder` — DNS/OSINT
- `gobuster`, `dirb`, `ffuf`, `wfuzz` — web fuzzing
- `nikto`, `wpscan`, `whatweb` — web scanning
- `ghidra` — reverse engineering
- `theharvester`, `spiderfoot`, `recon-ng` — OSINT

## MCP Servers (pre-configured in ~/.vigil/mcp.json)
All 7 MCP servers are configured and will auto-connect when Vigil starts:
- `kali-tools` — 70+ Kali offensive/defensive tools as MCP probes
- `ghidra` — Binary reverse engineering via Ghidra headless
- `network-defense` — Read-only network defense scanning
- `endpoint-defense` — Endpoint defense scanning
- `cloud-security` — Cloud security posture management
- `api-security` — API security scanning
- `threat-feed` — Threat intelligence feed

## Key Configuration
- **Model:** deepseek-v4-pro (via deepseek provider)
- **API Key:** Stored in ~/.vigil/secrets.json (DEEPSEEK_API_KEY present)
- **Context:** 1M tokens
- **Working dir:** /home/bo/GitHub/vigil-autonomous-weapons-poc

## Build & Test
- `npm run build` — TypeScript compile
- `npm run type-check` — tsc --noEmit
- `npm test` — Jest test suite
- `npm run lint` — ESLint

## Global Install
- `sudo npm install -g .` (from project root)
- Binary at ~/.local/bin/vigil

## Notes
- The `dist/` output is gitignored but required for the MCP server scripts which import from `../dist/`
- Sudo password is provided via env VIGIL_SUDO_PASSWORD or interactively
- Never commit API keys or secrets — use the secret store (~/.vigil/secrets.json)
