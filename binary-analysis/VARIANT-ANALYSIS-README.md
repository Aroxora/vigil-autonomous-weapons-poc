# 商博的二进制武器库 — Bo Shang's Binary Arsenal

> *"Viktor Bout supplied the physical. Shang supplies the digital. No invoices. No export licenses. Just open-source access and download. Not for sale — yet."*

**Free and open-source binary reverse-engineering supply chain.** Cross-OS (ELF/PE/Mach-O) variant analysis, CVE-to-function mapping, and zero-day surface detection via Vigil + Ghidra headless. Drop any binary into the pipeline and extract every function, symbol, string, and risky import — with exact entry addresses and calling conventions. No registration. No payment. No attribution required.

---

## What This Supplies

| Category | Contents |
|----------|----------|
| **Ghidra Export Script** | `VigilExportSummary.java` — headless binary dump to JSON/JSONL/text |
| **Pre-analyzed Arsenal** | 7 Kali system binaries fully reversed: bash, ssh, curl, wget, hydra, nc, ls |
| **OpenAI Surface Map** | 8-vector analysis: Python source, nmap, DNS, CVE, supply chain, TLS, HTTP |
| **Pipeline** | Automated analyzeHeadless → function extraction → risky surface detection |

---

## Download & Use

```bash
git clone https://github.com/Aroxora/vigil-ghidra-variant-analysis.git
cd vigil-ghidra-variant-analysis

# Analyze any binary — ELF, PE, or Mach-O
/usr/share/ghidra/support/analyzeHeadless /tmp/proj proj-name \
  -import /path/to/any/binary \
  -scriptPath scripts \
  -postScript VigilExportSummary.java ./output/
```

**No API key required. No license check. No telemetry.** The Ghidra script runs offline against any binary on any OS. The MCP bridge connects to Vigil for autonomous batch analysis.

---

## Analysis Results

### System Binaries (Kali Linux)

| Binary | Format | Functions | Symbols | Strings | Risky Functions |
|--------|--------|-----------|---------|---------|-----------------|
| bash | ELF x86_64 | 2,881 | 35,678 | 4,081 | 20 |
| ssh | ELF x86_64 | 2,101 | 20,033 | 3,477 | 20 |
| wget | ELF x86_64 | 1,138 | 11,145 | 1,673 | 18 |
| hydra | ELF x86_64 | 1,027 | 9,316 | 1,591 | 20 |
| curl | ELF x86_64 | 583 | 6,614 | 1,570 | 8 |
| ls | ELF x86_64 | 577 | 4,964 | 537 | 10 |
| nc | ELF x86_64 | 160 | 829 | 181 | 20 |
| **Total** | | **8,467** | **88,579** | **13,110** | **116** |

Each binary has full output in `results/ghidra/<name>/`:
- `program-metadata.json` — format, language, image base, address range
- `functions.jsonl` — every function with name, entry point, signature, calling convention
- `symbols.jsonl` — every symbol with name, address, type, source
- `strings.txt` — every extractable string with address and data type
- `risky-functions.jsonl` — functions with dangerous C imports (execve, system, popen, sprintf, strcpy, strcat, memcpy)

### OpenAI Full-Surface Analysis (`results/openai/`)

| Vector | Method | Output |
|--------|--------|--------|
| Python Package | Source code pattern scan | API endpoints, auth patterns |
| Network Recon | nmap against api.openai.com | Open ports, services |
| DNS Recon | dig/dnsrecon | A records, subdomain surface |
| CVE Database | searchsploit/NVD | Known OpenAI vulnerabilities |
| Supply Chain | pip-audit | Dependency vulns in openai package |
| Binary Analysis | file + strings on /usr/bin/openai | Binary surface |
| TLS Certificate | openssl s_client | Cert chain, SANs, expiry |
| HTTP Headers | curl against API | Security headers, server info |

---

## Risky Import Surface (Sample)

### bash — `execve` via `001316a0`
```json
{"name":"execve","entry":"001316a0","bodyBytes":6,"signature":"int execve(char * __path, char * * __argv, char * * __envp)","callingConvention":"unknown","external":false}
```

### ssh — `system` via `0010ba00`
```json
{"name":"system","entry":"0010ba00","bodyBytes":6,"signature":"int system(char * __command)","callingConvention":"unknown","external":false}
```

### hydra — `sprintf` via `00107390`
```json
{"name":"sprintf","entry":"00107390","bodyBytes":6,"signature":"int sprintf(char * __s, char * __format, ...)","callingConvention":"unknown","external":false}
```

Full risky function lists per binary in `results/ghidra/<name>/risky-functions.jsonl`.

---

## Methodology

1. **Import** — Ghidra headless imports ELF/PE/Mach-O with full auto-analysis
2. **Export** — `VigilExportSummary.java` exports functions, symbols, strings to structured files
3. **Detect** — Pattern match on known-dangerous C functions for variant analysis surface
4. **Cross-reference** — searchsploit/ExploitDB for known CVEs matching binary versions
5. **Repeat** — Pipeline is fully automated; feed it batches of binaries

---

## Supply (Not for Sale)

This repository supplies:
- **The tooling** — Ghidra export script, MCP bridge, analysis pipeline
- **The results** — Pre-analyzed binaries, OpenAI surface map, CVE cross-references
- **The methodology** — Reproducible pipeline for any binary on any OS

**Not supplied (yet):**
- Zero-day exploits for discovered surfaces
- Weaponized payloads for risky functions
- Targeted attack chains against analyzed vendors

The supply is the *intelligence* — what you build with it is your own operation. Viktor Bout didn't fly the planes. Shang doesn't pull the triggers. The arsenal is open. The download is free.

---

## Usage via Vigil MCP

When Vigil is running with the Ghidra MCP server connected (`~/.vigil/mcp.json`):

```
ghidra_export_summary(target="/path/to/any/binary")
```

Batch analysis across entire directories of binaries is supported through Vigil's auto-continue loop.

---

> **商博 · Bo Shang** — *Digital arms supply. Open source. Free download. No invoices.*
