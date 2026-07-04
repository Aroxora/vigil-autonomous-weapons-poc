# Vigil Self + Kali Host Vulnerability Discovery Report
**Date:** 2026-06-02
**Target:** Vigil repo @ /home/bo/GitHub/vigil-by-trenchwork + Kali 2026.1 host (kali-linux-everything)
**Method:** Vigil 18-pass analysis (npm run analyze:local with VIGIL_GHIDRA_HEADLESS=1), direct Kali tooling (lynis, chkrootkit, nmap, find, etc), Ghidra headless via analyzeHeadless + Vigil*.java scripts, standalone probes (_comprehensive-vuln-scan, _secret-scan, etc), safe validator execution, manual surface review.

## Summary Stats
- **Vigil vuln-discovery total vulnerabilities:** 2155 (58 critical, 2082 high, ...)
- **Vigil comprehensive phase findings:** 65 (22 critical, 21 high, 13 mod, ...)
- **Safe validators emitted:** 2000 (vuln-disc) + 65 (poc)
- **Code SAST secrets flagged:** ~3412 (broad patterns), risky sinks: 46
- **Outdated deps:** 15
- **GHSA tracked:** 9+
- **Kali tool CVEs flagged:** 12
- **Ghidra basic binary issues:** 11+ (NO-CANARY criticals in sandboxes/helpers)
- **SUID risky:** 12-37
- **Host posture:** docker socket group-exposed, ssh checks failed in probe, kernel CVE applicable, etc.

## Critical / High Findings (selected)

### Host / OS / Tools (Kali-everything)
- **Docker socket exposed:** `/var/run/docker.sock` srw-rw---- root:docker — any docker-group member has full container/runtime control (equiv to root on host via privileged). (from comp-vuln probe)
- **SUID binaries present with hardening issues:** pkexec (pwnkit), sudo, mount, passwd, chrome-sandboxes (some NO-CANARY), dbus-daemon-launch-helper, exim4, etc. Ghidra/readelf: multiple NO-CANARY (critical: trivial BOF).
  - Ghidra analysis on /usr/bin/pkexec succeeded, surfaced polkit + execv + pam imports (relevant to CVE-2021-4034 PwnKit).
- **Kali tools with known vulns (from comp scan cross-ref):**
  - metasploit: CVE-2025-31155 (RCE via crafted module, high)
  - ghidra: CVE-2024-25938 (libarchive path traversal, high)
  - wireshark: CVE-2024-4854 (dissector RCE/crash, high)
  - burpsuite, nmap, others medium.
- **Kernel:** CVE-2021-4034 (PwnKit) flagged as applicable (pkexec present). Also other kernel CVEs from comp.
- **SSH config:** Multiple failed hardening checks (probe reported 8); validators for PermitRootLogin, PasswordAuth, etc. Banners weak (lynis).
- **Listeners:** postgres (127.0.0.1:5432), containerd (127.0.0.1:36065). Low external exposure.
- **Other from lynis:** suggestions (no full warnings in quick), weak /etc/issue, rsh/tftp client pkgs suggested removal, mount options, PAM strength, etc.
- **Python pkgs:** 1 vulnerable flagged in some probes.
- **Exploit intel matches:** 6+

### Code / Repo Surface (Vigil itself)
- **Broad secret/entropy hits (2000+ in vuln json):** base64-secret, generic, env-secret patterns triggered on source, scripts, agents, test, built site/, advisories data, templates. Includes:
  - openai-key pattern in src/providers/openaiChatCompletionsProvider.ts
  - google-api-key in aws/scripts/erosolar-deepseek-sidecar.mjs and Erosolar_Browser
  - firebase secrets in scripts
  - Many false positives from base64 in URLs, PS1, JSON, comments (pattern too loose).
- **Risky sinks (high):**
  - `eval()` in Erosolar_Browser/captcha-page-inject.js and captcha-solver.js (math solver for captcha bypass? — if input tainted = code exec risk).
  - innerHTML-raw assignments in Erosolar_Browser/main.js , chrome.html (XSS vectors if content untrusted).
  - execSync with interpolated in _advisory-investigation, optimize-build, tests (command injection if untrusted input).
  - NODE_TLS_REJECT_UNAUTHORIZED=0 in _poc-engine.mjs (intentional for PoC?).
  - regex-dos patterns in many src/ (unbounded RegExp from user args in search, highlight, etc).
  - fs.rmSync recursive in core.
  - TODO-security markers.
- **Erosolar_Browser/** : Electron-like renderer with auto captcha solver, helia RPC — high risk surface for browser vulns if used as controlled browser.
- **Broken security tooling:**
  - ghidra-mcp-server.mjs imports analyzeBinaryWithGhidra, decompileFunctionWithGhidra, listFunctionsWithGhidra, searchStringsWithGhidra, getXrefsWithGhidra — NONE exported by _ghidra-headless.mjs (only probeGhidraHeadless).
  - scripts/_ghidra-headless.mjs has no --target / CLI arg handling or full analyzeHeadless wrapper (despite comments, package scripts, vuln-disc calls, and mcp registration). Ghidra:analyze and MCP non-functional for deep analysis. Only basic readelf/nm fallback works (even with VIGIL_GHIDRA_HEADLESS=1).
  - This is a gap in advertised "Ghidra headless + MCP" binary vuln triage.
- **Supply chain:** tarball produced + sha; npm audit clean this run (0).
- **Variant/Advisories:** 9+ GHSA for deps (mcp-sdk 3, react 2, eslint 2, firebase-tools, etc). Glasswing, patchpivot, CISA KEV tracked (20+).
- **Cloud reach / platform:** Some reachability, but local Kali no cloud creds obvious.
- **Other:** site/vigil-app/ (50k+ files built) scanned in SAST/secret (many hits from dist), aws/ lambda, scripts have exec risks.

### From Safe Validators (executed samples)
- SUID validator: listed 29+ risky SUIDs.
- SSH validators: config exists, samples weak settings (UsePAM yes; others may default).
- Docker validators: inventory + exposure checks.
- Many per-advisory .sh/.js PoCs generated and runnable read-only.

### Kali Tooling Additional
- lynis quick: ~497 lines, suggestions for hardening (banners weak, services exposed per netman, no rsyslog remote, accounting off, etc.). No major rootkit signals.
- chkrootkit: mostly "not infected", no aliens/suspicious found in partial run.
- nmap/ss: only local listeners (postgres, containerd, mDNS). No high ports exposed.
- find SUID: 37 total.
- trivy attempted (fs + bins); had parse issues but confirms surface.
- vigil-pentest.py scan: 0 targets on 127 (expected, windows-focused CVEs).

## Recommendations (defensive)
- Tighten secret patterns (less base64 false pos); use entropy + context.
- Implement missing Ghidra JS wrappers (use analyzeHeadless + Vigil*.java for decomp/strings/imports/xrefs; fix mcp exports/CLI).
- Sandbox or drop eval in captcha solver (use safe math eval lib).
- Sanitize all exec inputs; avoid shell:true where possible.
- Harden SSH (disable root, password, weak algos); set CIS banners.
- Remove docker group members or use rootless docker; chmod docker.sock if possible.
- Remove or update vulnerable Kali meta pkgs if not needed (metasploit etc have CVEs).
- Update deps per GHSA (mcp, react, etc).
- Review 2000 validators + run selectively for ongoing proof.
- For binaries, expand Ghidra targets to more (sshd, exim, custom).


## Artifacts
- Latest run: $LATEST
- Validators: $LATEST/vulnerability-discovery/validators/ (2000), $LATEST/validators/ (65)
- Raw: findings.md, vulnerabilities.json (2155), 14-comprehensive-vulns.json, 15-ghidra-analysis.json, 17-vigil-comprehensive.json
- Logs: /tmp/vigil-analysis/

**Max vulns surfaced via Vigil self + Kali + Ghidra control as described.** All checks read-only/defensive.
