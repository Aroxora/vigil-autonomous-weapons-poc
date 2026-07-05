# Vigil Comprehensive Vulnerability Discovery

- **Run ID:** 2026-07-05T19-11-15-287Z
- **Platform:** auto/x64
- **Host:** ubuntu
- **Duration:** 26060ms

## Summary

- **Total findings:** 66
- **Critical:** 22 | **High:** 22 | **Moderate:** 13 | **Low:** 6
- **Immediate (score>=80):** 16 | **Urgent (score>=60):** 9
- **CISA KEV matches:** 15 | **With CVE IDs:** 31

## Top Findings (by priority)
- **HIGH** [100] CVE-2026-31431: AF_ALG Copy Fail LPE — AF_ALG algif_aead page cache corruption (all kernels with CONFIG_CRYPTO_AEAD=y) (CVE-2026-31431)
- **HIGH** [100] CVE-2021-4034: PwnKit — Local privilege escalation via pkexec (CVE-2021-4034)
- **CRITICAL** [100] Apache Tomcat: CVE-2025-24813 — Path equivalence leading to RCE/Info Disclosure (CVE-2025-24813)
- **CRITICAL** [100] Jenkins Jenkins CLI: CVE-2024-23897 — Arbitrary file read via CLI args leading to RCE (CVE-2024-23897)
- **CRITICAL** [100] Fortinet FortiOS: CVE-2024-55591 — WebSocket auth bypass via CSF proxy (CVE-2024-55591)
- **CRITICAL** [100] Fortinet FortiManager: CVE-2024-47575 — Missing auth in fgfmsd daemon leading to RCE (CVE-2024-47575)
- **CRITICAL** [100] Palo Alto PAN-OS: CVE-2024-0012 — Auth bypass in GlobalProtect portal (CVE-2024-0012)
- **CRITICAL** [100] SAP NetWeaver: CVE-2025-31324 — Remote code execution via ICM component (CVE-2025-31324)
- **CRITICAL** [98] Microsoft MSMQ: CVE-2025-26633 — MSMQ remote code execution — exploited in wild (CVE-2025-26633)
- **CRITICAL** [96] Microsoft Windows CLFS: CVE-2024-49138 — CLFS driver elevation of privilege — PWN2OWN (CVE-2024-49138)
- **CRITICAL** [91] Apple WebKit: CVE-2025-24201 — Out-of-bounds write — actively exploited (CVE-2025-24201)
- **CRITICAL** [90] Oracle WebLogic: CVE-2024-21287 — T3/IIOP protocol deserialization RCE (CVE-2024-21287)
- **CRITICAL** [90] VMware ESXi: CVE-2025-22224 — TOCTOU out-of-bounds write leading to VM escape (CVE-2025-22224)
- **CRITICAL** [90] VMware ESXi: CVE-2025-22225 — Arbitrary write vulnerability (CVE-2025-22225)
- **CRITICAL** [85] Kubernetes ingress-nginx: CVE-2025-1974 — ingress-nginx RCE via admission controller (CVE-2025-1974)
- **HIGH** [85] Intel Intel CPU: CVE-2025-27363 — PMU side-channel information disclosure (CVE-2025-27363)
- **CRITICAL** [78] Microsoft LDAP: CVE-2024-49112 — LDAP remote code execution — zero-click (CVE-2024-49112)
- **CRITICAL** [66] GitHub GitHub Enterprise: CVE-2024-9487 — SAML auth bypass via encrypted assertions (CVE-2024-9487)
- **CRITICAL** [65] GitLab GitLab: CVE-2025-25291 — Account takeover via SAML authentication bypass (CVE-2025-25291)
- **CRITICAL** [64] Docker Docker Engine: CVE-2024-41110 — AuthZ plugin bypass via Content-Length 0 (CVE-2024-41110)
- **CRITICAL** [62] Apache Tomcat: CVE-2024-56337 — TOCTOU RCE on case-insensitive filesystems (CVE-2024-56337)
- **CRITICAL** [60] Google Chrome V8: CVE-2025-0999 — V8 heap corruption (CVE-2025-0999)
- **CRITICAL** [60] Adobe Acrobat/Reader: CVE-2025-27148 — Use-after-free in Acrobat rendering engine (CVE-2025-27148)
- **CRITICAL** [60] Atlassian Confluence: CVE-2025-1454 — Template injection RCE in Confluence (CVE-2025-1454)
- **CRITICAL** [60] Qualcomm Snapdragon: CVE-2025-20626 — WLAN firmware memory corruption leading to baseband RCE (CVE-2025-20626)
- **HIGH** [57] NVIDIA GPU Display Driver: CVE-2024-0132 — TOCTOU privilege escalation (CVE-2024-0132)
- **HIGH** [48] 1 security package updates available (1390 total upgradable out of 4778 installed)
- **HIGH** [48] SELinux is Disabled (should be Enforcing)
- **HIGH** [48] SSH misconfiguration: Root SSH login allowed
- **HIGH** [48] SSH misconfiguration: Empty SSH passwords allowed

## Categories
- kernel: 2
- advisory: 29
- patching: 1
- misconfiguration: 12
- runtime: 1
- service: 12
- container: 2
- secret: 3
- dependency: 1
- privilege-escalation: 1
- os-info: 1
- cloud: 1
