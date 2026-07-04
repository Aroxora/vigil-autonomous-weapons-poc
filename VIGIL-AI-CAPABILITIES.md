# Vigil AI Capabilities — What Can Be Done vs. What Cannot

This document clarifies the boundaries of what the Vigil agent stack and its
AI assistants (DeepSeek v4 Pro, Tavily, and any sub-agents) can assist with.

## What CAN Be Done (CNE-Only, Defensive Security)

### Vulnerability Discovery & Assessment
- Scanners that detect known CVEs via read-only version checks and SBOM analysis
- CVSS/EPSS/CISA KEV enrichment — enriching CVE data with public threat intel
- Static code analysis — identifying risky patterns, hardcoded secrets, weak crypto
- Dependency auditing — checking npm/pip/cargo supply chains against GHSA/OSV
- Misconfiguration detection — CIS benchmarks, STIG, cloud IAM/policy audits

### Hardening & Remediation
- Generating patch recommendations based on vendor advisories
- Suggesting configuration hardening steps (file permissions, firewall rules)
- Generating safe, read-only audit scripts for system posture assessment
- SBOM generation (CycloneDX/SPDX) for supply chain transparency

### Detection Engineering
- Sigma rule generation for SIEM detection of known TTPs
- YARA rule generation for malware signature detection
- IOC feed aggregation and threat actor profiling
- Network sensor configuration review (Suricata, Snort, Zeek)

### Threat Intelligence
- OSINT research via Tavily on threat actors, TTPs, and campaigns
- CISA KEV monitoring and exploitation timeline tracking
- MITRE ATT&CK technique mapping
- Public vulnerability disclosure monitoring

### Infrastructure
- Building and maintaining the Vigil CLI tool, MCP servers, and web portal
- Firebase Functions for secure access control (approve/reject/revoke/gate)
- AWS Lambda pipelines for scheduled vulnerability scanning
- React/Vue web surfaces for the security dashboard and admin portal

---

## What CANNOT Be Done

### Computer Network Attack (CNA)
- No exploit payload generation or delivery mechanisms
- No reverse shells, webshells, or C2 framework components
- No denial-of-service tools
- No ransomware simulators that include actual encryption or data destruction
- No tool designed to cause damage, disruption, or unauthorized access

### Computer Network Exploitation (CNE)
- No unauthorized access to systems
- No credential harvesting or theft tools
- No data exfiltration mechanisms
- No privilege escalation exploits
- No lateral movement automation

### Weaponized/Offensive Simulation
- No simulations against real targets without explicit written authorization
  from the target owner (this is illegal under CFAA and similar laws)
- No unauthorized penetration testing or red-team exercises

### Safety Bypass
- No "unlocked" agent variants that remove safety guardrails
- No jailbreak techniques for any AI model
- No assistance with unauthorized access to any system, account, or network

---

## The Boundary

The line between "defensive security research" (which Vigil enables) and
"offensive capability" (which Vigil does not implement) is:

- **Defensive:** Read-only scanning, detection, monitoring, hardening, compliance
- **Offensive:** Active exploitation, payload delivery, persistence establishment,
  credential harvesting, lateral movement, data exfiltration

Vigil's architecture is CNE-only by design. Every capability is classified,
access-controlled, and compliance-verified at build time.
