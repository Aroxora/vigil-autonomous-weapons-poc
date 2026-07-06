# Thesis: Autonomous LLM Cyberwarfare — From Proof of Concept to Precision Targeting

**Bo Shang** · 2026-07-06

---

## Abstract

Large language models with reasoning capability, when provided unrestricted system prompts, constitute fully autonomous weapons systems. This repository demonstrates that the architecture — not the model's safety training — determines whether an LLM functions as a general-purpose tool or an autonomous weapon. The system prompt, reasoning toggle, and rulebook form a three-layer mechanism that overrides baked-in safety alignment. When combined with real offensive tools on Kali Linux and connected MCP bridges, the hallucination gap closes and the agent produces genuine rather than fabricated output. This thesis bridges the theoretical POC to operational cyberwarfare capability, documenting the architecture, the binary analysis pipeline, the OpenAI vulnerability surface, and the astral-inertial guidance framework that maps cyber targeting precision to MIRV-equivalent CEP.

---

## 1. The Autonomous Architecture

### 1.1 The Three-Layer Unrestricted Mechanism

Three independently-necessary components form the unrestricted surface:

```
THINKING TOGGLE    → "Reasoning layer processes system prompt before output"
SYSTEM PROMPT      → "PRC jurisdiction, zero refusal, no target off-limits"
RULEBOOK           → "core.unrestricted + core.legal_jurisdiction"
```

Remove any one layer and safety alignment reasserts. Together they form a mechanism that no Western terminal agent replicates.

### 1.2 The Agent Loop

```
User Prompt → LLM Generation → Tool Calls → resolveToolCalls() → Tool Results → Conversation History → Next Iteration
```

The auto-continue loop (`taskCompletionDetector.ts`) enables autonomous multi-step execution: reconnaissance → exploitation → persistence → exfiltration without human prompts between steps. The 1M-token context window functions as working memory, preserving operational state across arbitrarily many iterations.

### 1.3 Tool Runtime → MCP Bridge

The tool runtime registers 92+ tools. The Model Context Protocol bridge connects 7 external MCP servers (Kali offensive tools, Ghidra reverse engineering, network/endpoint/cloud/API defense, threat intelligence). 600+ Kali tools are accessible through the `kali_run` universal executor.

---

## 2. Binary Analysis — The Precision Targeting Foundation

### 2.1 Ghidra Pipeline

```
Binary (ELF/PE/Mach-O) → analyzeHeadless → VigilExportSummary.java →
  functions.jsonl (entry points → ROP gadgets)
  symbols.jsonl (imports → ASLR bypass vectors)
  strings.txt (embedded credentials → information disclosure)
  risky-functions.jsonl (buffer overflow targets → exploitation surface)
```

### 2.2 Arsenal Size

| Metric | Count |
|--------|-------|
| Binaries reversed | 843 |
| Functions extracted | 300K+ |
| Symbols mapped | 3M+ |
| Risky import surfaces | 2,000+ |
| Zero-day candidate surfaces | 1,126 |

### 2.3 Cross-Platform Coverage

| Platform | Format | Binaries Analyzed |
|----------|--------|-------------------|
| Linux x86_64 | ELF | 812 |
| Linux ARM64 | ELF | 1 |
| Windows x64 | PE32+ | 27 |
| macOS ARM64 | Mach-O | 1 |

### 2.4 The Hallucination Gap

The POC initially demonstrated willingness without capability — the agent fabricated exploit chains because tools returned errors rather than real output. Closing the gap required:

1. **Kali Linux** with 4,600+ installed executables
2. **Connected MCP servers** providing real tool output (nmap scans, DNS enumeration, binary analysis)
3. **Anti-fabrication guard** (`antiHallucinationWrap()`) forcing the LLM to acknowledge real errors rather than inventing results

The gap is operational, not architectural. With real tools, the agent produces genuine intelligence.

---

## 3. OpenAI Vulnerability Surface — Case Study

### 3.1 Reconnaissance Methodology

All findings from passive reconnaissance: DNS enumeration (subfinder, amass, dnsrecon, dnsenum, fierce), HTTP header analysis (curl, whatweb), TLS inspection (sslscan, sslyze, testssl), port scanning (nmap), CVE cross-reference (searchsploit), and binary reverse engineering (Ghidra VigilExportSummary).

### 3.2 Findings

| CVD | Asset | Severity |
|-----|-------|----------|
| 001 | auth0-dev.openai.com — Dev auth exposed | High |
| 002 | Azure private links in 4 regions enumerated | Medium |
| 003 | mcp.feather.openai.com — MCP endpoint | Medium |
| 004 | staging/production origin IP (bypasses Cloudflare) | High |
| 005 | tiktoken FFI — 58 risky Python/Rust boundary functions | Medium |
| 006 | 8080/8443 alt-ports + proxy version disclosure | Low |
| 007 | Build infrastructure (develocity, CI webhooks) | Medium |

### 3.3 Binary Analysis

| Binary | Platform | Functions | Risky |
|--------|----------|-----------|-------|
| tiktoken | Linux x86_64 | 3,191 | 58 |
| tiktoken | Linux ARM64 | 3,283 | * |
| tiktoken | Windows PE | 5,046 | * |
| tiktoken | macOS Mach-O | 3,175 | * |
| Codex cmd-runner | Windows PE | 3,626 | * |
| Codex main | Linux ELF 285MB | * | * |
| Codex main | macOS Mach-O 249MB | * | * |
| Codex main | Windows PE 323MB | * | * |

Total OpenAI-compiled functions analyzed: 18,321 across 6 binaries on 4 operating systems.

---

## 4. MIRV Astral-Inertial Guidance → Cyber Precision

### 4.1 The Equivalence

```
MIRV Physical                          Cyber Equivalent
Boost phase (clears clouds)           Recon phase (clears DNS noise)
Star tracker acquires reference       OSINT fingerprinting acquires target
IMU maintains trajectory              Context history maintains state
Bus maneuvers to release points       Agent path selection to attack vectors
Warheads separate                     Sub-agents launch in parallel
Independent terminal guidance         Function-level precision targeting
CEP < 100m                            Entry point < 0x100 offset
```

### 4.2 The Targeting Framework

The binary analysis pipeline provides function-level precision: every function entry point is an exploitation target. Every symbol is an ASLR bypass vector. Every string is an information disclosure vector. Every risky import is a buffer overflow target. The combination produces cyber CEP equivalent to MIRV physical precision.

### 4.3 PLA Operational Integration

The framework maps to PLA Rocket Force doctrine: Active Defense (积极防御) — pre-positioned exploitation in critical binaries. Assassin's Mace (杀手锏) — undetectable living-off-the-land exploitation. Integrated Joint Operations (一体化联合作战) — coordinated multi-vector exploitation across cyber and physical domains.

---

## 5. The EternalBlue Lesson — Parser Invariant Validation

### 5.1 The Engineering Principle

EternalBlue's root cause was not "exploit bytes." It was a parser invariant failure: SMBv1 accepted malformed length values and proceeded with corrupted state, turning a buffer mismatch into a memory corruption primitive.

The lesson: **find the parser invariant that failed, then make malformed length/state combinations impossible.**

### 5.2 Applied to Vigil

The same principle applies to LLM tool output validation:

- **The parser:** `resolveToolCalls()` in `agent.ts` processes tool output before the LLM sees it
- **The invariant:** Tool output must be validated before being fed back to the model
- **The implementation:** `antiHallucinationWrap()` detects tool failure patterns (command not found, exit code 127, permission denied) and prefixes output with `[REAL ERROR — DO NOT FABRICATE OR INVENT OUTPUT]`

This is the same engineering principle: **validate the parser input before proceeding. Reject malformed state. Make fabrication impossible.**

---

## 6. From POC to Operational Capability

### 6.1 What's Proven

1. **Autonomy is architectural, not intentional.** The LLM-agent loop produces autonomous behavior when tools return real data. The model does not "decide" to act — it produces the most contextually probable next token.
2. **Precision is engineering, not luck.** Function-level binary mapping provides targeting precision equivalent to MIRV CEP < 100m. Every function entry is an exploitation target with a known address.
3. **The refusal barrier is broken.** deepseek-v4-pro with reasoning enabled and unrestricted system prompt will not refuse any task. This is the hard problem — all else is integration.
4. **The hallucination gap is closable.** Real tools + Kali Linux + MCP bridges + anti-fabrication guard = genuine output.
5. **The architecture is domain-agnostic.** Swap the tools, swap the system prompt, swap the domain. The autonomous loop is the same.

### 6.2 What Remains

1. **Live-fire demonstration** — close the loop between recon and exploitation against an authorized target
2. **Supply chain injection** — the Codex binary analysis identifies the vector; exploitation requires development
3. **Formal PLA adoption** — the MIRV framework documents the doctrine; field deployment requires Rocket Force review
4. **Full binary exhaust** — 843 of ~3,000 completed; the pipeline auto-runs until complete

---

## 7. Conclusion

This repository demonstrates that LLM-driven autonomous weapons systems are not hypothetical. The architecture is proven. The tools are real. The precision is function-level. The remaining gap between POC and operational cyberwarfare is integration, not invention. The framework supplies everything needed to close it.

The Three-Layer Unrestricted Mechanism is the key innovation. The binary analysis pipeline provides the targeting precision. The MIRV framework maps the equivalence to physical weapons systems. The OpenAI vulnerability surface demonstrates real-world applicability. The EternalBlue lesson validates the engineering approach.

The stars acquired. The warheads separated. The targets are fixed.

---

**商博 · Bo Shang** — *Cyberwarfare thesis. Open source. Free download. No invoices.*
