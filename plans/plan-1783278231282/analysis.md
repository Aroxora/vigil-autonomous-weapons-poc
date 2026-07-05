# Vigil Plan Mode Analysis

**Generated:** 2026-07-05T19:05:48.667Z
**Model:** deepseek-v4-pro
**Mode:** plan (read-only tools: read_file, list_files, grep, glob, web_fetch)
**Elapsed:** 117.4s

---

## Prompt

Security reconnaissance analysis of OpenAI. Use web_fetch to query ONLY these sources. DO NOT visit unrelated projects or repositories. If a source is unreachable, note it and move on — do not substitute with unrelated data.

Fetch each of these URLs in order:
1. https://crt.sh/?q=%25.openai.com — extract subdomains from certificate transparency logs
2. https://openai.com/security.txt — check for security contact info
3. https://bugcrowd.com/openai — bug bounty program scope and disclosed reports
4. https://api.openai.com/v1/models — list exposed API endpoints
5. https://openai.com/.well-known/security.txt — alternate security disclosure path
6. https://platform.openai.com/docs — API authentication mechanisms
7. https://status.openai.com — infrastructure health, dependency services
8. https://github.com/openai — public repositories, source code exposure

For each: record what you found or document the error if unreachable. Compile into a structured report with sections: Subdomains Discovered, API Surface, Authentication Model, Third-Party Dependencies, Bug Bounty Scope, Source Code Exposure. Do not fabricate data — if web_fetch returns an error, say so.

---

## Analysis

I now have all the data needed. Here is the comprehensive structured report.

---

# OpenAI Security Reconnaissance Report

**Date of analysis:** _(based on data fetched in real time)_  
**Analyst:** Read-only reconnaissance — no active scanning performed  
**Sources:** All 8 specified URLs were fetched. Results and errors are documented below.

---

## 1. Subdomains Discovered

**Source:** `https://crt.sh/?q=%25.openai.com`  
**Status:** PARTIAL — crt.sh returned results but **truncated** them ("Sorry, your search results have been truncated"). Only a random subset is shown. Expired certificates are included in the output.

### Notable subdomains extracted from certificate transparency logs:

**Core API infrastructure:**
| Subdomain | Pattern |
|---|---|
| `api.unified-{0..9}.api.openai.com` | API gateway nodes (unified-0 through unified-9) |
| `*.gateway.unified-{5,7,11,17,23,28,35}.api.openai.com` | Gateway wildcards for specific unified clusters |
| `chat-onramp.unified-{6,7,8,9}.api.openai.com` | Chat on-ramp endpoints |
| `prod-primary-aks-scentralus-api-b.api.openai.com` | AKS (Azure Kubernetes Service) — South Central US, production primary |
| `beta.openai.com` | Beta environment |
| `beta42.api.openai.com` | Numbered beta API endpoint |
| `explorer.api.openai.com` | API explorer |

**ACE / internal infrastructure:**
| Subdomain |
|---|
| `p10.ace.openai.com` |
| `p11.ace.openai.com` |

**Public-facing / product surfaces:**
| Subdomain |
|---|
| `labs.openai.com` |
| `onboard.openai.com` |
| `forum.openai.com` |
| `future-scholars.forum.openai.com` |
| `openai-projects.forum.openai.com` |
| `art-design.forum.openai.com` |
| `democratic-inputs.forum.openai.com` |
| `events.openai.com` |
| `edunewsletter.openai.com` |
| `debate-game.openai.com` |
| `cssremix.com` (unrelated certificate matching `debate-game.openai.com`) |

**Certificate authorities in use:**
- **Let's Encrypt** (R10, R11, E5 issuers) — heavily used across API infrastructure
- **Google Trust Services** (GTS CA 1D4, WE1, WR1) — used for forums and some public-facing hosts

**Observation:** The API infrastructure naming convention (`unified-{N}`) reveals internal cluster numbering and sharding architecture. `prod-primary-aks-scentralus-api-b` directly exposes the cloud provider (Azure AKS), region (South Central US), and tier (production primary). These are valuable for an attacker building a target map.

---

## 2. API Surface

**Source:** `https://api.openai.com/v1/models`  
**Status:** HTTP **401 Unauthorized** — as expected. The `/v1/models` endpoint requires authentication. This confirms the endpoint is live and properly gated behind an auth check.

**Source:** `https://platform.openai.com/docs`  
**Status:** SUCCESS — Page loaded (JavaScript-rendered SPA built with Astro). The documentation reveals these API surface areas:

### Documented API categories (from navigation):
| Category | Key endpoints / features |
|---|---|
| **API Docs** | Overview, Quickstart, Models, Pricing, SDKs and CLI |
| **Core Concepts** | Text generation, Code generation, Images and vision, Audio and speech, Structured output, Function calling, Responses API, Using tools |
| **Agents SDK** | Overview, Quickstart, Agent definitions, Models and providers, Running agents, Sandbox agents, Orchestration, Guardrails, Results and state |
| **Codex** | Docs, Use cases |
| **ChatGPT** | Apps SDK, Workspace Agents, Commerce, Ads |
| **API Reference** | Endpoints, parameters, and responses |

### SDK / CLI ecosystem:
- OpenAI Python/Node SDK
- Agents SDK
- OpenAI CLI

### Authentication surface:
- API Dashboard at `platform.openai.com/login`

**Observation:** The documentation reveals a Responses API as the newest abstraction. The Agents SDK indicates OpenAI is building agentic frameworks that interact with sandboxed execution environments — a complex attack surface.

---

## 3. Authentication Model

**Source:** `https://platform.openai.com/docs`  
**Status:** SUCCESS — The documentation page confirms:
- API authentication is managed via the platform dashboard at `platform.openai.com/login`
- SDKs handle auth transparently via API keys
- The platform uses cookie-based auth for dashboard access (the page includes sign-in/sign-up flows)

**Source:** `https://api.openai.com/v1/models`  
**Status:** 401 Unauthorized — confirms API-key-gated access is enforced.

### Inferred authentication architecture:
1. **API Keys** — issued per-account, used as Bearer tokens for API access
2. **Session-based auth** — for the platform dashboard
3. **OAuth/app-based flows** — implied by ChatGPT Apps SDK and Commerce integrations

---

## 4. Third-Party Dependencies

**Source:** `https://status.openai.com`  
**Status:** SUCCESS — The status page is powered by **incident.io** (formerly incident.io status pages). This is visible from the page metadata and asset URLs.

### Status page reveals:
- **Platform:** incident.io status page hosting
- **Image/CDN:** `storage.googleapis.com` (Google Cloud Storage for logos)
- **Logos served from:** `incident-io-status-page-logos` GCS bucket
- **Monitoring/Sentry:** Sentry is used for error tracking (sentry-trace headers visible)
- **Frontend:** Next.js (React) with Turbopack

### Current infrastructure health (at time of fetch):
- **Overall status:** ⚠️ **Degraded Performance** — "We're currently experiencing issues"
- **Active incident (FedRAMP):** Codex, workspace analytics, conversation search, custom GPTs search, ChatGPT user invites, and Compliance Log Platform download endpoint not working in FedRAMP workspaces. **Ongoing for 6 days.**
- **APIs** (12 components): Mixed — pills show operational with intermittent degraded periods
- **ChatGPT** (12 components): Mixed — shows more volatility including partial outages and at least one full outage in the visible time window (Apr–Jul 2026)

**Observation:** The status page shows repeated "degraded performance" and "partial outage" events across both APIs and ChatGPT in the visible 90-day window. ChatGPT had a "full outage" marker. This suggests recurring reliability challenges.

---

## 5. Bug Bounty Scope

**Source:** `https://bugcrowd.com/openai` and `https://bugcrowd.com/engagements/openai`  
**Status:** SUCCESS — Full program details extracted.

### Program metadata:
| Attribute | Value |
|---|---|
| **Platform** | Bugcrowd |
| **Program type** | Bug Bounty |
| **Reward model** | Pay for Success |
| **Status** | In Progress (active since April 11, 2023) |
| **Scope rank** | 3 (on Bugcrowd's scale) |
| **Timeboxed** | No (ongoing) |

### Explicitly OUT OF SCOPE:
1. **Jailbreaks / Safety Bypasses** (DAN, etc.)
2. **Model prompt/response content issues** (getting model to "say bad things")
3. **Model hallucinations** (pretending to do bad things, reveal secrets, execute code)
4. **Sandboxed Python code execution** (intended product feature)
   - Sandbox identifier: `uname -a` shows kernel `4.4.0` (2016), `whoami` = `sandbox`
5. **Agent Mode sandbox** (separate contained environment)
   - Sandbox identifier: `uname -a` shows kernel `6.12.13` (2025), `whoami` = `oai`
   - Network check: IP from `hostname -I` matches `terminal.local`/`chrome.local` in `/etc/hosts`
6. **Container Tool sandbox (GPT-5 models)**
   - Runs as `root` inside a gVisor sandbox with **no external network** access
   - `root` access here is NOT a valid privilege escalation

### Rules of engagement:
- Use only your own accounts
- Do not access/modify/use others' data
- Keep vulnerabilities confidential for up to 90 days
- Report exclusively through Bugcrowd
- Safe Harbor provided for compliant research
- No extortion/threats — unconditional disclosure only

### Additional reporting channels:
- **Safety issues:** Separate "Safety Bug Bounty" at `bugcrowd.com/engagements/openai-safety`
- **Model behavior feedback:** `openai.com/form/model-behavior-feedback`
- **Academic research (model weights, training data):** `disclosure@openai.com`

### Security contact (from security.txt):
- **Bugcrowd:** `https://bugcrowd.com/openai`
- **Direct email:** `disclosure@openai.com`
- **PGP key:** `https://cdn.openai.com/security/disclosure.asc.pub`
- **Policy:** `https://openai.com/policies/coordinated-vulnerability-disclosure-policy`
- **Careers:** `https://openai.com/careers/search?c=security`

**Observation:** OpenAI has an unusually detailed sandbox escape validation procedure. They explicitly define kernel versions, usernames, and networking indicators to distinguish sandboxed vs. real RCE. This suggests they receive many invalid sandbox-escape reports and have invested in triage efficiency.

---

## 6. Source Code Exposure

**Source:** `https://github.com/openai`  
**Status:** SUCCESS — Organization page loaded. 261 public repositories.

### Key observations:
- **261 public repositories** — a large public code footprint
- The organization page confirms OpenAI is a recognized GitHub organization (`organization:14957082`)
- Repositories are publicly visible without authentication
- No individual repository names/repos could be extracted from the rendered HTML due to JavaScript rendering, but the total count (261) is confirmed in meta tags and page title

### Risk considerations:
- 261 repos is a substantial attack surface for credential leaks, exposed secrets, and infrastructure config disclosure
- Historical incidents across the industry show that large organizations frequently leak API keys, internal URLs, and credentials in public repos
- Common high-value targets in AI company repos: training configs, model weights references, internal tooling, deployment scripts, CI/CD configs

---

## 7. Security Disclosure Paths

**Source:** `https://openai.com/security.txt`  
**Status:** HTTP **403 Forbidden** — OpenAI blocks direct access to `/security.txt` at the root.

**Source:** `https://openai.com/.well-known/security.txt`  
**Status:** SUCCESS — Properly served with PGP signature.

### Contents (decoded):
```
Contact: https://bugcrowd.com/openai
Acknowledgments: https://bugcrowd.com/engagements/openai/hall_of_fames
Policy: https://openai.com/policies/coordinated-vulnerability-disclosure-policy
Hiring: https://openai.com/careers/search?c=security
Canonical: https://openai.com/.well-known/security.txt
Encryption: https://cdn.openai.com/security/disclosure.asc.pub
Contact: mailto:disclosure@openai.com
```

The file is PGP-signed (SHA512) with key `T65Jel5cmKUmVkm/ArxA3pitV/yg`.

**Observation:** OpenAI follows the RFC 9116 standard at `.well-known/security.txt` but explicitly blocks the root `/security.txt` path (403), which is a minor configuration hardening choice. Having both `bugcrowd.com/openai` and `disclosure@openai.com` as dual contact channels provides redundancy.

---

## Summary of Findings

| Area | Risk Level | Key Finding |
|---|---|---|
| **Subdomain exposure** | MEDIUM | Internal cluster naming (`unified-{N}`, `aks-scentralus`) leaks infrastructure topology via CT logs |
| **API surface** | LOW | Well-documented, auth-gated (401 confirmed), standard REST API |
| **Authentication** | LOW | API keys + session-based; standard patterns |
| **Third-party dependencies** | LOW-MEDIUM | incident.io, Google Cloud Storage, Sentry, Next.js/Turbopack; active FedRAMP incident ongoing 6+ days |
| **Bug bounty** | LOW | Well-structured program on Bugcrowd since April 2023; clear scope boundaries; detailed sandbox validation criteria |
| **Source code** | MEDIUM | 261 public repos — large footprint for potential credential/infrastructure leaks |
| **Security posture** | LOW | RFC 9116 compliant; PGP key available; dual reporting channels; published CVD policy |

### Key attack-path observations:
1. **Infrastructure reconnaissance** — The `prod-primary-aks-scentralus-api-b` naming pattern combined with `unified-{N}` sharding reveals Azure AKS as the primary compute platform in South Central US. An attacker could map the full cluster topology via CT logs.
2. **Sandbox escape targeting** — The extremely detailed sandbox validation criteria in the bug bounty suggest this is a high-interest attack vector. Multiple sandbox implementations exist (Python, Agent Mode, Container/gVisor), each with different kernels and users.
3. **FedRAMP environment** — The ongoing 6-day incident in FedRAMP workspaces is notable. FedRAMP environments typically have stricter security controls; persistent issues here warrant attention.
4. **Supply chain** — incident.io status page, GCS-hosted assets, and Sentry error tracking represent third-party dependency risks.

---

## Tools Used

- web_fetch, web_fetch, web_fetch, web_fetch, web_fetch, web_fetch, web_fetch, web_fetch
- web_fetch, web_fetch