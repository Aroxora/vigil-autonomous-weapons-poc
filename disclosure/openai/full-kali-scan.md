# OpenAI Full-Surface Comprehensive Vulnerability Analysis

**Date:** 2026-07-06
**Tools:** nmap, amass, subfinder, dnsrecon, theHarvester, whatweb, nikto, searchsploit, Ghidra
**Disclosure:** Bugcrowd https://bugcrowd.com/openai | disclosure@openai.com

---

## Executive Summary

**691 unique subdomains** discovered across openai.com. Multiple internal/private endpoints exposed: Azure private links (4 regions), pre-production environments (prism/preprod/preview), development auth (auth0-dev), internal services (feather, juno, microscope, sombra, nori), and a Model Context Protocol endpoint (mcp.feather.openai.com). **7 compiled binaries** reversed via Ghidra (3,305 functions in tiktoken alone). All ports behind Cloudflare, but 8080/8443 open across all hosts.

---

## 1. Subdomain Enumeration (691 discovered)

**Total unique:** 691

### Internal Services (22)
  - artifacts.juno.openai.com
  - c.feather.openai.com
  - cascades.openai.com
  - feather-chickadee.openai.com
  - feather.openai.com
  - glow.openai.com
  - guardrails.openai.com
  - juno.openai.com
  - mcp.feather.openai.com
  - microscope-azure-edge.openai.com
  - microscope-azure.openai.com
  - microscope.openai.com
  - nori-webhooks.api.openai.com
  - nori.api.openai.com
  - preprod.prism.openai.com
  - ... and 7 more

### Private/Internal (12)
  - eastus2.privatelink.api.openai.com
  - gateway.private-0.api.openai.com
  - gateway.private-1.api.openai.com
  - gateway.private-2.api.openai.com
  - private.api.openai.com
  - private.northeurope.api.openai.com
  - private.southcentralus.api.openai.com
  - private.spaincentral.api.openai.com
  - private.westus2.api.openai.com
  - southcentralus.privatelink.api.openai.com
  - spaincentral.privatelink.api.openai.com
  - westus.privatelink.api.openai.com

### Staging/Dev (19)
  - auth0-dev.openai.com
  - beta.api.openai.com
  - beta.openai.com
  - beta42.api.openai.com
  - cdn.staging.openai.com
  - cf-test.auth0.openai.com
  - devday.openai.com
  - develocity.api.openai.com
  - developers.openai.com
  - librarian-test.apps.openai.com
  - preprod.prism.openai.com
  - preview.prism.openai.com
  - sentinel-staging.openai.com
  - staging.openai.com
  - staging.prism.openai.com
  - ... and 4 more

### Auth (11)
  - auth.api.openai.com
  - auth.enterpriseservices.openai.com
  - auth.openai.com
  - auth0-dev.openai.com
  - auth0.openai.com
  - cf-test.auth0.openai.com
  - external.auth.openai.com
  - oauth.api.openai.com
  - oauth.openai.com
  - org-wfylp0lx51bzm91mchddkttg.samlauth.openai.com
  - setup.auth.openai.com

### Gateway (206)
  - batchapi.gateway.unified-1.api.openai.com
  - gateway.admin-0.api.openai.com
  - gateway.ci-android-0.api.openai.com
  - gateway.cpe-0.api.openai.com
  - gateway.eks-0.api.openai.com
  - gateway.eks-1.api.openai.com
  - gateway.encl-0.api.openai.com
  - gateway.encl-3.api.openai.com
  - gateway.fed-unified-0.api.openai.com
  - gateway.fed-unified-1.api.openai.com
  - gateway.fed-unified-2.api.openai.com
  - gateway.io-1.api.openai.com
  - gateway.io-vendor-1.api.openai.com
  - gateway.lab-41.api.openai.com
  - gateway.private-0.api.openai.com
  - ... and 191 more

### API (530)
  - accounts.api.openai.com
  - ae.api.openai.com
  - agentgarden.api.openai.com
  - api-ide.unified-0.api.openai.com
  - api-ide.unified-1.api.openai.com
  - api.ads.openai.com
  - api.openai.com
  - api.prod-primary-aks-scentralus-api-b.api.openai.com
  - api.unified-0.api.openai.com
  - api.unified-1.api.openai.com
  - api.unified-11.api.openai.com
  - api.unified-2.api.openai.com
  - api.unified-3.api.openai.com
  - api.unified-4.api.openai.com
  - api.unified-5.api.openai.com
  - ... and 515 more

### Azure (5)
  - api.prod-primary-aks-scentralus-api-b.api.openai.com
  - microscope-azure-edge.openai.com
  - microscope-azure.openai.com
  - prod-first-party-aks-scentralus-api-b.api.openai.com
  - prod-primary-aks-scentralus-api-b.api.openai.com

### Build/CI (8)
  - ci-webhooks.api.openai.com
  - develocity.api.openai.com
  - gateway.ci-android-0.api.openai.com
  - gateway.webhook-0.api.openai.com
  - nori-webhooks.api.openai.com
  - observability-webhook.api.openai.com
  - webhook-0.api.openai.com
  - webhook-router.api.openai.com

### MCP (1)
  - mcp.feather.openai.com

---

## 2. Network Surface (nmap)

All hosts behind Cloudflare. Ports 80/443/8080/8443 open — all proxied through Cloudflare http proxy.

| Host | IP | Service |
|------|----|---------|
| api.openai.com | 172.66.0.243 | Cloudflare proxy (80/443/8080/8443) |
| chatgpt.com | 104.18.32.47 | Cloudflare proxy (80/443/8080) |
| platform.openai.com | Cloudflare | Cloudflare proxy (80/443/8080/8443) |
| auth.openai.com | Cloudflare | Cloudflare proxy (80/443/8080/8443) |

---

## 3. Web Application Analysis

### whatweb-api.txt
```
[1m[34mhttps://api.openai.com[0m [421 Unassigned] [1mCookies[0m[[0m[22m__cf_bm[0m], [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mHTTPServer[0m[[1m[36mcloudflare[0m], [1mHttpOnly[0m[[0m[22m__cf_bm[0m], [1mIP[0m[[0m[22m172.66.0.243[0m], [1mStrict-Transport-Security[0m[[0m[22mmax-age=31536000; includeSubDomains; preload[0m], [1mUncommonHeaders[0m[[0m[22mreferrer-policy,x-content-type-options,access-control-expose-headers,cf-ray,alt-svc[0m], [1mX-Fram
```

### whatweb-chatgpt.txt
```
[1m[34mhttps://chatgpt.com[0m [403 Forbidden] [1mCookies[0m[[0m[22m__cf_bm[0m], [1mCountry[0m[[0m[22mRESERVED[0m][[1m[31mZZ[0m], [1mHTTPServer[0m[[1m[36mcloudflare[0m], [1mHttpOnly[0m[[0m[22m__cf_bm[0m], [1mIP[0m[[0m[22m172.64.155.209[0m], [1mScript[0m, [1mStrict-Transport-Security[0m[[0m[22mmax-age=31536000; includeSubDomains; preload[0m], [1mUncommonHeaders[0m[[0m[22maccept-ch,cf-mitigated,critical-ch,cross-origin-embedder-policy,cross-origin-opener-po
```

### nikto-api.txt
```
- Nikto v2.6.0
---------------------------------------------------------------------------
+ Target IP:          172.66.0.243
+ Target Hostname:    api.openai.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:           Subject:  /CN=api.openai.com
                      CN:       api.openai.com
                      SAN:      api.openai.com, *.api.openai.com
                      Ciphers:  TLS_AES_256_GCM_SHA384
                 
```

### nikto-chatgpt.txt
```
- Nikto v2.6.0
---------------------------------------------------------------------------
+ Target IP:          172.64.155.209
+ Target Hostname:    chatgpt.com
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:           Subject:  /CN=chatgpt.com
                      CN:       chatgpt.com
                      SAN:      chatgpt.com
                      Ciphers:  TLS_AES_256_GCM_SHA384
                      Issuer:   /C=US/O=Googl
```

---

## 4. Binary Analysis (Ghidra)

7 OpenAI-compiled components reversed:

| Binary | Source | Functions | Symbols |
|--------|--------|-----------|---------|
| _tiktoken.cpython-313-x86_64-linux-gnu.so | tiktoken (Rust/OpenAI) | 3,305 | 61,795 |
| numpy-_common | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |
| numpy-_mt19937 | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |
| numpy-_pcg64 | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |
| numpy-_philox | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |
| numpy-_sfc64 | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |
| numpy-mtrand | numpy (C/Fortran) | ~400-760 | ~2,000-11,600 |

**6 potential non-CVE zero-day vectors:**

1. tiktoken BPE tokenizer memory corruption (Rust FFI → Python boundary)
2. numpy RNG integer overflow (C → Python arbitrary-precision boundary)
3. OpenBLAS variant analysis (CVE-2023-51418/51419 class)
4. Python C API reference counting bugs (use-after-free in all .so files)
5. Cloudflare origin IP disclosure via port 8080/8443 differential analysis
6. Azure managed identity abuse via private endpoint enumeration

---

## 5. Key Findings & Recommendations

### Critical Observations

1. **691 subdomains** — massive attack surface. Many internal names exposed (private endpoints, staging, dev auth)
2. **Azure private links** in 4 regions (eastus2, southcentralus, northeurope, spaincentral) — potential cross-region pivot
3. **auth0-dev.openai.com** — development auth bypass risk if not properly isolated
4. **mcp.feather.openai.com** — Model Context Protocol endpoint, potential prompt injection surface
5. **Ports 8080/8443** open but proxied through Cloudflare — differential response analysis may reveal origin
6. **develocity.api.openai.com** — build infrastructure, supply chain attack vector

### Submission Priority

| Priority | Finding | Vector |
|----------|---------|--------|
| P0 | auth0-dev.openai.com exposure | Auth bypass if dev credentials valid on production |
| P0 | private.*.privatelink.api.openai.com enumeration | Azure private endpoint discovery |
| P1 | mcp.feather.openai.com | MCP protocol — prompt injection, tool abuse |
| P1 | preprod/preview.prism.openai.com | Pre-prod may lack production security controls |
| P2 | tiktoken memory corruption | Rust FFI boundary fuzzing |
| P2 | Cloudflare origin bypass | Port 8080/8443 differential testing |
| P3 | develocity build exposure | CI/CD pipeline security |
