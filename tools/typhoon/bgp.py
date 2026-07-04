#!/usr/bin/env python3
"""
Typhoon BGP Audit Module — Inter-Domain Routing Security

Covers BGP-4 attack surfaces:
  - Prefix hijack via unauthorized AS_PATH advertisement (AS7007 incident)
  - Route leak — customer routes leaked to transit providers
  - RPKI ROA not deployed — no Route Origin Authorization for carrier prefixes
  - BGP MD5/TTL security not configured — session hijacking via TCP RST injection
  - Maximum-prefix limit not set — route table overflow causing cascading failure
  - AS_PATH prepending manipulation — traffic steering for man-in-the-middle
  - Looking glass / route server information disclosure

All findings are deterministic — no active probing. The audit models what
an adversary COULD do given the known BGP architecture of the carrier.
"""

from __future__ import annotations

from tools.typhoon.core import CarrierProfile, Finding


# ---------------------------------------------------------------------------
# BGP Findings Factory
# ---------------------------------------------------------------------------

def _f(
    run_id: str,
    seq: str,
    severity: str,
    protocol: str,
    attack_tcode: str,
    title: str,
    description: str,
    tools: list[str],
    exploitation: str,
    counter: str,
    vigil_tool: str,
) -> Finding:
    """Factory to keep BGP findings DRY and consistent."""
    return Finding(
        id=f"BGP-{run_id}-{seq}",
        surface="bgp-hijack",
        severity=severity,
        protocol=protocol,
        attackTcode=attack_tcode,
        title=title,
        description=description,
        tools=tools,
        exploitationMethod=exploitation,
        counter=counter,
        vigilTool=vigil_tool,
    )


# ---------------------------------------------------------------------------
# BGP Audit Entry Point
# ---------------------------------------------------------------------------

def audit_bgp(carrier: CarrierProfile, run_id: str) -> list[Finding]:
    """Generate BGP audit findings for the given carrier profile."""
    findings: list[Finding] = []

    # ---- 1. BGP Prefix Hijack via Unauthorized AS_PATH Advertisement ----
    findings.append(_f(
        run_id, "7007",
        severity="critical",
        protocol="BGP-4",
        attack_tcode="T1498",
        title="BGP Prefix Hijack via Unauthorized AS_PATH Advertisement (AS7007-Style)",
        description=(
            f"{carrier.name} BGP peers accept prefix announcements without "
            f"validating AS_PATH origin. An adversary can announce a more-specific "
            f"prefix (/24 or longer) for a legitimate carrier network block, "
            f"injecting a false AS_PATH to redirect global Internet traffic "
            f"through adversary-controlled infrastructure. This mirrors the "
            f"notorious AS7007 incident where a misconfigured (or malicious) peer "
            f"leaked full Internet routes via an unauthorized AS_PATH, causing "
            f"worldwide Internet outages. Prefix hijack can be executed via any "
            f"compromised or rogue BGP peer connected to {carrier.name} exchange "
            f"points, IXP route servers, or transit fabric."
        ),
        tools=[
            "BGPalerter",
            "BGPStream",
            "bgp.he.net",
            "ARTEMIS",
            "ExaBGP",
        ],
        exploitation=(
            "1. Identify target prefix block via bgp.he.net or BGP looking glass. "
            "2. Compromise or provision a BGP-speaking node at a peering point. "
            "3. Announce a /24 more-specific prefix for the target with a crafted "
            "AS_PATH claiming origin. 4. BGP best-path selection prefers the "
            "longest prefix match — traffic diverts globally within minutes. "
            "5. Adversary can blackhole, inspect, or modify traffic before "
            "forwarding (or dropping) it toward the legitimate origin."
        ),
        counter=(
            "Deploy RPKI Route Origin Validation (ROV) to reject invalid origin AS "
            "announcements. Implement prefix filtering at all BGP sessions — only "
            "accept prefixes explicitly assigned to peers (IRR + RPKI). Configure "
            "BGP maximum-prefix limits. Deploy BGP monitoring (BGPalerter, "
            "BGPStream) for real-time anomaly detection. Use ASPA (Autonomous "
            "System Provider Authorization) to prevent path manipulation."
        ),
        vigil_tool="typhoon.bgp.prefixHijackAudit()",
    ))

    # ---- 2. BGP Route Leak — Customer Routes Leaked to Transit Providers ----
    findings.append(_f(
        run_id, "rlek",
        severity="critical",
        protocol="BGP-4",
        attack_tcode="T1190",
        title="BGP Route Leak — Customer Routes Leaked to Transit Providers",
        description=(
            f"{carrier.name} BGP configuration lacks egress route filtering on "
            f"customer-edge and transit-edge BGP sessions. A customer advertising "
            f"routes learned from one upstream transit to another upstream transit "
            f"can cause a route leak — accidentally or maliciously — polluting the "
            f"global BGP table. The 2017 Google/Verizon route leak and the 2019 "
            f"Cloudflare/Verizon leak both originated from misconfigured BGP route "
            f"export policies. An adversary with control of a single customer "
            f"network connected to {carrier.name} can propagate malicious routes "
            f"to all carrier transit providers, creating a man-in-the-middle "
            f"position or a large-scale denial-of-service condition."
        ),
        tools=[
            "BGPStream",
            "bgp.he.net",
            "ASRank (CAIDA)",
            "BGPalerter",
        ],
        exploitation=(
            "1. Establish (or compromise) a BGP customer session with the carrier. "
            "2. Advertise routes learned from Transit-A toward Transit-B, or "
            "advertise private/internal prefixes as externally reachable. "
            "3. Due to lack of BGP export filtering, the carrier propagates these "
            "malicious routes to all peers. 4. Global traffic is steered through "
            "the adversary-controlled customer network. 5. Traffic can be inspected, "
            "modified, or dropped — effectively a prefix-level MITM or DoS."
        ),
        counter=(
            "Implement strict BGP export filtering based on IRR route/route6 objects "
            "and RPKI ROAs. Configure BGP community-based traffic engineering to "
            "prevent transit-to-transit route propagation. Deploy BGPsec path "
            "validation. Monitor for route leak signatures via BGPStream and "
            "bgp.he.net alerts. Enforce 'no-export' and 'no-advertise' communities "
            "on customer BGP sessions by default."
        ),
        vigil_tool="typhoon.bgp.routeLeakAudit()",
    ))

    # ---- 3. RPKI ROA Not Deployed — No Route Origin Authorization ----
    findings.append(_f(
        run_id, "rpki",
        severity="high",
        protocol="BGP-4",
        attack_tcode="T1190",
        title="RPKI Route Origin Authorization (ROA) Not Deployed for Carrier Prefixes",
        description=(
            f"{carrier.name} has not deployed RPKI Route Origin Authorization (ROA) "
            f"for its advertised BGP prefixes, and lacks Route Origin Validation (ROV) "
            f"on inbound BGP sessions. Without ROAs, any adversary with BGP peering "
            f"access can announce {carrier.name} IP space without cryptographic "
            f"challenge. The global RPKI adoption rate remains below 50%, meaning "
            f"the majority of ISPs — including potentially {carrier.name} — operate "
            f"without cryptographic origin validation. An adversary can announce "
            f"any prefix owned by {carrier.name} and RPKI-unaware peers will accept "
            f"it without validation, enabling undetected prefix hijack."
        ),
        tools=[
            "RPKI-Client",
            "routinator (NLnet Labs)",
            "RTRlib",
            "bgp.he.net RPKI Check",
        ],
        exploitation=(
            "1. Query bgp.he.net to confirm carrier prefixes lack ROA coverage. "
            "2. Use RPKI-Client or routinator to validate that no ROA exists for "
            "target prefixes. 3. Announce target prefix via any BGP-speaking node "
            "at an IXP or transit provider. 4. RPKI-unaware networks accept the "
            "announcement without validation. 5. Traffic to carrier IP space is "
            "redirected to adversary infrastructure — undetected by RPKI validation."
        ),
        counter=(
            "Publish ROAs for all carrier-announced prefixes via the five RIRs "
            "(ARIN, RIPE, APNIC, LACNIC, AFRINIC). Deploy RPKI ROV on all BGP "
            "sessions using routinator, RTRlib, or vendor-native RPKI support. "
            "Configure ROV to drop 'invalid' ROA status routes. Integrate RPKI "
            "monitoring into NOC dashboards for ROA expiration alerts."
        ),
        vigil_tool="typhoon.bgp.rpkiAudit()",
    ))

    # ---- 4. BGP MD5/TTL Security Not Configured — Session Hijacking ----
    findings.append(_f(
        run_id, "md5t",
        severity="critical",
        protocol="BGP-4",
        attack_tcode="T1557",
        title="BGP MD5/TTL Security Not Configured — TCP Session Hijacking via RST Injection",
        description=(
            f"{carrier.name} BGP sessions with peers, transit providers, and route "
            f"reflectors lack TCP MD5 signature authentication (RFC 2385) and "
            f"Generalized TTL Security Mechanism (GTSM / RFC 5082). An on-path "
            f"adversary can inject TCP RST packets into the BGP session, tearing "
            f"down the peering relationship and triggering route withdrawal across "
            f"the carrier's entire backbone. TCP RST injection requires only the "
            f"ability to spoof a valid TCP sequence number within the window — "
            f"trivially achievable on long-lived BGP sessions with predictable "
            f"sequence numbers. GTSM (TTL=255 check) prevents remote off-path "
            f"RST injection but is not configured on {carrier.name} BGP sessions."
        ),
        tools=[
            "tcpdump / Wireshark",
            "Scapy (TCP RST crafting)",
            "bgp.he.net (topology discovery)",
            "Nmap (BGP port scan)",
        ],
        exploitation=(
            "1. Identify active BGP sessions via bgp.he.net topology or direct "
            "TCP/179 probing. 2. Determine TCP sequence number range via traffic "
            "analysis or brute-force (BGP sessions are long-lived — window size "
            "is large, making spoofing easier). 3. Inject spoofed TCP RST packet "
            "from the peer's IP toward the carrier's BGP speaker on port 179. "
            "4. BGP session tears down — all routes learned via that peer are "
            "withdrawn. 5. Traffic is re-routed (possibly through adversary path) "
            "or blackholed — cascading failure across the carrier backbone."
        ),
        counter=(
            "Enable TCP MD5 signature authentication on ALL BGP sessions — peering, "
            "transit, route reflector, and iBGP mesh. Deploy GTSM (RFC 5082) — set "
            "TTL=255 on BGP packets and reject any BGP packet with TTL < 254. "
            "Implement BGP TTL security hop-count validation. Use BGP session "
            "dampening and graceful restart to mitigate flap impact. Deploy "
            "BGP session monitoring with SNMP traps and NetFlow anomaly detection."
        ),
        vigil_tool="typhoon.bgp.sessionSecurityAudit()",
    ))

    # ---- 5. BGP Maximum-Prefix Limit Not Set — Route Table Overflow ----
    findings.append(_f(
        run_id, "mplf",
        severity="high",
        protocol="BGP-4",
        attack_tcode="T1499",
        title="BGP Maximum-Prefix Limit Not Set — Route Table Overflow Cascading Failure",
        description=(
            f"{carrier.name} has not configured maximum-prefix limits on BGP "
            f"sessions with peers, customers, or transit providers. Without these "
            f"limits, a single compromised or misconfigured BGP peer can flood "
            f"{carrier.name} routers with excessive route announcements — the "
            f"full Internet routing table (~950,000+ prefixes as of 2025) or "
            f"millions of bogus /32 prefixes. This exhausts router TCAM/hardware "
            f"FIB memory, causing route processing failures, BGP session flaps, "
            f"and potential cascading failure across the carrier backbone. The "
            f"2014 AS7018 (AT&T) outage and 2021 Facebook BGP outage both "
            f"involved route table overload conditions."
        ),
        tools=[
            "BGPalerter",
            "BGPStream",
            "ExaBGP (prefix flood generator)",
            "pybgpstream",
        ],
        exploitation=(
            "1. Establish or compromise a BGP session with the carrier (customer "
            "or peer). 2. Announce 1,000,000+ bogus /32 prefixes, or re-announce "
            "the full global BGP table of ~950,000 prefixes. 3. Carrier routers "
            "accept all prefixes without max-prefix enforcement. 4. TCAM/FIB "
            "memory exhausted — FIB programming fails, route processor CPU spikes. "
            "5. BGP sessions time out under high CPU load — cascading session "
            "teardown isolates the carrier backbone from the global Internet."
        ),
        counter=(
            "Configure per-peer maximum-prefix limits on ALL BGP sessions: "
            "customer peers (e.g., 1,000 prefixes), transit peers (e.g., "
            "1,000,000 prefixes), and route reflectors. Set max-prefix restart "
            "timers to auto-recover sessions after the offending peer is shut. "
            "Deploy prefix-list filtering to restrict accepted prefixes to "
            "known customer/peer blocks. Monitor TCAM/FIB utilization via SNMP "
            "and NetFlow for abnormal prefix count spikes."
        ),
        vigil_tool="typhoon.bgp.maxPrefixAudit()",
    ))

    # ---- 6. BGP AS_PATH Prepending Manipulation — Traffic Steering for MITM ----
    findings.append(_f(
        run_id, "aspp",
        severity="high",
        protocol="BGP-4",
        attack_tcode="T1557",
        title="BGP AS_PATH Prepending Manipulation — Traffic Steering for Adversary-in-the-Middle",
        description=(
            f"{carrier.name} does not validate AS_PATH length or AS_PATH content "
            f"integrity on received BGP announcements. An adversary can craft "
            f"AS_PATH with strategic prepending — either stripping legitimate AS "
            f"hops (AS_PATH shortening to attract traffic) or prepending extra AS "
            f"hops (AS_PATH lengthening to divert traffic away from competitor "
            f"paths). By manipulating AS_PATH attributes, an adversary forces "
            f"BGP best-path selection to route traffic through attacker-controlled "
            f"ASes. This enables adversary-in-the-middle (AiTM) interception: "
            f"traffic enters adversary infrastructure, is inspected or modified, "
            f"and then forwarded to the legitimate destination. Unlike full prefix "
            f"hijack, AS_PATH manipulation is stealthier — traffic still reaches "
            f"the destination, making detection via end-to-end monitoring harder."
        ),
        tools=[
            "BGPStream",
            "BGPalerter",
            "ExaBGP (AS_PATH crafting)",
            "bgp.he.net (AS topology graph)",
        ],
        exploitation=(
            "1. Map carrier AS-level topology using bgp.he.net and CAIDA ASRank "
            "to identify peering and transit paths. 2. Announce carrier prefixes "
            "with a shortened AS_PATH that skips legitimate transit ASes, making "
            "the adversary path appear shorter. 3. BGP best-path algorithm selects "
            "the adversary route (shorter AS_PATH wins). 4. Alternatively, prepend "
            "benign-looking AS numbers to divert traffic away from a target link "
            "while steering it through adversary infrastructure. 5. Adversary "
            "performs passive inspection or active modification of all transit "
            "traffic before delivering to the legitimate destination."
        ),
        counter=(
            "Deploy BGPsec path validation (RFC 8205) to cryptographically verify "
            "each AS hop in the AS_PATH. Implement AS_PATH filtering — reject "
            "routes with forbidden AS numbers or invalid AS_PATH lengths. Use "
            "ASPA (Autonomous System Provider Authorization) to validate that "
            "only authorized ASes appear as transit providers. Monitor AS_PATH "
            "changes via BGPStream for anomalous prepending or shortening events. "
            "Configure BGP community-based local preference to override AS_PATH "
            "shortest-path selection when integrity is in doubt."
        ),
        vigil_tool="typhoon.bgp.asPathAudit()",
    ))

    # ---- 7. BGP Looking Glass / Route Server Information Disclosure ----
    findings.append(_f(
        run_id, "lkgf",
        severity="high",
        protocol="BGP-4",
        attack_tcode="T1190",
        title="BGP Looking Glass / Route Server Information Disclosure",
        description=(
            f"{carrier.name} operates or exposes BGP looking glass servers, route "
            f"servers, or public BGP monitoring interfaces that disclose sensitive "
            f"network topology data without adequate access control. Looking glass "
            f"servers expose the full BGP routing table, AS_PATH to any prefix, "
            f"peer status, and internal next-hop topology to unauthenticated "
            f"remote users. An adversary can use this intelligence to map the "
            f"carrier's entire peering fabric, identify critical transit paths, "
            f"discover unannounced prefixes, and select optimal hijack targets. "
            f"Route server information combined with BGP community data reveals "
            f"traffic engineering policies, preferred upstreams, and peering "
            f"settlement relationships — all valuable for planning targeted "
            f"inter-domain attacks against {carrier.name}."
        ),
        tools=[
            "bgp.he.net (looking glass aggregation)",
            "traceroute / MTR",
            "BGPalerter",
            "BGPStream",
        ],
        exploitation=(
            "1. Access carrier looking glass via public URL or bgp.he.net "
            "aggregation. 2. Issue 'show ip bgp' or equivalent query to dump "
            "full BGP RIB with AS_PATH, next-hop, local-pref, and communities. "
            "3. Map carrier peering topology — which transit providers, which "
            "IXPs, which customers, and AS_PATH length to each prefix. 4. Identify "
            "single-homed prefixes (no backup path), critical transit chokepoints, "
            "and prefixes with weak AS_PATH diversity. 5. Select optimal hijack "
            "targets based on topology intelligence — maximizing impact while "
            "minimizing detection probability."
        ),
        counter=(
            "Restrict looking glass access to authenticated and authorized "
            "users only (SSO / MFA). Do not expose full BGP RIB; instead provide "
            "prefix-specific queries (e.g., show ip bgp X.X.X.X only). Implement "
            "rate limiting on looking glass queries to prevent bulk RIB extraction. "
            "Audit route server configurations to remove unnecessary BGP community "
            "and policy disclosures. Deploy RPKI ROA + BGPsec so topology "
            "intelligence has limited exploitation value even if disclosed."
        ),
        vigil_tool="typhoon.bgp.lookingGlassAudit()",
    ))

    return findings
