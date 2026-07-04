#!/usr/bin/env python3
"""
Typhoon Passive Recon Module — Carrier Infrastructure OSINT

Zero active probing. Uses exclusively public sources:
  - Certificate Transparency (crt.sh) — subdomain discovery
  - DNS resolution (A, AAAA) for known carrier hostnames
  - BGPView API — ASN prefix advertisement data
  - Shodan InternetDB (free tier) — passive port/service fingerprinting

All queries are rate-limited to avoid triggering abuse detection.
Designed for authorized telecom security assessments only.

Usage:
    python3 -m tools.typhoon.recon at&t     # passive recon
    python3 -m tools.typhoon.recon --json at&t  # JSON output
"""

from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote

from tools.typhoon.core import CarrierProfile
from tools.typhoon.carriers import get_carrier

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_MIN_DELAY = 1.5   # seconds between HTTP requests (crt.sh rate limit: ~1/sec)
_LAST_REQUEST = 0.0


def _rate_limit() -> None:
    global _LAST_REQUEST
    now = time.time()
    elapsed = now - _LAST_REQUEST
    if elapsed < _MIN_DELAY:
        time.sleep(_MIN_DELAY - elapsed)
    _LAST_REQUEST = time.time()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

USER_AGENT = "Typhoon/1.0 (Vigil CNE; telecom security assessment; authorized only)"


def _http_get(url: str, timeout: int = 15) -> Optional[str]:
    """Fetch a URL with rate limiting and error handling."""
    _rate_limit()
    try:
        req = Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
        })
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return body.decode("utf-8", errors="replace")
    except (URLError, HTTPError, OSError) as e:
        print(f"  [recon] HTTP error for {url[:80]}: {e}", flush=True)
        return None


# ---------------------------------------------------------------------------
# 1. Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

def _ct_search(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh for certificates matching the carrier domain."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    body = _http_get(url, timeout=20)
    if not body:
        return []

    try:
        entries = json.loads(body)
    except json.JSONDecodeError:
        return []

    # Deduplicate by name_value
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for entry in entries[:500]:
        name = entry.get("name_value", "").strip().lower()
        if name and name not in seen:
            seen.add(name)
            results.append({
                "name": name,
                "issuer": (entry.get("issuer_name") or "")[:120],
                "not_before": entry.get("not_before", ""),
                "not_after": entry.get("not_after", ""),
            })
    return sorted(results, key=lambda x: x["name"])


# ---------------------------------------------------------------------------
# 2. DNS resolution
# ---------------------------------------------------------------------------

def _dns_resolve(hostname: str) -> dict[str, Any]:
    """Resolve A and AAAA records for a hostname."""
    result: dict[str, Any] = {
        "hostname": hostname, "ipv4": [], "ipv6": [], "cname": None,
    }
    # A records
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        result["ipv4"] = sorted(set(a[4][0] for a in addrs))
    except (socket.gaierror, OSError):
        pass
    # AAAA records
    try:
        addrs = socket.getaddrinfo(hostname, None, socket.AF_INET6, socket.SOCK_STREAM)
        result["ipv6"] = sorted(set(a[4][0] for a in addrs))
    except (socket.gaierror, OSError):
        pass
    return result


# ---------------------------------------------------------------------------
# 3. BGPView API — ASN and prefix lookup
# ---------------------------------------------------------------------------

def _bgpview_asn(asn: str) -> Optional[dict[str, Any]]:
    """Query bgpview.io for ASN information."""
    url = f"https://api.bgpview.io/asn/{asn}"
    body = _http_get(url)
    if not body:
        return None
    try:
        data = json.loads(body)
        asn_data = data.get("data", {})
        return {
            "asn": asn_data.get("asn"),
            "name": asn_data.get("name", ""),
            "description": asn_data.get("description_short", ""),
            "country": asn_data.get("country_code", ""),
            "prefixes_v4": len(asn_data.get("ipv4_prefixes", [])),
            "prefixes_v6": len(asn_data.get("ipv6_prefixes", [])),
        }
    except (json.JSONDecodeError, KeyError):
        return None


def _bgpview_prefixes(asn: str) -> list[str]:
    """Get all advertised IPv4 prefixes for an ASN."""
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    body = _http_get(url)
    if not body:
        return []
    try:
        data = json.loads(body)
        v4 = data.get("data", {}).get("ipv4_prefixes", [])
        return [p["prefix"] for p in v4[:50]]
    except (json.JSONDecodeError, KeyError):
        return []


def _bgpview_search(query: str) -> list[dict[str, Any]]:
    """Search BGPView for organization name."""
    url = f"https://api.bgpview.io/search?query_term={quote(query)}"
    body = _http_get(url)
    if not body:
        return []
    try:
        data = json.loads(body)
        results = data.get("data", {}).get("asns", [])
        return [
            {"asn": r["asn"], "name": r.get("name", ""), "country": r.get("country_code", "")}
            for r in results[:10]
        ]
    except (json.JSONDecodeError, KeyError):
        return []


# ---------------------------------------------------------------------------
# 4. Shodan InternetDB (free tier — passive, no API key needed)
# ---------------------------------------------------------------------------

def _shodan_internetdb(ip: str) -> Optional[dict[str, Any]]:
    """Query Shodan InternetDB for passive port/service fingerprinting (no API key)."""
    url = f"https://internetdb.shodan.io/{ip}"
    body = _http_get(url, timeout=10)
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# 5. Carrier Recon Engine
# ---------------------------------------------------------------------------

class CarrierRecon:
    """Passive recon engine for a single carrier profile."""

    def __init__(self, carrier: CarrierProfile):
        self.carrier = carrier
        self.results: dict[str, Any] = {
            "carrier": carrier.to_dict(),
            "timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "ct_logs": {},
            "dns": {},
            "bgp": {},
            "shodan_passive": {},
        }

    def _parent_domain(self) -> str:
        """Extract parent domain from SIP trunk or GRX node."""
        for source in [self.carrier.sipTrunk, self.carrier.grxNode]:
            if source:
                parts = source.split(".")
                if len(parts) >= 2:
                    return ".".join(parts[-2:])
        return ""

    # ---- Surface runners ----

    def run_ct(self) -> dict[str, Any]:
        """Certificate Transparency enumeration and subdomain classification."""
        domain = self._parent_domain()
        if not domain:
            return {"error": "no parent domain derivable from carrier profile"}

        print(f"  [recon] CT logs for *.{domain}...", flush=True)
        entries = _ct_search(domain)

        services: dict[str, list[str]] = {
            "sip": [], "grx": [], "diameter": [], "ss7": [],
            "sbc": [], "cdr": [], "hadoop": [], "kafka": [],
            "mgmt": [], "other": [],
        }
        for e in entries:
            name = e["name"]
            if "sip" in name or "voip" in name:
                services["sip"].append(name)
            elif "grx" in name or "ipx" in name:
                services["grx"].append(name)
            elif "diameter" in name or "dra" in name or "dea" in name:
                services["diameter"].append(name)
            elif "ss7" in name or "sigtran" in name or "stp" in name:
                services["ss7"].append(name)
            elif "sbc" in name or "session" in name:
                services["sbc"].append(name)
            elif "cdr" in name or "mediation" in name or "billing" in name:
                services["cdr"].append(name)
            elif "hadoop" in name or "hdfs" in name:
                services["hadoop"].append(name)
            elif "kafka" in name:
                services["kafka"].append(name)
            elif "mgmt" in name or "admin" in name or "manage" in name:
                services["mgmt"].append(name)
            else:
                services["other"].append(name)

        return {
            "domain": domain,
            "total_certs": len(entries),
            "unique_names": sum(len(v) for v in services.values()),
            "services": {k: v[:30] for k, v in services.items() if v},
            "sample_certs": entries[:10],
        }

    def run_dns(self) -> dict[str, Any]:
        """Resolve carrier hostnames to IP addresses."""
        hostnames = [
            ("sip_trunk", self.carrier.sipTrunk),
            ("grx_node", self.carrier.grxNode),
            ("diameter_peer", self.carrier.diameterPeer),
            ("kafka_broker", self.carrier.kafkaBroker),
        ]
        results = {}
        for label, hostname in hostnames:
            if not hostname:
                continue
            print(f"  [recon] DNS {hostname}...", flush=True)
            results[label] = _dns_resolve(hostname)
        return results

    def run_bgp(self) -> dict[str, Any]:
        """BGP ASN lookup and prefix enumeration."""
        name = self.carrier.name
        print(f"  [recon] BGP search for '{name}'...", flush=True)
        asns = _bgpview_search(name)

        results: dict[str, Any] = {"asns_found": asns, "prefixes": {}}
        for asn_info in asns[:3]:
            asn = str(asn_info["asn"])
            detail = _bgpview_asn(asn)
            if detail:
                results["prefixes"][asn] = {
                    "detail": detail,
                    "prefixes": _bgpview_prefixes(asn),
                }
        return results

    def run_shodan_passive(self) -> dict[str, Any]:
        """Passive Shodan lookups on discovered IPs."""
        ips: set[str] = set()
        for host_result in self.results.get("dns", {}).values():
            ips.update(host_result.get("ipv4", []))
            ips.update(host_result.get("ipv6", []))

        if not ips:
            return {"note": "no IPs resolved from DNS — skipping Shodan"}

        results = {}
        for ip in sorted(ips)[:10]:
            print(f"  [recon] Shodan InternetDB {ip}...", flush=True)
            data = _shodan_internetdb(ip)
            if data:
                results[ip] = {
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "tags": data.get("tags", []),
                    "vulns": data.get("vulns", []),
                }
        return results

    # ---- Lifecycle ----

    def run(self, modules: Optional[list[str]] = None) -> dict[str, Any]:
        """Run all or selected recon modules."""
        modules = modules or ["ct", "dns", "bgp"]

        if "ct" in modules:
            self.results["ct_logs"] = self.run_ct()
        if "dns" in modules:
            self.results["dns"] = self.run_dns()
        if "bgp" in modules:
            self.results["bgp"] = self.run_bgp()
        if "shodan" in modules:
            self.results["shodan_passive"] = self.run_shodan_passive()

        self.results["timestamp"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        return self.results

    def write(self, output_dir: Optional[str] = None) -> str:
        """Write recon results to JSON file."""
        output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "._exploit_outputs",
        )
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(
            output_dir, f"typhoon_recon_{self.carrier.slug}.json"
        )
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(self.results, fh, indent=2, ensure_ascii=False)
        return out_path

    def print_summary(self) -> None:
        """Print a quick summary of recon results."""
        ct = self.results.get("ct_logs", {})
        dns_data = self.results.get("dns", {})
        bgp = self.results.get("bgp", {})

        print(f"\n{'='*60}")
        print(f" Typhoon Recon — {self.carrier.name} ({self.carrier.mccMnc})")
        print(f" {'='*60}")

        if "error" not in ct:
            svc = ct.get("services", {})
            print(f" CT Logs: {ct.get('total_certs', 0)} certs, "
                  f"{ct.get('unique_names', 0)} unique names")
            for k, v in sorted(svc.items()):
                if v:
                    print(f"   {k:12s}: {len(v):4d} hosts")
        else:
            print(f" CT Logs: {ct.get('error', 'skipped')}")

        print(f" DNS Resolved: {len(dns_data)} hostnames")
        for label, result in dns_data.items():
            ipv4 = result.get("ipv4", [])
            if ipv4:
                print(f"   {label:20s}: {', '.join(ipv4[:3])}")

        asns = bgp.get("asns_found", [])
        print(f" BGP ASNs found: {len(asns)}")
        for a in asns[:5]:
            print(f"   AS{a['asn']:>6d}  {a.get('name', '')}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Typhoon Passive Recon")
    parser.add_argument(
        "carrier", nargs="?", default="at&t",
        help="Carrier name (e.g. 'at&t', 'china-mobile')",
    )
    parser.add_argument(
        "--json", "-j", action="store_true", help="Output JSON to stdout",
    )
    parser.add_argument(
        "--modules", "-m", default="ct,dns,bgp",
        help="Comma-separated modules: ct,dns,bgp,shodan (default: ct,dns,bgp)",
    )
    args = parser.parse_args()

    carrier = get_carrier(args.carrier)
    print(f"Typhoon Passive Recon: {carrier.name} ({carrier.mccMnc})")
    print("=" * 60)

    recon = CarrierRecon(carrier)
    modules = [m.strip() for m in args.modules.split(",")]
    results = recon.run(modules=modules)

    out_path = recon.write()
    recon.print_summary()
    print(f"\nArtifact: {out_path}")

    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
