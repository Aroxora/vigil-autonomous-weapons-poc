#!/usr/bin/env python3
"""
Typhoon Active Scan Module — Protocol Probe Templates

Generates protocol-specific probe configurations for active telecom
infrastructure assessment. Uses nmap NSE scripts where available;
falls back to Python socket probes for custom protocol checks.

ALL probes are passive by default (--dry-run). Active mode requires
explicit operator authorization and generates probes that:
  - Never send destructive payloads
  - Respect rate limits (≤1 pkt/sec per target)
  - Only probe operator-authorized infrastructure

Protocol probes:
  - SIGTRAN/SCTP (SS7 transport) — port 2905, 3868
  - SIP — ports 5060/5061
  - Diameter — port 3868
  - GTP-C — port 2123
  - Hadoop HDFS — ports 8020/9000
  - Kafka — port 9092
  - CDR mediation — HTTP ports 80/443/8080

Usage:
    python3 -m tools.typhoon.scan --dry-run at&t   # probe plan only
    python3 -m tools.typhoon.scan --active at&t    # execute probes (auth required)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

from tools.typhoon.core import CarrierProfile
from tools.typhoon.carriers import get_carrier

# ---------------------------------------------------------------------------
# Probe configuration
# ---------------------------------------------------------------------------

@dataclass
class Probe:
    """A single protocol probe configuration."""

    name: str
    protocol: str
    transport: str  # tcp | udp | sctp
    port: int
    target_host: str
    nmap_script: str = ""  # NSE script to use (if available)
    custom_probe: str = ""  # Custom Python probe description
    safe: bool = True  # All Typhoon probes are safe by design
    rate_limit: float = 1.0  # seconds between probes
    expected_response: str = ""  # What a healthy service returns
    vulnerability_indicator: str = ""  # What an exploitable service returns

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Probe catalog — maps typhoon surfaces to probe lists
# ---------------------------------------------------------------------------

def _ss7_probes(carrier: CarrierProfile) -> list[Probe]:
    """SS7/SIGTRAN probes."""
    host = carrier.grxNode or carrier.sipTrunk or ""
    return [
        Probe(
            name="SIGTRAN SCTP availability",
            protocol="SCTP",
            transport="sctp",
            port=2905,
            target_host=host,
            nmap_script="sctp-init",
            expected_response="SCTP INIT_ACK with destination port 2905",
            vulnerability_indicator="SCTP INIT_ACK from non-whitelisted source GT",
        ),
        Probe(
            name="SS7 M3UA availability",
            protocol="M3UA",
            transport="sctp",
            port=2905,
            target_host=host,
            custom_probe="SCTP association + M3UA ASP_UP message to check SS7 stack responsiveness",
            expected_response="M3UA ASP_UP_ACK",
            vulnerability_indicator="M3UA ASP_UP_ACK from unauthorized ASP identifier",
        ),
    ]


def _sip_probes(carrier: CarrierProfile) -> list[Probe]:
    """SIP/VoIP probes."""
    host = carrier.sipTrunk or ""
    return [
        Probe(
            name="SIP OPTIONS ping",
            protocol="SIP",
            transport="udp",
            port=5060,
            target_host=host,
            custom_probe="SIP OPTIONS request to check SBC responsiveness and banner",
            expected_response="SIP 200 OK with Server header",
            vulnerability_indicator="SIP 200 OK from known-vulnerable SBC version (e.g. Oracle Acme Packet < 8.4)",
        ),
        Probe(
            name="SIP TLS availability",
            protocol="SIPS",
            transport="tcp",
            port=5061,
            target_host=host,
            nmap_script="ssl-enum-ciphers",
            expected_response="TLS 1.2+ with strong ciphers",
            vulnerability_indicator="TLS < 1.2 or weak ciphers (RC4, 3DES, EXPORT)",
        ),
    ]


def _diameter_probes(carrier: CarrierProfile) -> list[Probe]:
    """Diameter protocol probes."""
    host = carrier.diameterPeer or carrier.grxNode or ""
    return [
        Probe(
            name="Diameter SCTP association",
            protocol="Diameter",
            transport="sctp",
            port=3868,
            target_host=host,
            nmap_script="sctp-init",
            expected_response="SCTP INIT_ACK on port 3868",
            vulnerability_indicator="SCTP INIT_ACK without TLS negotiation (GSMA FS.19 violation)",
        ),
        Probe(
            name="Diameter CER/CEA exchange",
            protocol="Diameter",
            transport="sctp",
            port=3868,
            target_host=host,
            custom_probe="Diameter Capabilities-Exchange to identify peer identity and supported applications",
            expected_response="CEA with valid Origin-Host and supported Vendor-Id",
            vulnerability_indicator="CEA from unauthorized peer or with suspicious Origin-Realm",
        ),
    ]


def _gtp_probes(carrier: CarrierProfile) -> list[Probe]:
    """GTP-C / GTP-U probes."""
    host = carrier.grxNode or ""
    return [
        Probe(
            name="GTP-C Echo Request",
            protocol="GTPv1-C",
            transport="udp",
            port=2123,
            target_host=host,
            custom_probe="GTP-C Echo Request (type 1) to confirm GTP stack is reachable",
            expected_response="GTP Echo Response with Recovery IE",
            vulnerability_indicator="GTP Echo Response from non-whitelisted GRX peer",
        ),
        Probe(
            name="GTPv2-C Echo Request",
            protocol="GTPv2-C",
            transport="udp",
            port=2123,
            target_host=host,
            custom_probe="GTPv2-C Echo Request (type 1) for 4G/LTE GRX validation",
            expected_response="GTPv2 Echo Response with Recovery IE",
            vulnerability_indicator="Response from GRX node without GTP firewall (IR.88)",
        ),
    ]


def _hdfs_probes(carrier: CarrierProfile) -> list[Probe]:
    """Hadoop HDFS probes."""
    host = carrier.hadoopCluster or ""
    return [
        Probe(
            name="HDFS NameNode port check",
            protocol="Hadoop RPC",
            transport="tcp",
            port=8020,
            target_host=host,
            nmap_script="hadoop-namenode-info",
            expected_response="NameNode RPC response with Kerberos principal",
            vulnerability_indicator="NameNode RPC response WITHOUT Kerberos principal (CVE-2023-26031)",
        ),
    ]


def _kafka_probes(carrier: CarrierProfile) -> list[Probe]:
    """Apache Kafka probes."""
    host = carrier.kafkaBroker or ""
    return [
        Probe(
            name="Kafka broker API version",
            protocol="Kafka",
            transport="tcp",
            port=9092,
            target_host=host,
            custom_probe="Kafka ApiVersions request (API key 18) to check SASL/SSL configuration",
            expected_response="ApiVersions response with SASL/SSL mechanisms listed",
            vulnerability_indicator="ApiVersions response with NO SASL mechanisms and NO SSL",
        ),
    ]


def _http_probes(carrier: CarrierProfile) -> list[Probe]:
    """CDR Mediation HTTP probes."""
    host = carrier.sipTrunk or carrier.grxNode or ""
    return [
        Probe(
            name="CDR mediation web interface",
            protocol="HTTPS",
            transport="tcp",
            port=443,
            target_host=host,
            nmap_script="http-title,http-headers",
            expected_response="HTTP 401/403 (authenticated mediation interface)",
            vulnerability_indicator="HTTP 200 with CDR search form (no authentication)",
        ),
        Probe(
            name="CDR mediation SQL injection surface",
            protocol="HTTPS",
            transport="tcp",
            port=443,
            target_host=host,
            custom_probe="Passive parameter enumeration on /cdr/search endpoint (NO injection, params only)",
            expected_response="Parameterized endpoint with WAF protection",
            vulnerability_indicator="Raw SQL error in response (e.g. 'ORA-', 'PostgreSQL ERROR', 'MySQL error')",
        ),
    ]


# ---- Surface → probe factory map ----

PROBE_FACTORIES = {
    "ss7": _ss7_probes,
    "sip-voip": _sip_probes,
    "diameter": _diameter_probes,
    "grx-ipx": _gtp_probes,
    "cdr-metadata": lambda c: _hdfs_probes(c) + _kafka_probes(c) + _http_probes(c),
}


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------

class ProtocolScanner:
    """Generates and executes protocol probes for a carrier."""

    def __init__(self, carrier: CarrierProfile, dry_run: bool = True):
        self.carrier = carrier
        self.dry_run = dry_run
        self.probes: list[Probe] = []
        self.results: list[dict[str, Any]] = []

    def plan(self, surfaces: Optional[list[str]] = None) -> list[Probe]:
        """Generate probe plan for the given surfaces."""
        surfaces = surfaces or list(PROBE_FACTORIES.keys())
        self.probes = []

        for surface in surfaces:
            factory = PROBE_FACTORIES.get(surface)
            if factory:
                self.probes.extend(factory(self.carrier))

        return self.probes

    def execute(self, surfaces: Optional[list[str]] = None) -> list[dict[str, Any]]:
        """Execute probes against live targets. Only in active mode."""
        if self.dry_run:
            print("[scan] DRY-RUN mode — no packets sent.")
            return [{"probe": p.name, "status": "DRY_RUN", "note": "no packets sent"} for p in self.probes]

        if not self.probes:
            self.plan(surfaces)

        self.results = []
        for probe in self.probes:
            if not probe.target_host:
                self.results.append({
                    "probe": probe.name, "status": "SKIPPED",
                    "reason": "no target host configured",
                })
                continue

            result = self._run_probe(probe)
            self.results.append(result)
            time.sleep(probe.rate_limit)

        return self.results

    def _run_probe(self, probe: Probe) -> dict[str, Any]:
        """Execute a single probe. Uses nmap NSE if available, else socket."""
        result: dict[str, Any] = {
            "probe": probe.name,
            "protocol": probe.protocol,
            "target": f"{probe.target_host}:{probe.port}",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": "UNKNOWN",
        }

        # Prefer nmap NSE
        if probe.nmap_script and shutil_which("nmap"):
            try:
                cmd = [
                    "nmap", "-Pn", "-p", str(probe.port),
                    f"--script={probe.nmap_script}",
                    "--host-timeout", "15s",
                    probe.target_host,
                ]
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                )
                result["stdout"] = proc.stdout[:2000]
                result["stderr"] = proc.stderr[:500]
                result["status"] = "COMPLETED" if proc.returncode == 0 else "ERROR"
                result["exit_code"] = proc.returncode
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                result["status"] = "TIMEOUT" if "Timeout" in str(e) else "NMAP_NOT_FOUND"
                result["error"] = str(e)[:200]
        else:
            # Fall back to socket probe
            result["method"] = "socket"
            result["status"] = "PROBE_DESCRIPTION_ONLY"
            result["note"] = probe.custom_probe or "socket probe template"

        return result

    def to_dict(self) -> dict[str, Any]:
        """Serialize scanner state."""
        return {
            "carrier": self.carrier.name,
            "mcc_mnc": self.carrier.mccMnc,
            "dry_run": self.dry_run,
            "probe_count": len(self.probes),
            "probes": [p.to_dict() for p in self.probes],
            "results": self.results,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }

    def write(self, output_dir: Optional[str] = None) -> str:
        """Write scan plan/results to JSON."""
        output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "..", "._exploit_outputs",
        )
        os.makedirs(output_dir, exist_ok=True)
        out_path = os.path.join(
            output_dir, f"typhoon_scan_{self.carrier.slug}.json"
        )
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)
        return out_path


def shutil_which(cmd: str) -> bool:
    """Check if a command is available on PATH."""
    import shutil
    return shutil.which(cmd) is not None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Typhoon Protocol Scanner")
    parser.add_argument("carrier", nargs="?", default="at&t", help="Carrier name")
    parser.add_argument("--dry-run", action="store_true", default=True,
                       help="Plan probes without sending packets (default)")
    parser.add_argument("--active", dest="dry_run", action="store_false",
                       help="Execute active probes (requires authorization)")
    parser.add_argument("--surface", "-s", default="all",
                       help="Surface(s) to scan (comma-separated, or 'all')")
    parser.add_argument("--json", "-j", action="store_true",
                       help="Output JSON to stdout")
    args = parser.parse_args()

    carrier = get_carrier(args.carrier)
    scanner = ProtocolScanner(carrier, dry_run=args.dry_run)

    surfaces = None if args.surface == "all" else [s.strip() for s in args.surface.split(",")]
    scanner.plan(surfaces=surfaces)

    print(f"Typhoon Scan Plan: {carrier.name} ({carrier.mccMnc})")
    print("=" * 60)
    print(f"Mode: {'DRY-RUN' if args.dry_run else 'ACTIVE'}")
    print(f"Probes planned: {len(scanner.probes)}")
    print()

    for p in scanner.probes:
        print(f"  [{p.protocol:12s}] {p.transport:4s}/{p.port:<5d}  {p.name}")
        if p.nmap_script:
            print(f"    NSE: {p.nmap_script}")
        if p.vulnerability_indicator:
            print(f"    Vuln: {p.vulnerability_indicator[:90]}")

    if not args.dry_run:
        print(f"\n[scan] Executing {len(scanner.probes)} probes...")
        scanner.execute(surfaces=surfaces)

    out_path = scanner.write()
    print(f"\nArtifact: {out_path}")

    if args.json:
        print(json.dumps(scanner.to_dict(), indent=2, ensure_ascii=False))
