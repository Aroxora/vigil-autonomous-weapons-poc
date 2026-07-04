#!/usr/bin/env python3
"""
Typhoon Core — Audit Engine, Finding Registry, Carrier Profiles

Orchestrates protocol-surface audits, collects findings into structured
registry, and emits the final audit artifact (JSON).
Zero external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional, Union

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SURFACES = [
    "ss7", "sip-voip", "diameter", "grx-ipx",
    "lawful-intercept", "cdr-metadata",
    "cip-enip", "canbus", "bgp-hijack",
]

ATTACK_TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Exploitation for Client Execution",
    "T1213": "Data from Information Repositories",
    "T1498": "Network Denial of Service",
    "T1530": "Data from Cloud Storage",
    "T1557.001": "LLMNR/NBT-NS Poisoning and Relay",
    "T1562.004": "Disable or Modify System Firewall",
    "T1588.001": "Obtain Capabilities: Malware",
    "T1596.001": "Search Open Technical Databases: DNS/Passive DNS",
    "T1552": "Unsecured Credentials",
}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single audit finding — maps 1:1 to the existing typhoon schema."""

    id: str
    surface: str
    severity: str  # critical | high | medium | low
    protocol: str
    attackTcode: str
    title: str
    description: str
    tools: list[str] = field(default_factory=list)
    exploitationMethod: str = ""
    counter: str = ""
    vigilTool: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 99)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Countermeasure
# ---------------------------------------------------------------------------

@dataclass
class Countermeasure:
    surface: str
    priority: str  # critical | high
    estimatedFixTime: str
    recommendation: str
    vigilCommand: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Carrier Profile
# ---------------------------------------------------------------------------

@dataclass
class CarrierProfile:
    """Carrier-specific configuration for audit targeting."""

    name: str  # e.g. "AT&T Mobility"
    country: str  # ISO 3166-1 alpha-2
    mccMnc: str  # e.g. "310-410"
    ss7Gt: str = ""  # SS7 global title
    sipTrunk: str = ""  # SIP trunk domain
    grxNode: str = ""  # GRX node hostname
    diameterPeer: str = ""  # Diameter peer hostname
    lawfulInterceptVendor: str = ""  # LI vendor (Utimaco, SS8, etc.)
    cdrMediationVendor: str = ""  # CDR mediation (Amdocs, Ericsson, etc.)
    hadoopCluster: str = ""  # Hadoop cluster name
    kafkaBroker: str = ""  # Kafka broker hostname

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def slug(self) -> str:
        return self.name.lower().replace(" ", "-").replace("&", "and")

    @property
    def profile_id(self) -> str:
        return f"{self.slug}-{self.mccMnc.replace('-', '')}"


# ---------------------------------------------------------------------------
# Audit Engine
# ---------------------------------------------------------------------------

class AuditEngine:
    """Orchestrates protocol-surface audits and collects findings."""

    def __init__(self, carrier: CarrierProfile, output_dir: Optional[str] = None):
        self.carrier = carrier
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", "..",
            "._exploit_outputs",
        )
        self.findings: list[Finding] = []
        self.counters: list[Countermeasure] = []
        self._run_id = self._generate_run_id()
        self._started_at: Optional[str] = None
        self._completed_at: Optional[str] = None

    # ---- Run id ----------------------------------------------------------

    @staticmethod
    def _generate_run_id() -> str:
        return f"TA-{hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:12]}"

    # ---- Surface runners -------------------------------------------------

    def run_ss7(self) -> list[Finding]:
        """Run SS7 protocol audit. Imported lazily to avoid circular deps."""
        from tools.typhoon.ss7 import audit_ss7
        return audit_ss7(self.carrier, self._run_id)

    def run_sip(self) -> list[Finding]:
        from tools.typhoon.sip import audit_sip
        return audit_sip(self.carrier, self._run_id)

    def run_diameter(self) -> list[Finding]:
        from tools.typhoon.diameter import audit_diameter
        return audit_diameter(self.carrier, self._run_id)

    def run_telecom_data(self) -> list[Finding]:
        from tools.typhoon.telecom_data import audit_telecom_data
        return audit_telecom_data(self.carrier, self._run_id)

    def run_cip(self) -> list[Finding]:
        from tools.typhoon.cip import audit_cip
        return audit_cip(self.carrier, self._run_id)

    def run_canbus(self) -> list[Finding]:
        from tools.typhoon.canbus import audit_canbus
        return audit_canbus(self.carrier, self._run_id)

    def run_bgp(self) -> list[Finding]:
        from tools.typhoon.bgp import audit_bgp
        return audit_bgp(self.carrier, self._run_id)

    # ---- Lifecycle --------------------------------------------------------

    # ---- Recon & Scan integration ---------------------------------------

    def run_recon(self) -> dict[str, Any]:
        """Run passive recon for this carrier. Returns recon artifact."""
        from tools.typhoon.recon import CarrierRecon
        recon = CarrierRecon(self.carrier)
        return recon.run()

    def run_scan(self, dry_run: bool = True) -> dict[str, Any]:
        """Run active protocol scan for this carrier. Returns scan artifact."""
        from tools.typhoon.scan import ProtocolScanner
        scanner = ProtocolScanner(self.carrier, dry_run=dry_run)
        scanner.plan()
        if not dry_run:
            scanner.execute()
        return scanner.to_dict()

    # ---- Lifecycle --------------------------------------------------------

    def run(self, surfaces: Optional[list[str]] = None, with_recon: bool = False,
            with_scan: bool = False, scan_active: bool = False) -> dict[str, Any]:
        """Execute full or partial audit. Returns the audit artifact dict.

        Args:
            surfaces: Protocol surfaces to audit (None = all).
            with_recon: Run passive OSINT recon before audit.
            with_scan: Run active protocol scanning before audit.
            scan_active: If True with with_scan, actually send probe packets.
        """
        self._started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        # Optional pre-audit recon
        recon_data: dict[str, Any] = {}
        if with_recon:
            try:
                recon_data = self.run_recon()
            except Exception as e:
                recon_data = {"error": str(e)}
                print(f"[typhoon] Recon failed: {e}", file=__import__("sys").stderr)

        # Optional pre-audit scan
        scan_data: dict[str, Any] = {}
        if with_scan:
            try:
                scan_data = self.run_scan(dry_run=not scan_active)
            except Exception as e:
                scan_data = {"error": str(e)}
                print(f"[typhoon] Scan failed: {e}", file=__import__("sys").stderr)

        runner_map = {
            "ss7": self.run_ss7,
            "sip-voip": self.run_sip,
            "diameter": self.run_diameter,
            "grx-ipx": self.run_diameter,
            "lawful-intercept": self.run_telecom_data,
            "cdr-metadata": self.run_telecom_data,
            "cip-enip": self.run_cip,
            "canbus": self.run_canbus,
            "bgp-hijack": self.run_bgp,
        }

        surfaces_requested = surfaces or SURFACES[:]
        already_run: set[str] = set()

        for surface in surfaces_requested:
            runner = runner_map.get(surface)
            if runner is None or surface in already_run:
                continue
            try:
                findings = runner()
                self.findings.extend(findings)
                already_run.add(surface)
                if surface == "diameter":
                    already_run.add("grx-ipx")
                elif surface == "grx-ipx":
                    already_run.add("diameter")
                elif surface == "lawful-intercept":
                    already_run.add("cdr-metadata")
                elif surface == "cdr-metadata":
                    already_run.add("lawful-intercept")
            except ImportError as e:
                print(f"[typhoon] WARNING: surface '{surface}' module not loaded: {e}", file=__import__("sys").stderr)
            except Exception as e:
                print(f"[typhoon] ERROR: surface '{surface}' audit failed: {e}", file=__import__("sys").stderr)

        self._completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self._sort_findings()
        self._generate_counters()

        artifact = self._build_artifact()
        if recon_data:
            artifact["recon"] = recon_data
        if scan_data:
            artifact["scan"] = scan_data
        return artifact

    # ---- Sort & counters --------------------------------------------------

    def _sort_findings(self) -> None:
        self.findings.sort(key=lambda f: (f.severity_rank, f.surface, f.id))

    def _generate_counters(self) -> None:
        """Generate countermeasures from findings, deduplicated by surface."""
        seen_surfaces: set[str] = set()
        for finding in self.findings:
            if finding.surface in seen_surfaces:
                continue
            seen_surfaces.add(finding.surface)

            # Extract the key recommendation from the finding's counter text
            rec = finding.counter
            # Generate a vigil CLI command from the finding's vigilTool
            cmd = self._counter_to_cli(finding)
            fix_time = self._estimate_fix_time(finding.surface)

            self.counters.append(Countermeasure(
                surface=finding.surface,
                priority=finding.severity,
                estimatedFixTime=fix_time,
                recommendation=rec,
                vigilCommand=cmd,
            ))

    @staticmethod
    def _counter_to_cli(finding: Finding) -> str:
        """Map finding to a vigil CLI countermeasure command."""
        mapping = {
            "ss7": "vigil --ss7-audit --firewall-deploy --gt-whitelist",
            "sip-voip": "vigil --sip-audit --sbc-harden --tls-enforce --srtp-enforce",
            "diameter": "vigil --diameter-audit --peer-tls --dea-harden",
            "grx-ipx": "vigil --grx-audit --gtp-firewall --diameter-tls --s8hr-enforce",
            "lawful-intercept": "vigil --li-audit --mfa-enforce --psk-rotate --hi-auth",
            "cdr-metadata": "vigil --cdr-audit --sql-fix --hadoop-kerberos --kafka-sasl",
        }
        return mapping.get(finding.surface, f"vigil --audit --surface {finding.surface}")

    @staticmethod
    def _estimate_fix_time(surface: str) -> str:
        mapping = {
            "ss7": "2-4 weeks",
            "sip-voip": "1-3 weeks",
            "diameter": "3-6 weeks",
            "grx-ipx": "3-6 weeks",
            "lawful-intercept": "4-8 weeks",
            "cdr-metadata": "2-6 weeks",
        }
        return mapping.get(surface, "2-8 weeks")

    # ---- Artifact builder -------------------------------------------------

    def _build_artifact(self) -> dict[str, Any]:
        critical_count = sum(1 for f in self.findings if f.severity == "critical")
        high_count = sum(1 for f in self.findings if f.severity == "high")

        return {
            "audit": {
                "id": self._run_id,
                "target": self.carrier.to_dict(),
                "timestamp": self._started_at or "",
                "completedAt": self._completed_at or "",
                "findings": [f.to_dict() for f in self.findings],
                "criticalCount": critical_count,
                "highCount": high_count,
                "totalCount": len(self.findings),
                "surfacesAudited": sorted(set(f.surface for f in self.findings)),
                "summary": (
                    f"Typhoon telecom audit of {self.carrier.name}: "
                    f"{len(self.findings)} findings across "
                    f"{len(set(f.surface for f in self.findings))} attack surfaces. "
                    f"{critical_count} critical, {high_count} high."
                ),
            },
            "counters": [c.to_dict() for c in self.counters],
            "metadata": {
                "framework": "Typhoon",
                "version": "1.0.0",
                "generatedBy": "Vigil CNE / Trenchwork",
            },
        }

    # ---- I/O --------------------------------------------------------------

    def write_artifact(self, artifact: Optional[dict[str, Any]] = None) -> str:
        """Write the audit artifact to JSON file. Returns the file path."""
        if artifact is None:
            artifact = self._build_artifact()

        os.makedirs(self.output_dir, exist_ok=True)
        out_path = os.path.join(
            self.output_dir,
            f"typhoon_{self.carrier.slug}_{self._run_id}.json",
        )
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(artifact, fh, indent=2, ensure_ascii=False)
        print(f"[typhoon] Audit artifact written to {out_path}")
        return out_path

    def print_summary(self) -> None:
        """Print a quick summary to stdout."""
        crit = sum(1 for f in self.findings if f.severity == "critical")
        high = sum(1 for f in self.findings if f.severity == "high")
        print(f"\n{'='*60}")
        print(f" Typhoon Audit — {self.carrier.name} ({self.carrier.mccMnc})")
        print(f" Run ID: {self._run_id}")
        print(f" {'='*60}")
        print(f" Surfaces audited: {sorted(set(f.surface for f in self.findings))}")
        print(f" Total findings:   {len(self.findings)} ({crit} critical, {high} high)")
        print(f" {'='*60}\n")
        for f in self.findings:
            if f.severity in ("critical", "high"):
                print(f"  [{f.severity.upper():8s}] {f.surface:20s} {f.title}")


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from tools.typhoon.carriers import get_carrier

    import sys
    carrier_name = sys.argv[1] if len(sys.argv) > 1 else "at&t"
    carrier = get_carrier(carrier_name)
    engine = AuditEngine(carrier)
    artifact = engine.run()
    engine.print_summary()
    engine.write_artifact(artifact)
