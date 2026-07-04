#!/usr/bin/env python3
"""
Typhoon CIP/ENIP Protocol Audit Module

Covers Common Industrial Protocol / EtherNet/IP attack surfaces:
  - CIP Authentication Bypass (CVE-2021-22681 shared private key)
  - EtherNet/IP Port 44818 Unauthenticated Session Registration
  - CIP Forward Open without authentication (tag read/write)
  - Firmware download without integrity check (malicious ladder logic)
  - CIP CPU mode change without authorization (Run→Program)
  - CIP symbol table extraction (tag database enumeration)
  - CIP connection flood (denial of service via Forward Open)
"""

from __future__ import annotations

from typing import Any

from tools.typhoon.core import CarrierProfile, Finding


def _f(
    run_id: str,
    seq: str,
    surface: str,
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
    return Finding(
        id=f"CIP-{run_id}-{seq}",
        surface=surface,
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


def audit_cip(carrier: CarrierProfile, run_id: str) -> list[Finding]:
    """Generate CIP/ENIP audit findings for the given carrier profile."""
    findings: list[Finding] = []

    # ---- CIP Authentication Bypass (CVE-2021-22681) ----
    findings.append(_f(
        run_id, "a701",
        surface="cip-enip",
        severity="critical",
        protocol="CIP/ENIP",
        attack_tcode="T0859",
        title="CIP Authentication Bypass — Shared Private Key (CVE-2021-22681)",
        description=(
            "CVE-2021-22681: Rockwell Automation ControlLogix and CompactLogix "
            "controllers share a hard-coded private key across all devices for "
            "CIP Security authentication. An attacker who extracts this key from "
            "any single controller can authenticate to all Rockwell controllers "
            "worldwide, bypassing CIP Security protections entirely."
        ),
        tools=[
            "Wireshark ENIP Dissector",
            "pycomm3",
            "cpppo (EtherNet/IP Python Library)",
            "CIP Security Key Extractor (Metasploit module)",
            "EtherNet/IP Protocol Analyzer",
        ],
        exploitation=(
            "Extract hard-coded RSA private key from any Rockwell controller "
            "firmware (publicly available since 2021) → use key to authenticate "
            "to target controller via CIP Security handshake → gain full "
            "controller access bypassing all CIP Security authentication."
        ),
        counter=(
            "Apply Rockwell firmware patch that replaces shared private key with "
            "per-device unique key material. Deploy CIP Security with unique "
            "certificates per controller. Segment OT network from IT/IT networks. "
            "Monitor CIP Security handshake failures for authentication bypass "
            "attempts."
        ),
        vigil_tool="typhoon.cip.authBypassAudit()",
    ))

    # ---- EtherNet/IP Port 44818 Exposure ----
    findings.append(_f(
        run_id, "b812",
        surface="cip-enip",
        severity="critical",
        protocol="EtherNet/IP",
        attack_tcode="T0859",
        title="EtherNet/IP Port 44818 Exposure — Unauthenticated Session Registration",
        description=(
            "EtherNet/IP TCP port 44818 is exposed on the OT network without "
            "authentication requirements. Attackers can register a CIP session "
            "(RegisterSession request) without any credentials, establishing a "
            "valid session handle for subsequent Forward Open commands to read "
            "and write controller tags."
        ),
        tools=[
            "nmap --script enip-info",
            "pycomm3 CIPDriver",
            "cpppo.enip",
            "EtherNet/IP Session Registration Tool",
            "Wireshark ENIP Filter (enip.session)",
        ],
        exploitation=(
            "Scan OT subnet for TCP/44818 → send RegisterSession request to "
            "discovered controllers → receive valid session handle → use session "
            "to issue Forward Open and tag read/write operations → extract "
            "process data, modify setpoints, or alter safety parameters."
        ),
        counter=(
            "Deploy CIP Security with authentication enabled. Segment OT network "
            "behind industrial firewalls with explicit allow lists. Monitor "
            "RegisterSession requests and alert on sessions from unauthorized IP "
            "addresses. Implement 802.1X network access control on all OT switch "
            "ports."
        ),
        vigil_tool="typhoon.cip.port44818Audit()",
    ))

    # ---- CIP Forward Open Without Authentication ----
    findings.append(_f(
        run_id, "c923",
        surface="cip-enip",
        severity="critical",
        protocol="CIP/ENIP",
        attack_tcode="T0855",
        title="CIP Forward Open Without Authentication — Unauthorized Tag Read/Write",
        description=(
            "CIP Forward Open service allows reading and writing controller tags "
            "(process variables, setpoints, safety parameters) without any "
            "authentication or authorization checks. Once a CIP session is "
            "established on port 44818, any tag in the controller's symbol table "
            "is accessible for read and write operations."
        ),
        tools=[
            "pycomm3 (read_tag / write_tag)",
            "cpppo (read/write CIP tags)",
            "EtherNet/IP CIP Client",
            "custom Python CIP stack",
        ],
        exploitation=(
            "Establish unauthenticated CIP session via RegisterSession → enumerate "
            "symbol table for tag names (see CIP-*-d134) → issue Forward Open "
            "with tag name and connection parameters → issue Read Tag or Write "
            "Tag service → modify critical process parameters (motor speeds, "
            "valve positions, safety interlocks) or exfiltrate proprietary "
            "process recipes."
        ),
        counter=(
            "Enable CIP Security authentication and authorization. Implement "
            "tag-level access control (read-only vs read-write per session). "
            "Deploy controller audit logging for all Forward Open and tag write "
            "operations. Segment OT network and enforce least-privilege CIP "
            "access."
        ),
        vigil_tool="typhoon.cip.forwardOpenAudit()",
    ))

    # ---- Firmware Download Without Integrity Check ----
    findings.append(_f(
        run_id, "d134",
        surface="cip-enip",
        severity="critical",
        protocol="CIP/ENIP",
        attack_tcode="T0843",
        title="Firmware Download Without Integrity Check — Malicious Ladder Logic Upload",
        description=(
            "Controller firmware download via CIP services lacks mandatory "
            "cryptographic integrity verification. An attacker with CIP session "
            "access can upload modified ladder logic containing malicious rungs "
            "(e.g., logic bombs, data exfiltration triggers, safety override "
            "logic) that executes with full controller authority."
        ),
        tools=[
            "Rockwell RSLogix 5000",
            "Studio 5000 Logix Designer",
            "pycomm3 firmware download utilities",
            "CIP Firmware Injection Framework",
            "PLC Ladder Logic Disassembler",
        ],
        exploitation=(
            "Authenticate or bypass CIP session → use CIP Download service to "
            "transfer modified firmware/ladder logic binary → no integrity "
            "verification performed by controller → modified logic executes on "
            "next controller scan cycle → attacker logic runs alongside or "
            "replaces legitimate control program."
        ),
        counter=(
            "Enable controller firmware signature verification (digitally signed "
            "firmware). Implement hardware keyswitch in RUN position to block "
            "remote firmware downloads. Monitor CIP Download service requests "
            "via OT SIEM. Require physical presence and MFA for any firmware "
            "modification."
        ),
        vigil_tool="typhoon.cip.firmwareIntegrityAudit()",
    ))

    # ---- CIP CPU Mode Change Without Authorization ----
    findings.append(_f(
        run_id, "e245",
        surface="cip-enip",
        severity="critical",
        protocol="CIP/ENIP",
        attack_tcode="T0855 / T0889",
        title="CIP CPU Mode Change Without Authorization — Run→Program Mode Switching",
        description=(
            "CIP controller CPU mode (Run/Program/Remote Program) can be changed "
            "via CIP service requests without any authorization. Switching a "
            "controller from Run to Program mode halts all process control logic, "
            "disabling safety interlocks, alarm generation, and process monitoring "
            "— enabling covert physical attacks while suppressing alarms."
        ),
        tools=[
            "pycomm3 (set_plc_mode)",
            "cpppo (NOP service for mode change)",
            "EtherNet/IP Mode Switch Tool",
            "Wireshark CIP Service Filter",
        ],
        exploitation=(
            "Establish CIP session → send CIP NOP (Network Operation) service "
            "request with mode change parameter → controller transitions from "
            "RUN to PROGRAM mode → process control halts, alarms suppressed → "
            "attacker triggers physical process failure (overpressure, overspeed, "
            "overheat) while operator HMI shows no alarms."
        ),
        counter=(
            "Require controller keyswitch in REMOTE position for remote mode "
            "changes. Implement CIP Security to authenticate mode change requests. "
            "Deploy OT network monitoring for CIP NOP/mode change service codes. "
            "Configure independent safety PLC watchdog that alerts on main "
            "controller heartbeat loss."
        ),
        vigil_tool="typhoon.cip.cpuModeAudit()",
    ))

    # ---- CIP Symbol Table Extraction ----
    findings.append(_f(
        run_id, "f356",
        surface="cip-enip",
        severity="high",
        protocol="CIP/ENIP",
        attack_tcode="T0855",
        title="CIP Symbol Table Extraction — Tag Database Enumeration",
        description=(
            "CIP controllers expose their full symbol table (tag names, data "
            "types, memory addresses, and descriptions) via unauthenticated CIP "
            "services. Enumeration of the symbol table reveals all accessible "
            "process variables, safety parameters, and engineering metadata, "
            "enabling targeted attacks on critical control parameters."
        ),
        tools=[
            "pycomm3 (get_tag_list)",
            "cpppo (list_instances / symbol discovery)",
            "EtherNet/IP Tag Browser",
            "Custom CIP Symbol Enumeration Script",
        ],
        exploitation=(
            "Establish CIP session → send Get Instance List or Get Attribute All "
            "for symbol class (Class 0x6B) → controller returns complete tag "
            "database including names like SAFETY_INTERLOCK_BYPASS, "
            "REACTOR_TEMP_SETPOINT, EMERGENCY_SHUTDOWN_ACTIVE → attacker maps "
            "critical tags → targets specific tags with Forward Open write "
            "operations to disable safety systems."
        ),
        counter=(
            "Enable CIP Security to restrict symbol table access to authenticated "
            "sessions. Implement tag-level visibility restrictions (mark sensitive "
            "tags as non-browsable). Deploy controller configuration audit logging "
            "for symbol table enumeration. Segment OT network from untrusted "
            "zones."
        ),
        vigil_tool="typhoon.cip.symbolTableAudit()",
    ))

    # ---- CIP Connection Flood — DoS via Forward Open ----
    findings.append(_f(
        run_id, "g467",
        surface="cip-enip",
        severity="high",
        protocol="EtherNet/IP",
        attack_tcode="T0814",
        title="CIP Connection Flood — Denial of Service via Excessive Forward Open",
        description=(
            "CIP controllers have a limited number of CIP connections (typically "
            "32-256 depending on model). An attacker can exhaust all available "
            "connections by sending rapid Forward Open requests without ever "
            "closing them, preventing legitimate SCADA/DCS systems from "
            "communicating with the controller and causing process control loss."
        ),
        tools=[
            "cpppo (Forward Open flood)",
            "pycomm3 (connection stress test)",
            "EtherNet/IP Fuzzer",
            "Custom CIP Connection Exhaustion Script",
        ],
        exploitation=(
            "Establish CIP session → send rapid succession of Forward Open "
            "requests for various tags → each request consumes one CIP connection "
            "slot → continue until controller connection table is exhausted → "
            "legitimate HMI/SCADA requests fail with connection refused → "
            "operators lose visibility and control of the process."
        ),
        counter=(
            "Implement CIP connection rate limiting at the controller or "
            "industrial firewall. Deploy per-IP connection quotas. Monitor CIP "
            "connection table utilization and alert on rapid connection growth. "
            "Configure controller to prioritize existing connections and reject "
            "excessive new Forward Open requests from untrusted sources."
        ),
        vigil_tool="typhoon.cip.connectionFloodAudit()",
    ))

    return findings
