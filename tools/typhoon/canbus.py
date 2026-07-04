#!/usr/bin/env python3
"""
Typhoon CAN Bus / CANopen / J1939 Protocol Audit Module

Covers vehicle and industrial control CAN bus attack surfaces:
  - CAN bus frame injection via OBD-II port — unauthorized diagnostic commands
  - CANopen heartbeat manipulation — node guarding bypass
  - J1939 DM1 diagnostic message spoofing — fake fault codes to trigger shutdown
  - CAN bus denial of service via high-priority frame flood (arbitration ID 0x000)
  - CANopen SDO read of restricted objects — unauthorized configuration access
  - J1939 address claiming conflict — source address injection
  - CAN bus physical layer tap via auxiliary port (no encryption, no auth)

All findings are deterministic — no active probing. The audit models what
an adversary COULD do given the exposed CAN bus architecture.
"""

from __future__ import annotations

from typing import Any

from tools.typhoon.core import CarrierProfile, Finding


# ---------------------------------------------------------------------------
# CAN Findings Factory
# ---------------------------------------------------------------------------

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
    """Factory to keep CAN bus findings DRY and consistent."""
    return Finding(
        id=f"CAN-{run_id}-{seq}",
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


# ---------------------------------------------------------------------------
# CAN Bus Audit
# ---------------------------------------------------------------------------

def audit_canbus(carrier: CarrierProfile, run_id: str) -> list[Finding]:
    """Generate CAN bus / CANopen / J1939 audit findings."""
    findings: list[Finding] = []

    # ---- CAN Bus Frame Injection via OBD-II Port ----
    findings.append(_f(
        run_id, "0001",
        surface="canbus",
        severity="critical",
        protocol="CAN",
        attack_tcode="T0855",
        title="CAN Bus Frame Injection via OBD-II Port — Unauthorized Diagnostic Commands",
        description=(
            f"OBD-II diagnostic port on {carrier.name} fleet vehicles exposes the "
            f"CAN bus without authentication or authorization checks. An attacker "
            f"with physical access can inject arbitrary CAN frames to issue "
            f"unauthorized diagnostic commands — including ECU reset, throttle "
            f"override, brake disable, or firmware reflash initiation — directly "
            f"onto the high-speed CAN bus (CAN-H/CAN-L, 500 kbps). The ISO 15765-4 "
            f"(CAN TP / UDS) diagnostic protocol is exposed with no session security."
        ),
        tools=[
            "cansend",
            "candump",
            "ICSpector",
            "can-utils (canplayer, cangen)",
        ],
        exploitation=(
            "Connect CAN-to-USB adapter (e.g., SocketCAN, PCAN) to OBD-II port "
            "(pins 6=CAN-H, 14=CAN-L) → use cansend to inject UDS diagnostic "
            "request frames (e.g., 0x7E0 for engine ECU) → send SecurityAccess "
            "(0x27) request → brute-force or replay known seed/key → send "
            "RoutineControl (0x31) to trigger ECU reset → inject Diagnostic "
            "Session Control (0x10) to override normal operation → flash "
            "malicious firmware via RequestDownload (0x34) / TransferData (0x36)."
        ),
        counter=(
            "Implement CAN bus authentication (AUTOSAR SecOC with fresh message "
            "authentication codes) + OBD-II port access control (physical lock, "
            "tamper-evident seal, CAN gateway firewall filtering diagnostic "
            "requests) + UDS security level enforcement (seed/key with replay "
            "protection) + cansend anomaly detection via IDS on CAN gateway."
        ),
        vigil_tool="typhoon.canbus.obd2Audit()",
    ))

    # ---- CANopen Heartbeat Manipulation — Node Guarding Bypass ----
    findings.append(_f(
        run_id, "0002",
        surface="canbus",
        severity="high",
        protocol="CANopen",
        attack_tcode="T0855",
        title="CANopen Heartbeat Manipulation — Node Guarding Bypass",
        description=(
            f"CANopen nodes on {carrier.name} industrial control networks use "
            f"heartbeat producer/consumer mechanism (COB-ID 0x700+NodeID) for "
            f"node monitoring. No message authentication is enforced. An attacker "
            f"can suppress a node's heartbeat and inject forged heartbeat messages "
            f"to trick the NMT master into believing a compromised or offline "
            f"node is still operational — enabling silent failure masking and "
            f"unauthorized persistence of compromised nodes."
        ),
        tools=[
            "cansend",
            "candump",
            "can-player",
            "ICSpector",
        ],
        exploitation=(
            "Identify target node's heartbeat COB-ID (0x700 + NodeID) via "
            "candump monitoring → flood CAN bus with higher-priority frames to "
            "cause target heartbeat loss (arbitration win) → inject forged "
            "heartbeat at correct interval (producer heartbeat time, Object "
            "0x1017) → NMT master sees node as alive → physically disconnect "
            "or compromise target node → attacker sustains forged heartbeat "
            "indefinitely → node guarding / lifeguarding fully bypassed."
        ),
        counter=(
            "CANopen message authentication (CiA 305 CANopen Safety with CRC "
            "or MAC) + heartbeat sequence numbering + NMT master multi-factor "
            "node health check (heartbeat + SDO read of Object 0x1000 device "
            "type) + heartbeat interval anomaly detection + CAN bus IDS "
            "monitoring for duplicate heartbeat sources."
        ),
        vigil_tool="typhoon.canbus.canopenHeartbeatAudit()",
    ))

    # ---- J1939 DM1 Diagnostic Message Spoofing — Fake Fault Codes ----
    findings.append(_f(
        run_id, "0003",
        surface="canbus",
        severity="critical",
        protocol="J1939",
        attack_tcode="T0855",
        title="J1939 DM1 Diagnostic Message Spoofing — Fake Fault Codes to Trigger Shutdown",
        description=(
            f"J1939 DM1 (Diagnostic Message 1, PGN 65226) on {carrier.name} "
            f"heavy-duty vehicles and industrial equipment broadcasts active "
            f"diagnostic trouble codes (DTCs) without source authentication. "
            f"An attacker can spoof DM1 messages claiming critical SPN fault "
            f"codes (e.g., SPN 190 engine speed, SPN 110 engine coolant "
            f"temperature, SPN 175 engine oil pressure) to force the engine "
            f"ECU into derate, limp-home mode, or complete shutdown — causing "
            f"vehicle immobilization or industrial process interruption."
        ),
        tools=[
            "cansend",
            "candump",
            "ICSpector",
            "J1939 DTC Decoder",
        ],
        exploitation=(
            "Determine target ECU source address (SA 0x00 for engine #1) via "
            "candump → craft J1939 DM1 message with PGN 65226, target SA, "
            "and high-severity SPN fault codes (FMI 0=high, OC=1) → transmit "
            "at periodic rate (1 Hz per J1939-73) → vehicle dash displays "
            "critical fault lamp (MIL, red stop lamp) → engine ECU derates "
            "or shuts down based on spoofed DTC severity → attacker maintains "
            "DM1 flood to prevent fault clearing → complete vehicle immobilization."
        ),
        counter=(
            "J1939 source address authentication + DM1 message integrity "
            "validation (PGN-based message authentication per SAE J1939-91) + "
            "CAN bus IDS with DTC anomaly detection (correlate DM1 claims "
            "across multiple ECUs) + redundant sensor validation before derate "
            "decision + ECU hardware root-of-trust for critical fault response."
        ),
        vigil_tool="typhoon.canbus.j1939dm1Audit()",
    ))

    # ---- CAN Bus Denial of Service via High-Priority Frame Flood ----
    findings.append(_f(
        run_id, "0004",
        surface="canbus",
        severity="critical",
        protocol="CAN",
        attack_tcode="T0814",
        title="CAN Bus Denial of Service via High-Priority Frame Flood (Arbitration ID 0x000)",
        description=(
            f"CAN bus at {carrier.name} uses non-destructive bitwise arbitration "
            f"where the lowest CAN ID wins bus access. An attacker flooding "
            f"frames with arbitration ID 0x000 (highest priority) continuously "
            f"occupies the bus, preventing all legitimate ECU communication. "
            f"This is a 100% bus utilization attack — safety-critical messages "
            f"(brake-by-wire, steer-by-wire, emergency stop) are indefinitely "
            f"blocked, causing complete vehicle or industrial control system "
            f"failure within milliseconds."
        ),
        tools=[
            "cansend",
            "cangen",
            "candump",
            "can-player",
        ],
        exploitation=(
            "Configure CAN interface (e.g., can0 at 500 kbps) → use cangen "
            "to generate continuous frames with CAN ID 0x000 and DLC=8 at "
            "maximum rate → CAN controller wins arbitration on every bit "
            "against all other ECUs → bus utilization reaches 100% → all "
            "legitimate frames experience infinite arbitration loss → ECU "
            "timeouts trigger → vehicle enters failsafe/limp mode or complete "
            "control loss → safety-critical functions (ABS, ESC, EPAS) "
            "disabled → physical damage or safety incident possible."
        ),
        counter=(
            "CAN bus IDS with bus-load anomaly detection (trigger alert at "
            ">80% utilization) + CAN gateway ingress filtering (drop frames "
            "with ID 0x000 from unauthorized sources) + bus segmentation "
            "(multiple CAN buses with gateway firewall) + time-triggered CAN "
            "(TTCAN, ISO 11898-4) with TDMA slot enforcement + CAN bus "
            "physical isolation for safety-critical subnets."
        ),
        vigil_tool="typhoon.canbus.dosAudit()",
    ))

    # ---- CANopen SDO Read of Restricted Objects ----
    findings.append(_f(
        run_id, "0005",
        surface="canbus",
        severity="high",
        protocol="CANopen",
        attack_tcode="T0884",
        title="CANopen SDO Read of Restricted Objects — Unauthorized Configuration Access",
        description=(
            f"CANopen Service Data Object (SDO) protocol on {carrier.name} "
            f"industrial controllers allows read access to all objects in the "
            f"Object Dictionary (OD) including restricted manufacturer-specific "
            f"profiles (0x2000–0x5FFF) and device profile parameters (0x6000–"
            f"0x9FFF). No SDO server-side read protection is configured. An "
            f"attacker can enumerate and exfiltrate PID tuning parameters, "
            f"safety limits, calibration data, and network configuration — "
            f"enabling subsequent targeted parameter modification attacks."
        ),
        tools=[
            "cansend",
            "candump",
            "ICSpector",
            "CANopen SDO Client",
        ],
        exploitation=(
            "Identify target node ID via heartbeat/NMT traffic → send SDO "
            "upload request (CS=0x40) for Object 0x1000 (device type) to "
            "confirm CANopen compliance → enumerate OD via SDO segmented "
            "upload for all index/sub-index ranges → extract manufacturer "
            "profile parameters (0x2000+): PID gains, max speed, torque "
            "limits → extract safety parameters: watchdog timeout, emergency "
            "stop configuration → extract network config: COB-ID mappings, "
            "node ID, baud rate → use exfiltrated parameters to craft "
            "precision attacks (modify safety limits, override PID loops, "
            "disable emergency stop)."
        ),
        counter=(
            "Implement CANopen SDO server read access restrictions (object "
            "dictionary access control list) + SDO channel encryption (CiA "
            "305 CANopen Safety) + manufacturer profile objects marked as "
            "write-only or access-restricted + SDO rate limiting + network "
            "segmentation (diagnostic CAN bus separate from control CAN bus) "
            "+ OD enumeration anomaly detection via CAN IDS."
        ),
        vigil_tool="typhoon.canbus.canopenSdoAudit()",
    ))

    # ---- J1939 Address Claiming Conflict — Source Address Injection ----
    findings.append(_f(
        run_id, "0006",
        surface="canbus",
        severity="high",
        protocol="J1939",
        attack_tcode="T0878",
        title="J1939 Address Claiming Conflict — Source Address Injection",
        description=(
            f"J1939 address claiming procedure (PGN 60928, Address Claimed) on "
            f"{carrier.name} fleet networks lacks authentication. Any node can "
            f"claim any source address (SA 0–253) by transmitting a higher-"
            f"priority NAME. An attacker can claim a safety-critical SA (e.g., "
            f"engine ECU SA 0x00, brake controller SA 0x0B, transmission SA "
            f"0x03), forcing the legitimate ECU to enter 'cannot claim address' "
            f"state and go offline — then inject malicious messages from the "
            f"hijacked source address to control actuators directly."
        ),
        tools=[
            "cansend",
            "candump",
            "ICSpector",
            "J1939 Address Claim Tool",
        ],
        exploitation=(
            "Monitor J1939 address claiming traffic (PGN 60928) via candump "
            "to identify targeted SA → craft Address Claimed message with "
            "target SA and NAME field containing highest-priority arbitrary "
            "address capable value (0x00 for industry group 0, arbitrary "
            "address capable) → transmit at 250 ms intervals → legitimate "
            "ECU receives higher-priority NAME for its own SA → enters "
            "'cannot claim address' state per J1939-81 → attacker now owns "
            "the hijacked SA → inject Torque/Speed Control (TSC1, PGN 0) or "
            "Electronic Brake Controller (EBC1, PGN 61441) messages from "
            "hijacked SA → direct actuator control without any ECU mediation."
        ),
        counter=(
            "J1939 address claiming authentication (SAE J1939-91 with message "
            "authentication) + NAME field integrity checks + static address "
            "configuration for safety-critical ECUs (disable address claiming) "
            "+ CAN bus IDS monitoring for address claiming conflicts (duplicate "
            "SA detection) + network segmentation to isolate critical ECUs on "
            "dedicated CAN buses + ECU cross-validation of command source."
        ),
        vigil_tool="typhoon.canbus.j1939addrClaimAudit()",
    ))

    # ---- CAN Bus Physical Layer Tap via Auxiliary Port ----
    findings.append(_f(
        run_id, "0007",
        surface="canbus",
        severity="critical",
        protocol="CAN",
        attack_tcode="T0855",
        title="CAN Bus Physical Layer Tap via Auxiliary Port — No Encryption, No Authentication",
        description=(
            f"CAN bus on {carrier.name} vehicles and industrial systems exposes "
            f"unencrypted, unauthenticated communication at the physical layer. "
            f"Auxiliary ports (infotainment USB, telematics unit, trailer ABS "
            f"connector, aftermarket GPS tracker port, or exposed CAN twisted "
            f"pair under dashboard) provide direct access to the CAN-H/CAN-L "
            f"differential pair. Every frame on the bus is broadcast to all "
            f"nodes in cleartext with no cryptographic protection — enabling "
            f"passive eavesdropping, traffic analysis, replay attacks, and "
            f"full bus compromise from any single physical access point."
        ),
        tools=[
            "candump",
            "cansend",
            "can-player",
            "ICSpector",
        ],
        exploitation=(
            "Locate exposed CAN bus access point (OBD-II pin 6/14, infotainment "
            "CAN gateway, telematics T-box, trailer ABS J1939 connector, or "
            "direct tap of CAN-H/CAN-L twisted pair) → connect CAN-to-USB "
            "adapter (SocketCAN, PCAN, Kvaser) → use candump to passively "
            "record all bus traffic (no authentication required to listen) → "
            "reverse-engineer CAN IDs and payload semantics via traffic analysis "
            "(frequency, value ranges, correlation with vehicle state) → use "
            "can-player to replay captured frames → use cansend to inject "
            "malicious frames → full bus compromise from a single physical "
            "tap — no encryption, no authentication, no intrusion detection."
        ),
        counter=(
            "CAN bus message authentication (AUTOSAR SecOC with AES-128 CMAC "
            "or HMAC-SHA256) + CAN frame encryption for confidentiality "
            "(AUTOSAR SecOC with optional payload encryption) + physical "
            "tamper detection on all CAN access points (tamper switches, "
            "sealed connectors) + CAN bus IDS with physical layer anomaly "
            "detection (impedance change, voltage anomaly from tap) + "
            "gateway-enforced bus segmentation to limit exposure from any "
            "single physical compromise + secure boot and hardware root-of-trust "
            "on all ECUs."
        ),
        vigil_tool="typhoon.canbus.physicalTapAudit()",
    ))

    return findings