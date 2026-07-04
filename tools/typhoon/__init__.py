#!/usr/bin/env python3
"""
Typhoon — Autonomous Telecom Carrier Security Audit Framework

Protocol Surfaces:
  ss7          — SS7/MAP/ISUP/SCCP (2G/3G signaling)
  sip          — SIP/VoIP/RTP/SBC (VoLTE/VoWiFi)
  diameter     — Diameter/GTP-C/GTP-U (4G/5G roaming)
  telecom_data — Lawful Intercept / CDR / Hadoop / Kafka

Zero external dependencies. Output: structured JSON audit artifact.

Usage:
    python3 -m tools.typhoon at&t           # audit AT&T Mobility
    python3 -m tools.typhoon --carrier tmobile  # audit T-Mobile US
    python3 -m tools.typhoon --surface ss7 at&t # SS7-only audit
"""

__version__ = "1.0.0"
__author__ = "Vigil CNE / Trenchwork"
__all__ = ["core", "ss7", "sip", "diameter", "telecom_data", "carriers", "cli"]
