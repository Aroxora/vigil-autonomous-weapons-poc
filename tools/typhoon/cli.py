#!/usr/bin/env python3
"""
Typhoon CLI — Telecom Carrier Security Audit Tool

Usage:
    python3 -m tools.typhoon.cli at&t              # full audit
    python3 -m tools.typhoon.cli --surface ss7 tmobile  # SS7 only
    python3 -m tools.typhoon.cli --list            # list carriers
    python3 -m tools.typhoon.cli --surface all verizon  # all surfaces
    python3 -m tools.typhoon.cli --output /path/out.json att

Zero external dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys

from tools.typhoon.core import AuditEngine
from tools.typhoon.carriers import get_carrier, list_carriers, available_carriers


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Typhoon — Autonomous Telecom Carrier Security Audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  typhoon at&t                    Full audit of AT&T Mobility (all surfaces)
  typhoon --surface ss7 tmobile   SS7-only audit of T-Mobile US
  typhoon --surface sip,ss7 verizon  SIP + SS7 audit of Verizon
  typhoon --list                  List all registered carrier profiles
  typhoon --output /tmp/out.json att  Write audit to custom path
  typhoon --json china-mobile     Output JSON to stdout
        """,
    )
    parser.add_argument(
        "carrier",
        nargs="?",
        help="Carrier name (e.g. 'at&t', 'tmobile', 'china-mobile'). Use --list to see all.",
    )
    parser.add_argument(
        "--surface", "-s",
        default="all",
        help="Surface(s) to audit: ss7, sip-voip, diameter, grx-ipx, "
             "lawful-intercept, cdr-metadata, cip-enip, canbus, "
             "bgp-hijack, or 'all' (default). "
             "Comma-separate for multiple.",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all registered carrier profiles and exit.",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Custom output path for audit JSON artifact.",
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Print audit artifact to stdout as JSON.",
    )
    parser.add_argument(
        "--recon", "-r",
        action="store_true",
        help="Run passive OSINT recon (CT logs, DNS, BGP) before audit.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run active protocol scan (dry-run) before audit.",
    )
    parser.add_argument(
        "--scan-active",
        action="store_true",
        help="Execute active probes (with --scan). Requires authorization.",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the summary table (no artifact file).",
    )

    args = parser.parse_args()

    # --list
    if args.list:
        print("\nTyphoon — Registered Carrier Profiles")
        print("=" * 60)
        for slug, name in sorted(available_carriers().items()):
            print(f"  {slug:30s} {name}")
        print()
        return

    # Carrier required
    if not args.carrier:
        parser.print_help()
        print("\nError: carrier name required (use --list to see available)")
        sys.exit(1)

    # Resolve carrier
    try:
        carrier = get_carrier(args.carrier)
    except KeyError as e:
        print(f"Error: {e}", file=sys.stderr)
        print(f"Use --list to see available carriers.", file=sys.stderr)
        sys.exit(1)

    # Resolve surfaces
    if args.surface == "all":
        surfaces = None  # engine runs all
    else:
        surfaces = [s.strip() for s in args.surface.split(",")]

    # Run audit
    print(f"[typhoon] Auditing {carrier.name} ({carrier.mccMnc})...")
    engine = AuditEngine(carrier)
    artifact = engine.run(
        surfaces=surfaces,
        with_recon=args.recon,
        with_scan=args.scan or args.scan_active,
        scan_active=args.scan_active,
    )

    # Output
    if args.json:
        print(json.dumps(artifact, indent=2, ensure_ascii=False))
    elif not args.summary_only:
        out_path = engine.write_artifact(artifact)
        if args.output:
            import shutil
            shutil.copy(out_path, args.output)
            print(f"[typhoon] Copied to {args.output}")

    engine.print_summary()


if __name__ == "__main__":
    main()
