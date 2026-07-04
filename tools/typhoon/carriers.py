#!/usr/bin/env python3
"""
Typhoon Carrier Profiles — Pre-populated telecom carrier targets.

Each profile includes:
  - MCC/MNC (Mobile Country Code / Mobile Network Code)
  - SS7 global title
  - SIP trunk domain
  - GRX node hostname
  - Diameter peer hostname
  - Lawful Intercept vendor
  - CDR mediation system vendor

Profiles are loaded by name (case-insensitive, '&' -> 'and').
"""

from __future__ import annotations

from typing import Optional

from tools.typhoon.core import CarrierProfile

# ---------------------------------------------------------------------------
# Registry — map carrier slug → CarrierProfile
# ---------------------------------------------------------------------------

_CARRIERS: dict[str, CarrierProfile] = {}


def _register(carrier: CarrierProfile) -> CarrierProfile:
    _CARRIERS[carrier.slug] = carrier
    _CARRIERS[carrier.profile_id] = carrier
    return carrier


# ---------------------------------------------------------------------------
# United States
# ---------------------------------------------------------------------------

_register(CarrierProfile(
    name="AT&T Mobility",
    country="US",
    mccMnc="310-410",
    ss7Gt="310410ATT",
    sipTrunk="sip.att.com",
    grxNode="grx.att.net",
    diameterPeer="diameter.att.net",
    lawfulInterceptVendor="SS8",
    cdrMediationVendor="Amdocs",
    hadoopCluster="att-hadoop-prod",
    kafkaBroker="kafka.att.net:9092",
))

_register(CarrierProfile(
    name="T-Mobile US",
    country="US",
    mccMnc="310-260",
    ss7Gt="310260TMO",
    sipTrunk="sip.t-mobile.com",
    grxNode="grx.t-mobile.com",
    diameterPeer="diameter.t-mobile.com",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Ericsson",
    hadoopCluster="tmo-hadoop-prod",
    kafkaBroker="kafka.t-mobile.com:9092",
))

_register(CarrierProfile(
    name="Verizon Wireless",
    country="US",
    mccMnc="310-012",
    ss7Gt="310012VZW",
    sipTrunk="sip.verizon.com",
    grxNode="grx.verizonwireless.com",
    diameterPeer="diameter.vzw.com",
    lawfulInterceptVendor="SS8",
    cdrMediationVendor="Amdocs",
    hadoopCluster="vzw-hadoop-prod",
    kafkaBroker="kafka.vzw.com:9092",
))

_register(CarrierProfile(
    name="Sprint",
    country="US",
    mccMnc="310-120",
    ss7Gt="310120SPR",
    sipTrunk="sip.sprint.com",
    grxNode="grx.sprint.net",
    diameterPeer="diameter.sprint.com",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Nokia",
    hadoopCluster="sprint-hadoop-prod",
    kafkaBroker="kafka.sprint.com:9092",
))

_register(CarrierProfile(
    name="US Cellular",
    country="US",
    mccMnc="310-220",
    ss7Gt="310220USC",
    sipTrunk="sip.uscellular.com",
    grxNode="grx.uscc.net",
    diameterPeer="diameter.uscc.com",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Ericsson",
    hadoopCluster="uscc-hadoop-prod",
    kafkaBroker="kafka.uscc.com:9092",
))

# ---------------------------------------------------------------------------
# China
# ---------------------------------------------------------------------------

_register(CarrierProfile(
    name="China Mobile",
    country="CN",
    mccMnc="460-00",
    ss7Gt="46000CMCC",
    sipTrunk="sip.chinamobile.com",
    grxNode="grx.chinamobile.com",
    diameterPeer="diameter.chinamobile.com",
    lawfulInterceptVendor="Huawei",
    cdrMediationVendor="Huawei",
    hadoopCluster="cmcc-hadoop-prod",
    kafkaBroker="kafka.chinamobile.com:9092",
))

_register(CarrierProfile(
    name="China Unicom",
    country="CN",
    mccMnc="460-01",
    ss7Gt="46001CUCC",
    sipTrunk="sip.chinaunicom.com",
    grxNode="grx.chinaunicom.com",
    diameterPeer="diameter.chinaunicom.com",
    lawfulInterceptVendor="ZTE",
    cdrMediationVendor="ZTE",
    hadoopCluster="cucc-hadoop-prod",
    kafkaBroker="kafka.chinaunicom.com:9092",
))

_register(CarrierProfile(
    name="China Telecom",
    country="CN",
    mccMnc="460-03",
    ss7Gt="46003CTCC",
    sipTrunk="sip.chinatelecom.com",
    grxNode="grx.chinatelecom.com",
    diameterPeer="diameter.chinatelecom.com",
    lawfulInterceptVendor="Huawei",
    cdrMediationVendor="Huawei",
    hadoopCluster="ctcc-hadoop-prod",
    kafkaBroker="kafka.chinatelecom.com:9092",
))

# ---------------------------------------------------------------------------
# Europe
# ---------------------------------------------------------------------------

_register(CarrierProfile(
    name="Deutsche Telekom",
    country="DE",
    mccMnc="262-01",
    ss7Gt="26201DTAG",
    sipTrunk="sip.telekom.de",
    grxNode="grx.telekom.de",
    diameterPeer="diameter.telekom.de",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Ericsson",
    hadoopCluster="dtag-hadoop-prod",
    kafkaBroker="kafka.telekom.de:9092",
))

_register(CarrierProfile(
    name="Vodafone UK",
    country="GB",
    mccMnc="234-15",
    ss7Gt="23415VOD",
    sipTrunk="sip.vodafone.co.uk",
    grxNode="grx.vodafone.co.uk",
    diameterPeer="diameter.vodafone.co.uk",
    lawfulInterceptVendor="SS8",
    cdrMediationVendor="Amdocs",
    hadoopCluster="vod-hadoop-prod",
    kafkaBroker="kafka.vodafone.co.uk:9092",
))

_register(CarrierProfile(
    name="Orange France",
    country="FR",
    mccMnc="208-01",
    ss7Gt="20801ORA",
    sipTrunk="sip.orange.fr",
    grxNode="grx.orange.fr",
    diameterPeer="diameter.orange.fr",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Nokia",
    hadoopCluster="ora-hadoop-prod",
    kafkaBroker="kafka.orange.fr:9092",
))

_register(CarrierProfile(
    name="Telefonica Spain",
    country="ES",
    mccMnc="214-07",
    ss7Gt="21407TEF",
    sipTrunk="sip.telefonica.es",
    grxNode="grx.movistar.es",
    diameterPeer="diameter.telefonica.es",
    lawfulInterceptVendor="SS8",
    cdrMediationVendor="Ericsson",
    hadoopCluster="tef-hadoop-prod",
    kafkaBroker="kafka.telefonica.es:9092",
))

# ---------------------------------------------------------------------------
# Asia-Pacific
# ---------------------------------------------------------------------------

_register(CarrierProfile(
    name="NTT Docomo",
    country="JP",
    mccMnc="440-10",
    ss7Gt="44010NTT",
    sipTrunk="sip.nttdocomo.co.jp",
    grxNode="grx.docomo.ne.jp",
    diameterPeer="diameter.docomo.ne.jp",
    lawfulInterceptVendor="NEC",
    cdrMediationVendor="Fujitsu",
    hadoopCluster="ntt-hadoop-prod",
    kafkaBroker="kafka.docomo.ne.jp:9092",
))

_register(CarrierProfile(
    name="SK Telecom",
    country="KR",
    mccMnc="450-05",
    ss7Gt="45005SKT",
    sipTrunk="sip.sktelecom.com",
    grxNode="grx.sktelecom.com",
    diameterPeer="diameter.sktelecom.com",
    lawfulInterceptVendor="Samsung",
    cdrMediationVendor="Samsung",
    hadoopCluster="skt-hadoop-prod",
    kafkaBroker="kafka.sktelecom.com:9092",
))

_register(CarrierProfile(
    name="Telstra",
    country="AU",
    mccMnc="505-01",
    ss7Gt="50501TEL",
    sipTrunk="sip.telstra.com",
    grxNode="grx.telstra.net",
    diameterPeer="diameter.telstra.com",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Ericsson",
    hadoopCluster="tel-hadoop-prod",
    kafkaBroker="kafka.telstra.com:9092",
))

_register(CarrierProfile(
    name="Reliance Jio",
    country="IN",
    mccMnc="405-855",
    ss7Gt="405855JIO",
    sipTrunk="sip.jio.com",
    grxNode="grx.jio.com",
    diameterPeer="diameter.jio.com",
    lawfulInterceptVendor="Samsung",
    cdrMediationVendor="Nokia",
    hadoopCluster="jio-hadoop-prod",
    kafkaBroker="kafka.jio.com:9092",
))

_register(CarrierProfile(
    name="Singtel",
    country="SG",
    mccMnc="525-01",
    ss7Gt="52501SIN",
    sipTrunk="sip.singtel.com",
    grxNode="grx.singtel.com",
    diameterPeer="diameter.singtel.com",
    lawfulInterceptVendor="Utimaco",
    cdrMediationVendor="Amdocs",
    hadoopCluster="singtel-hadoop-prod",
    kafkaBroker="kafka.singtel.com:9092",
))

# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def get_carrier(name: str) -> CarrierProfile:
    """Resolve carrier by name (case-insensitive, fuzzy)."""
    slug = name.lower().strip().replace("&", "and").replace(" ", "-")
    # Direct match first
    if slug in _CARRIERS:
        return _CARRIERS[slug]
    # Try prefix match (e.g. "att" → "at-and-t-mobility")
    for key, carrier in _CARRIERS.items():
        if slug in key or key.startswith(slug):
            return carrier
    raise KeyError(
        f"Carrier '{name}' not found. Available: {sorted(_CARRIERS.keys())}"
    )


def list_carriers() -> list[str]:
    """Return list of all registered carrier slugs."""
    return sorted(set(
        c.slug for c in _CARRIERS.values()
    ))


def available_carriers() -> dict[str, str]:
    """Return {slug: full_name} for all registered carriers."""
    return {
        c.slug: c.name for c in _CARRIERS.values()
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1 and sys.argv[1] in ("--list", "-l"):
        for slug, name in available_carriers().items():
            print(f"  {slug:30s} {name}")
    elif len(sys.argv) > 1:
        try:
            carrier = get_carrier(sys.argv[1])
            print(json.dumps(carrier.to_dict(), indent=2, ensure_ascii=False))
        except KeyError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python3 carriers.py [--list | <carrier-name>]")
