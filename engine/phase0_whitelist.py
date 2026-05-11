"""
Phase 0 — Whitelist & Reduction Pass.
Identifies known-good IPs, domains, and protocols before any TTP scoring.
Called by phase1_orientation. Result is embedded in AnalysisContext.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

# RFC1918 + special ranges treated as internal
_INTERNAL_RANGES: list[ipaddress.IPv4Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
]


@dataclass
class WhitelistResult:
    cleared_ips: set[str] = field(default_factory=set)
    cleared_domains: set[str] = field(default_factory=set)
    cleared_protocols: set[str] = field(default_factory=set)
    rules_loaded: int = 0


class Whitelist:
    """
    Loaded once from whitelist.yaml. Stateless after init — call apply() freely.
    """

    def __init__(self, config_path: Optional[str] = None):
        if config_path is None:
            here = Path(__file__).resolve()
            config_path = str(here.parents[1] / "config" / "whitelist.yaml")

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        self._ntp_nets = self._load_nets(cfg.get("ntp_servers", []))
        self._cdn_nets = self._load_nets(cfg.get("cdn_ranges", []))
        self._update_ip_nets = self._load_nets(
            cfg.get("update_servers", {}).get("ips", [])
        )
        self._update_domains: set[str] = {
            d.lower()
            for d in cfg.get("update_servers", {}).get("domains", [])
        }
        self._ca_domains: set[str] = {
            d.lower() for d in cfg.get("certificate_authorities", [])
        }
        self._cleared_protocols: set[str] = {
            p.lower() for p in cfg.get("local_protocols_to_clear", [])
        }

        self._all_nets = self._ntp_nets + self._cdn_nets + self._update_ip_nets
        self._all_domains = self._update_domains | self._ca_domains
        self._rules = len(self._all_nets) + len(self._all_domains)

    def _load_nets(self, entries: list) -> list[ipaddress.IPv4Network]:
        nets = []
        for e in entries:
            try:
                nets.append(ipaddress.ip_network(str(e), strict=False))
            except ValueError:
                pass
        return nets

    def is_whitelisted_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._all_nets)

    def is_whitelisted_domain(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        return d in self._all_domains or any(
            d.endswith("." + k) for k in self._all_domains
        )

    def is_internal_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in _INTERNAL_RANGES)

    def classify_ips(
        self, ips: set[str]
    ) -> tuple[set[str], set[str]]:
        """Split ip set into (internal_ips, external_ips)."""
        internal, external = set(), set()
        for ip in ips:
            if self.is_internal_ip(ip):
                internal.add(ip)
            else:
                external.add(ip)
        return internal, external

    def apply(
        self,
        ips: set[str],
        domains: Optional[set[str]] = None,
    ) -> WhitelistResult:
        """Mark known-good IPs and domains. Returns WhitelistResult."""
        result = WhitelistResult()
        result.cleared_protocols = self._cleared_protocols.copy()
        result.rules_loaded = self._rules

        for ip in ips:
            if self.is_whitelisted_ip(ip):
                result.cleared_ips.add(ip)

        if domains:
            for domain in domains:
                if self.is_whitelisted_domain(domain):
                    result.cleared_domains.add(domain)

        return result
