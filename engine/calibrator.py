"""
Threshold calibrator.
Takes a populated AnalysisContext and returns a dict of thresholds
tuned to that specific capture's size, duration, and protocol mix.
All TTP scoring uses these values rather than raw config defaults.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.phase1_orientation import AnalysisContext


def calibrate(ctx: "AnalysisContext") -> dict:
    dur = ctx.capture_duration_secs
    n_internal = len(ctx.internal_ips)
    n_all = max(len(ctx.all_ips), 1)

    return {
        # --- Beaconing ---
        # Need enough observed connections to distinguish automation from human
        "beacon_min_connections": max(5, int(dur / 300)),
        # Need enough capture time to observe regularity
        "beacon_min_duration_secs": min(dur * 0.3, 3600),

        # --- Lateral movement ---
        # Host contacting >30% of internal hosts in a short span is suspicious
        "lateral_new_internal_connections": max(5, int(n_internal * 0.3)),

        # --- Port scanning ---
        # Absolute floor prevents false positives on tiny captures
        "scan_unique_dst_ports": max(15, 20),
        "scan_unique_dst_hosts": max(10, int(n_all * 0.2)),

        # --- Data volume ---
        # Large outbound transfers relative to capture baseline
        "exfil_bytes_threshold": max(10_000_000, int(ctx.file_size_bytes * 0.05)),

        # --- Protocol skip flags ---
        # Skip entire TTP category if the protocol isn't present
        "skip_dns_ttps":      "dns"  not in ctx.protocols_present,
        "skip_smb_ttps":      "smb"  not in ctx.protocols_present,
        "skip_kerberos_ttps": "kerberos" not in ctx.protocols_present,
        "skip_http_ttps":     "http" not in ctx.protocols_present,
        "skip_tls_ttps": (
            "tls" not in ctx.protocols_present
            and "ssl" not in ctx.protocols_present
        ),
        "skip_icmp_ttps":     "icmp" not in ctx.protocols_present,
    }
