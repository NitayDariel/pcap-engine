"""
Phase 6 — IOC Enrichment.
Queries VirusTotal and ThreatFox for the most suspicious external IPs from findings.
Rate-limited to 4 VT req/min (free tier). Prioritises IPs from TTP findings, then top talkers.
Max 20 IPs to stay within daily VT limits.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.scorer import TTPScore
from engine.utils.vt_client import lookup_ip as vt_lookup, is_malicious as vt_is_malicious
from engine.utils.abusech_client import is_malicious as tf_is_malicious

MAX_IPS = 20
VT_INTERVAL = 16.0  # seconds between VT calls (4/min = 15s, add 1s buffer)


@dataclass
class IOCResult:
    ip: str
    vt_malicious: int = 0
    vt_suspicious: int = 0
    vt_reputation: int = 0
    vt_owner: str = ""
    vt_country: str = ""
    threatfox_found: bool = False
    threatfox_malware: str = ""
    threatfox_threat_type: str = ""
    threatfox_confidence: int = 0
    threatfox_tags: list = field(default_factory=list)
    is_confirmed_malicious: bool = False
    source: str = ""  # why this IP was selected for enrichment


def _priority_ips(
    ctx: AnalysisContext,
    ttp_scores: list[TTPScore],
    signals: ProtocolSignals,
) -> list[tuple[str, str]]:
    """
    Build a prioritised list of (ip, source_reason) to enrich.
    Priority: 1) IPs in scan_candidates  2) top external talkers  3) any external IP
    Skip: internal IPs and whitelisted IPs.
    """
    seen: set[str] = set()
    candidates: list[tuple[str, str]] = []

    def _add(ip: str, reason: str) -> None:
        if ip in seen:
            return
        if ip in ctx.internal_ips:
            return
        if ctx.whitelist and ip in ctx.whitelist.cleared_ips:
            return
        seen.add(ip)
        candidates.append((ip, reason))

    # 1. IPs from scan candidates (actively contacted hosts)
    for c in signals.scan_candidates:
        for host in c.get("unique_dst_hosts_sample", []):
            _add(host, "scan_target")
            if len(candidates) >= MAX_IPS:
                return candidates

    # 2. Top external talkers by bytes
    for talker in ctx.top_talkers:
        src, dst = talker.get("src", ""), talker.get("dst", "")
        for ip in (src, dst):
            _add(ip, "top_talker")
        if len(candidates) >= MAX_IPS:
            return candidates

    # 3. Remaining external IPs (alphabetical for reproducibility)
    for ip in sorted(ctx.external_ips):
        _add(ip, "external_ip")
        if len(candidates) >= MAX_IPS:
            return candidates

    return candidates


def _enrich_ip(ip: str, source: str, vt_delay: float) -> IOCResult:
    """Enrich a single IP via VT and ThreatFox. vt_delay controls rate limiting."""
    result = IOCResult(ip=ip, source=source)

    # VirusTotal
    try:
        if vt_delay > 0:
            time.sleep(vt_delay)
        vt = vt_lookup(ip)
        if vt:
            result.vt_malicious   = vt.get("malicious", 0)
            result.vt_suspicious  = vt.get("suspicious", 0)
            result.vt_reputation  = vt.get("reputation", 0)
            result.vt_owner       = vt.get("owner", "")
            result.vt_country     = vt.get("country", "")
    except Exception as e:
        print(f"    [VT]  {ip} failed: {e}")

    # ThreatFox (no strict rate limit)
    try:
        tf_found, tf_summary = tf_is_malicious(ip)
        if tf_found and tf_summary:
            result.threatfox_found       = True
            result.threatfox_malware     = tf_summary.get("malware", "")
            result.threatfox_threat_type = tf_summary.get("threat_type", "")
            result.threatfox_confidence  = tf_summary.get("confidence", 0)
            result.threatfox_tags        = tf_summary.get("tags", [])
    except Exception as e:
        print(f"    [TF]  {ip} failed: {e}")

    result.is_confirmed_malicious = (
        result.vt_malicious >= 3 or result.threatfox_confidence >= 75
    )

    return result


def run(
    ctx: AnalysisContext,
    ttp_scores: list[TTPScore],
    signals: ProtocolSignals,
    max_ips: int = MAX_IPS,
    offline: bool = False,
) -> dict[str, IOCResult]:
    """
    Enrich prioritised external IPs. Returns dict keyed by IP.
    Set offline=True to skip all API calls (returns empty dict).
    """
    if offline:
        print("  [Phase 6] Offline mode — skipping IOC enrichment.")
        return {}

    targets = _priority_ips(ctx, ttp_scores, signals)[:max_ips]
    print(f"  [Phase 6] Enriching {len(targets)} IPs via VT + ThreatFox...")

    results: dict[str, IOCResult] = {}
    for i, (ip, source) in enumerate(targets):
        # Apply VT rate limit: sleep between calls (not before first)
        vt_delay = VT_INTERVAL if i > 0 else 0.0
        r = _enrich_ip(ip, source, vt_delay)
        results[ip] = r

        status = "MALICIOUS" if r.is_confirmed_malicious else "clean"
        tf_note = f" [{r.threatfox_malware}]" if r.threatfox_found else ""
        print(
            f"  [Phase 6] {ip:<20} VT:{r.vt_malicious:>3} malicious  "
            f"TF:{r.threatfox_found}  {status}{tf_note}"
        )

    confirmed = sum(1 for r in results.values() if r.is_confirmed_malicious)
    print(f"  [Phase 6] Done — {confirmed}/{len(results)} IPs confirmed malicious.")

    return results
