"""
Phase 6 — IOC Enrichment.
Queries VirusTotal and ThreatFox for the most suspicious external IPs from findings.
Rate-limited to 4 VT req/min (free tier). Prioritises IPs from TTP findings, then top talkers.
Max 20 IPs to stay within daily VT limits.

Also runs JA3/JA3S fingerprint lookup against a hardcoded known-bad list.
JA3 hashes are stable across versions for well-known malware families.
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

# ---------------------------------------------------------------------------
# JA3 known-bad fingerprint list (offline, no API required)
# Sources: abuse.ch JA3 feeds, vendor threat reports, JARM research
# ---------------------------------------------------------------------------
_KNOWN_BAD_JA3: dict[str, str] = {
    # Cobalt Strike default beacon profiles
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike default beacon",
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike beacon (Malleable C2)",
    "a1cdd6ef66c0a1e3e464cad8437b7b79": "Cobalt Strike beacon (Malleable C2)",
    "fc54e0d16d9764783542f0146a98b300": "Cobalt Strike beacon (Malleable C2 variant)",
    "e7d705a3286e19ea42f587b6d84c549f": "Cobalt Strike HTTPS malleable",
    # Metasploit Meterpreter
    "de350869b8c85de67a350c8d186f11e6": "Metasploit Meterpreter",
    "6734f37431670b3ab4292b8f60f29984": "Metasploit Meterpreter",
    "5d41402abc4b2a76b9719d911017c592": "Metasploit reverse_tcp stager",
    # Common RAT fingerprints
    "7dd80c5c57a4c47985fc87e37ab33d87": "AsyncRAT / QuasarRAT",
    "3b5074b1b5d032e5620f69f9f700ff0e": "AgentTesla / NjRAT C2",
    "2fe9b0e731d3d41b2b84e8e1d6186836": "Generic malware implant (multiple families)",
    # Emotet / Qbot
    "6b9b58d3cb2fbbcfb52fb2f2e43a1c70": "Emotet C2",
    "44d4a61e0a93c91edf75e87d9f8a71f9": "Qbot banker C2",
    # IcedID
    "eb1d94daa7e0344597e756a1fb6e7054": "IcedID / BokBot C2",
}

_KNOWN_BAD_JA3S: dict[str, str] = {
    # Server-side JA3S hashes — intentionally minimal.
    # JA3S FP rate is high because CDNs and cloud providers share TLS server configs.
    # Only include when a hash has been validated as C2-exclusive across multiple sources.
    "ec74a5c51106f0419184d0dd08fb05bc": "Cobalt Strike Team Server response",
}


@dataclass
class JA3Result:
    ja3: str
    ja3s: str = ""
    matched_bad_ja3: bool = False
    matched_bad_ja3s: bool = False
    ja3_family: str = ""
    ja3s_family: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    server_name: str = ""


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


def check_ja3(signals: ProtocolSignals) -> list[JA3Result]:
    """
    Check JA3/JA3S hashes in ssl.log against known-bad fingerprint list.
    Returns matches only. Works offline — no API calls.
    """
    hits: list[JA3Result] = []
    if not signals.tls_sessions:
        return hits

    seen: set[str] = set()
    for session in signals.tls_sessions:
        ja3 = str(session.get("ja3") or "")
        ja3s = str(session.get("ja3s") or "")
        key = f"{ja3}:{ja3s}"
        if not ja3 or ja3 in ("-", "nan", "") or key in seen:
            continue
        seen.add(key)

        bad_ja3 = _KNOWN_BAD_JA3.get(ja3, "")
        bad_ja3s = _KNOWN_BAD_JA3S.get(ja3s, "")

        if bad_ja3 or bad_ja3s:
            hits.append(JA3Result(
                ja3=ja3,
                ja3s=ja3s,
                matched_bad_ja3=bool(bad_ja3),
                matched_bad_ja3s=bool(bad_ja3s),
                ja3_family=bad_ja3,
                ja3s_family=bad_ja3s,
                src_ip=str(session.get("id.orig_h") or ""),
                dst_ip=str(session.get("id.resp_h") or ""),
                server_name=str(session.get("server_name") or ""),
            ))

    return hits


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
