"""
Phase 7 — Anomaly Layer.
Identifies statistically unusual flows that didn't match any TTP playbook.
Produces structured anomaly dicts suitable for AI hypothesis prompting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.scorer import TTPScore

ANOMALY_THRESHOLD = 0.35  # below this score = anomaly candidate


@dataclass
class Anomaly:
    anomaly_id: str
    anomaly_type: str
    description: str
    raw_signals: dict = field(default_factory=dict)
    ttps_checked: list[str] = field(default_factory=list)
    reason_not_classified: str = ""
    ai_prompt: str = ""


def _build_ai_prompt(ctx: AnalysisContext, anomaly: Anomaly) -> str:
    return (
        "Given the following network anomaly from a PCAP analysis, suggest the 3 most likely "
        "attack techniques or malware families this could represent, explain your reasoning, "
        "and describe what additional packet-level evidence would confirm or deny each hypothesis.\n\n"
        f"Capture context: duration={ctx.capture_duration_secs:.0f}s, "
        f"total_flows={ctx.total_flows}, "
        f"internal_hosts={len(ctx.internal_ips)}, "
        f"visibility_pct={ctx.visibility_pct}%\n\n"
        f"Anomaly type: {anomaly.anomaly_type}\n"
        f"Description: {anomaly.description}\n"
        f"Raw signals: {json.dumps(anomaly.raw_signals, indent=2)}\n"
        f"TTPs already checked and cleared: {anomaly.ttps_checked}\n"
        f"Reason not auto-classified: {anomaly.reason_not_classified}"
    )


def run(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    ttp_scores: list[TTPScore],
) -> list[Anomaly]:
    """
    Identify anomalous patterns not captured by any playbook finding.
    Returns list of Anomaly objects with structured AI prompts.
    """
    anomalies: list[Anomaly] = []
    checked_ttps = [r.ttp_id for r in ttp_scores]
    counter = [0]

    def _new_id() -> str:
        counter[0] += 1
        return f"ANO-{counter[0]:04d}"

    # --- Anomaly 1: High DNS NXDOMAIN rate without tunneling confirmation ---
    if (
        signals.dns_nxdomain_rate >= 0.20
        and not any(r.ttp_id == "T1071.004" and r.score >= 0.60 for r in ttp_scores)
    ):
        a = Anomaly(
            anomaly_id=_new_id(),
            anomaly_type="dns_nxdomain_pattern",
            description=(
                f"DNS NXDOMAIN rate is {signals.dns_nxdomain_rate:.1%} "
                f"({signals.dns_unique_query_count} unique queries). "
                "This may indicate DGA (domain generation algorithm) activity, "
                "C2 domain cycling, or misconfigured software."
            ),
            raw_signals={
                "dns_nxdomain_rate": signals.dns_nxdomain_rate,
                "dns_unique_query_count": signals.dns_unique_query_count,
                "dns_avg_query_length": signals.dns_avg_query_length,
                "dns_max_subdomain_entropy": signals.dns_max_subdomain_entropy,
                "top_domains": signals.dns_top_domains[:5],
            },
            ttps_checked=checked_ttps,
            reason_not_classified=(
                "NXDOMAIN rate above 20% but DNS tunneling signals did not meet "
                "full threshold (avg query length < 40, unique FQDN count < 1)."
            ),
        )
        a.ai_prompt = _build_ai_prompt(ctx, a)
        anomalies.append(a)

    # --- Anomaly 2: High HTTP POST volume without exfil confirmation ---
    if (
        signals.http_plaintext_post_count >= 50
        and not any(r.ttp_id == "T1048.003" and r.score >= 0.60 for r in ttp_scores)
    ):
        a = Anomaly(
            anomaly_id=_new_id(),
            anomaly_type="high_http_post_volume",
            description=(
                f"{signals.http_plaintext_post_count} HTTP POST requests observed over cleartext. "
                "Could indicate form submission telemetry, C2 data upload, or credential harvesting."
            ),
            raw_signals={
                "http_plaintext_post_count": signals.http_plaintext_post_count,
                "http_packet_count": signals.http_packet_count,
                "max_outbound_bytes": signals.max_outbound_bytes,
            },
            ttps_checked=checked_ttps,
            reason_not_classified=(
                "POST count is high but max_outbound_bytes did not reach 10MB threshold "
                "for exfiltration detection."
            ),
        )
        a.ai_prompt = _build_ai_prompt(ctx, a)
        anomalies.append(a)

    # --- Anomaly 3: Broad host sweep without scan confirmation ---
    if (
        signals.scan_max_unique_dst_hosts >= 20
        and not any(r.ttp_id == "T1046" and r.score >= 0.60 for r in ttp_scores)
    ):
        a = Anomaly(
            anomaly_id=_new_id(),
            anomaly_type="broad_host_contact",
            description=(
                f"A single host contacted {signals.scan_max_unique_dst_hosts} unique destinations. "
                "This is unusual and may indicate automated outbound connections, malware C2 rotation, "
                "or reconnaissance."
            ),
            raw_signals={
                "scan_max_unique_dst_hosts": signals.scan_max_unique_dst_hosts,
                "scan_max_unique_dst_ports": signals.scan_max_unique_dst_ports,
                "scan_candidates": signals.scan_candidates[:3],
            },
            ttps_checked=checked_ttps,
            reason_not_classified="Below port scan threshold or captured as low-confidence finding.",
        )
        a.ai_prompt = _build_ai_prompt(ctx, a)
        anomalies.append(a)

    # --- Anomaly 4: TLS sessions without SNI (potential C2) ---
    if signals.tls_missing_sni_count >= 5:
        a = Anomaly(
            anomaly_id=_new_id(),
            anomaly_type="tls_missing_sni",
            description=(
                f"{signals.tls_missing_sni_count} TLS sessions have no SNI (Server Name Indication). "
                "Legitimate browsers always send SNI. Absent SNI suggests custom TLS implementation "
                "or raw IP-based C2."
            ),
            raw_signals={
                "tls_missing_sni_count": signals.tls_missing_sni_count,
                "tls_packet_count": signals.tls_packet_count,
                "tls_unique_ja3_count": signals.tls_unique_ja3_count,
            },
            ttps_checked=checked_ttps,
            reason_not_classified=(
                "No JA3 match available (zeek JA3 package not installed). "
                "Cannot confirm against known C2 fingerprints."
            ),
        )
        a.ai_prompt = _build_ai_prompt(ctx, a)
        anomalies.append(a)

    # --- Anomaly 5: ARP anomalies (potential MITM setup) ---
    if signals.arp_gratuitous_count >= 3 or signals.arp_ip_conflict_count >= 1:
        a = Anomaly(
            anomaly_id=_new_id(),
            anomaly_type="arp_anomaly",
            description=(
                f"{signals.arp_gratuitous_count} gratuitous ARP packets and "
                f"{signals.arp_ip_conflict_count} IP address conflicts detected. "
                "May indicate ARP spoofing, MITM attack setup, or misconfigured network equipment."
            ),
            raw_signals={
                "arp_packet_count": signals.arp_packet_count,
                "arp_gratuitous_count": signals.arp_gratuitous_count,
                "arp_ip_conflict_count": signals.arp_ip_conflict_count,
            },
            ttps_checked=checked_ttps,
            reason_not_classified=(
                "Gratuitous ARP count below definitive poisoning threshold. "
                "Requires correlation with ARP table changes on the network."
            ),
        )
        a.ai_prompt = _build_ai_prompt(ctx, a)
        anomalies.append(a)

    print(f"  [Phase 7] {len(anomalies)} anomaly/anomalies identified for review.")
    return anomalies
