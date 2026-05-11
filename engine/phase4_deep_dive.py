"""
Phase 4 — Deep Dive.
For each TTP with score >= deep_dive_threshold, runs targeted evidence gathering
using Zeek log queries and tshark. Returns structured findings with packet-level evidence.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from engine.phase2_protocol import ProtocolSignals
from engine.scorer import TTPScore
from engine.utils.tshark import fields as tshark_fields
from engine.utils.zeek import parse_conn_log, parse_log

DEEP_DIVE_THRESHOLD = 0.60


@dataclass
class DeepDiveFinding:
    ttp_id: str
    name: str
    score: float
    confidence: str
    summary: str = ""
    evidence: list[dict] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    raw_context: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Per-TTP deep dive functions
# ---------------------------------------------------------------------------

def _dive_port_scan(pcap: str, signals: ProtocolSignals, result: TTPScore) -> DeepDiveFinding:
    finding = DeepDiveFinding(
        ttp_id=result.ttp_id, name=result.name,
        score=result.score, confidence=result.confidence,
    )

    if not signals.scan_candidates:
        finding.summary = "No scan candidates extracted."
        return finding

    top = signals.scan_candidates[0]
    scanner_ip = top["src"]

    conn_df = parse_conn_log(signals.zeek_log_dir)
    scanner_conns = conn_df[conn_df["id.orig_h"] == scanner_ip].copy()

    unique_ports = sorted(scanner_conns["id.resp_p"].dropna().astype(int).unique().tolist())
    unique_hosts = sorted(scanner_conns["id.resp_h"].dropna().unique().tolist())

    finding.summary = (
        f"{scanner_ip} contacted {len(unique_hosts)} unique hosts "
        f"across {len(unique_ports)} unique ports."
    )
    finding.evidence = [
        {
            "scanner_ip": scanner_ip,
            "unique_dst_ports": unique_ports[:50],
            "unique_dst_hosts_count": len(unique_hosts),
            "unique_dst_hosts_sample": unique_hosts[:20],
            "total_connections": len(scanner_conns),
        }
    ]

    if "ts" in scanner_conns.columns:
        ts = pd.to_numeric(scanner_conns["ts"], errors="coerce").dropna()
        if not ts.empty:
            finding.timeline = [
                {"event": "scan_start", "ts": float(ts.min())},
                {"event": "scan_end",   "ts": float(ts.max())},
                {"event": "duration_secs", "ts": float(ts.max() - ts.min())},
            ]

    return finding


def _dive_smb_lateral(pcap: str, signals: ProtocolSignals, result: TTPScore) -> DeepDiveFinding:
    finding = DeepDiveFinding(
        ttp_id=result.ttp_id, name=result.name,
        score=result.score, confidence=result.confidence,
    )

    smb_map = parse_log(f"{signals.zeek_log_dir}/smb_mapping.log")
    if smb_map.empty:
        finding.summary = "No SMB mapping log available."
        return finding

    if "path" in smb_map.columns:
        admin = smb_map[
            smb_map["path"].str.upper().str.contains(r"ADMIN\$|C\$|IPC\$", na=False)
        ]
        finding.evidence = admin.head(20).to_dict("records")
        paths = smb_map["path"].dropna().unique().tolist()
        finding.summary = (
            f"SMB admin share access detected. "
            f"{len(admin)} events. Unique paths: {paths[:10]}"
        )

    smb_files = parse_log(f"{signals.zeek_log_dir}/smb_files.log")
    if not smb_files.empty:
        cols = [
            c for c in ["ts", "id.orig_h", "id.resp_h", "action", "path", "name", "size"]
            if c in smb_files.columns
        ]
        finding.raw_context["smb_files"] = smb_files[cols].head(20).to_dict("records")

    return finding


def _subdomain_entropy(query: str) -> float:
    s = query.split(".")[0] if isinstance(query, str) and "." in query else ""
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _dive_dns_tunneling(pcap: str, signals: ProtocolSignals, result: TTPScore) -> DeepDiveFinding:
    finding = DeepDiveFinding(
        ttp_id=result.ttp_id, name=result.name,
        score=result.score, confidence=result.confidence,
    )

    dns_df = parse_log(f"{signals.zeek_log_dir}/dns.log")
    if dns_df.empty:
        finding.summary = "No DNS log available."
        return finding

    dns_df = dns_df.copy()
    dns_df["entropy"] = dns_df["query"].apply(
        lambda q: _subdomain_entropy(str(q)) if pd.notna(q) else 0.0
    )

    suspicious = dns_df[dns_df["entropy"] > 3.5].sort_values("entropy", ascending=False)
    cols = [
        c for c in ["ts", "id.orig_h", "query", "qtype_name", "rcode_name", "entropy"]
        if c in suspicious.columns
    ]
    finding.evidence = suspicious[cols].head(30).to_dict("records")
    finding.summary = (
        f"{len(suspicious)} DNS queries with subdomain entropy > 3.5. "
        f"Max entropy: {signals.dns_max_subdomain_entropy:.2f}. "
        f"NXDOMAIN rate: {signals.dns_nxdomain_rate:.2%}."
    )

    return finding


def _dive_credential_sniffing(pcap: str, signals: ProtocolSignals, result: TTPScore) -> DeepDiveFinding:
    finding = DeepDiveFinding(
        ttp_id=result.ttp_id, name=result.name,
        score=result.score, confidence=result.confidence,
    )

    try:
        rows = tshark_fields(
            pcap,
            "http.authorization",
            "frame.time", "ip.src", "ip.dst", "http.authorization",
        )
        finding.evidence = [
            {"ts": r[0], "src": r[1], "dst": r[2], "auth_header": r[3]}
            for r in rows[:20] if len(r) >= 4
        ]
        finding.summary = f"{len(finding.evidence)} cleartext credential events found."
    except Exception as e:
        finding.summary = f"tshark query failed: {e}"

    return finding


def _dive_exfil(pcap: str, signals: ProtocolSignals, result: TTPScore) -> DeepDiveFinding:
    finding = DeepDiveFinding(
        ttp_id=result.ttp_id, name=result.name,
        score=result.score, confidence=result.confidence,
    )
    finding.evidence = signals.large_outbound_transfers[:20]
    finding.summary = (
        f"Max outbound bytes: {signals.max_outbound_bytes:,}. "
        f"HTTP POSTs: {signals.http_plaintext_post_count}."
    )

    http_df = parse_log(f"{signals.zeek_log_dir}/http.log")
    if not http_df.empty and "method" in http_df.columns:
        posts = http_df[http_df["method"] == "POST"]
        cols = [
            c for c in
            ["ts", "id.orig_h", "id.resp_h", "id.resp_p", "uri", "host", "request_body_len"]
            if c in posts.columns
        ]
        finding.raw_context["http_posts"] = posts[cols].head(20).to_dict("records")

    return finding


# ---------------------------------------------------------------------------
# Dispatch table and entry point
# ---------------------------------------------------------------------------

_DIVERS = {
    "T1046":     _dive_port_scan,
    "T1021.002": _dive_smb_lateral,
    "T1071.004": _dive_dns_tunneling,
    "T1040":     _dive_credential_sniffing,
    "T1048.003": _dive_exfil,
}


def run(
    pcap_path: str,
    ttp_scores: list[TTPScore],
    signals: ProtocolSignals,
    threshold: float = DEEP_DIVE_THRESHOLD,
) -> list[DeepDiveFinding]:
    """
    Run deep dive on all TTPs scoring >= threshold.
    Returns list of DeepDiveFinding ordered by score descending.
    """
    candidates = [r for r in ttp_scores if r.score >= threshold]
    print(f"  [Phase 4] Deep diving {len(candidates)} TTP(s) with score >= {threshold}...")

    findings = []
    for result in candidates:
        diver = _DIVERS.get(result.ttp_id)
        if diver:
            try:
                f = diver(pcap_path, signals, result)
                findings.append(f)
                print(f"  [Phase 4] {result.ttp_id}: {f.summary[:80]}")
            except Exception as e:
                print(f"  [Phase 4] {result.ttp_id} deep dive failed: {e}")

    return findings
