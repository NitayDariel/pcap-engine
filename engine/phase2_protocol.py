"""
Phase 2 — Protocol-Layer Analysis.
Computes pre-aggregated ProtocolSignals from Zeek logs + targeted tshark queries.
Phase 3 scorer reads these fields by name — field names are the API contract with playbooks.
"""

from __future__ import annotations

import math
import re
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd

from engine.phase1_orientation import AnalysisContext
from engine import phase2_beacon
from engine.utils.zeek import (
    run_zeek,
    parse_conn_log,
    parse_dns_log,
    parse_ssl_log,
    parse_http_log,
    parse_log,
    available_logs,
)
from engine.utils.tshark import fields as tshark_fields, run as tshark_run


# ---------------------------------------------------------------------------
# ProtocolSignals — the API contract between phase2 and playbook signals
# ---------------------------------------------------------------------------

@dataclass
class ProtocolSignals:
    """Pre-aggregated signals per protocol. Field names must match playbook source: keys exactly."""

    # --- DNS ---
    dns_packet_count: int = 0
    dns_unique_query_count: int = 0
    dns_avg_query_length: float = 0.0
    dns_txt_null_ratio: float = 0.0
    dns_nxdomain_rate: float = 0.0
    dns_max_subdomain_entropy: float = 0.0
    dns_suspicious_parent_count: int = 0    # parent domains with >10 unique subdomains
    dns_top_domains: list = field(default_factory=list)

    # --- HTTP ---
    http_packet_count: int = 0
    http_cleartext_creds_detected: bool = False
    http_unique_user_agent_count: int = 0
    http_plaintext_post_count: int = 0
    http_post_destinations: list = field(default_factory=list)  # resp IPs of POST requests
    http_on_nonstandard_port_count: int = 0                     # cleartext HTTP on non-standard ports

    # --- TLS/SSL ---
    tls_packet_count: int = 0
    tls_unique_ja3_count: int = 0
    tls_cert_anomaly_count: int = 0
    tls_cert_anomaly_ips: list = field(default_factory=list)
    tls_missing_sni_count: int = 0
    tls_sessions: list = field(default_factory=list)

    # --- SMB ---
    smb_packet_count: int = 0
    smb_admin_share_detected: bool = False
    smb_lateral_host_count: int = 0

    # --- ICMP ---
    icmp_packet_count: int = 0
    icmp_large_payload_count: int = 0

    # --- ARP ---
    arp_packet_count: int = 0
    arp_gratuitous_count: int = 0
    arp_ip_conflict_count: int = 0

    # --- Port scanning ---
    scan_candidate_count: int = 0
    scan_max_unique_dst_ports: int = 0
    scan_max_unique_dst_hosts: int = 0
    scan_syn_only_connection_count: int = 0  # S0/REJ/RSTO — real scans leave many; telemetry rarely does
    scan_candidates: list = field(default_factory=list)

    # --- Kerberos ---
    kerberos_packet_count: int = 0
    kerberos_tgs_req_count: int = 0
    kerberos_rc4_tgs_count: int = 0       # RC4 TGS tickets — classic Kerberoasting indicator
    kerberos_unique_spn_count: int = 0
    kerberos_preauth_failed_count: int = 0

    # --- Credential exposure ---
    cleartext_creds_detected: bool = False
    cleartext_proto_list: list = field(default_factory=list)

    # --- Exfiltration ---
    large_outbound_transfers: list = field(default_factory=list)
    max_outbound_bytes: int = 0

    # --- DCSync / Replication ---
    drsuapi_packet_count: int = 0              # MS-DRSR total packet count (includes benign DC replication)
    drsuapi_attacker_source_count: int = 0     # drsuapi from non-DC hosts — true DCSync indicator

    # --- FTP ---
    ftp_cleartext_detected: bool = False

    # --- RDP ---
    rdp_packet_count: int = 0

    # --- LDAP / CLDAP (AD enumeration) ---
    ldap_packet_count: int = 0
    cldap_packet_count: int = 0

    # --- WinRM (remote management lateral movement) ---
    winrm_connection_count: int = 0             # connections to port 5985 (HTTP) or 5986 (HTTPS)

    # --- Inbound scanning (T1595 — external host scanning inward) ---
    inbound_scan_unique_src_count: int = 0      # external IPs scanning >=5 ports on internal hosts

    # --- Data encoding / obfuscation ---
    dns_ptr_lookup_count: int = 0               # PTR queries — reverse DNS recon indicator
    dns_base64_label_count: int = 0             # DNS labels matching base64/hex encoding (len>=24, entropy>4.0)
    http_base64_uri_count: int = 0              # HTTP requests whose URI contains base64-like components

    # --- Web service C2 (T1102) ---
    dns_c2_service_lookup_count: int = 0        # DNS queries for Telegram/Discord/Pastebin/Slack C2 platforms

    # --- Beaconing (RITA-style 4-factor composite) ---
    beacon_candidates: list = field(default_factory=list)  # list of BeaconCandidate
    beacon_top_score: float = 0.0                          # highest composite score seen

    # --- Zeek metadata ---
    zeek_log_dir: str = ""
    logs_available: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _subdomain_of(query: str) -> str:
    """Extract the leftmost label — what gets encoded in DNS tunnel traffic."""
    if not isinstance(query, str):
        return ""
    return query.split(".")[0]


def _is_srv_record(fqdn: str) -> bool:
    """RFC 2782: SRV labels always start with '_' (e.g. _ldap._tcp.dc._msdcs.*). AD infrastructure, not user traffic."""
    return any(label.startswith("_") for label in fqdn.split("."))


def _entropy_eligible(q: str) -> bool:
    """Entropy is only meaningful for 3+ label subdomains, not apex queries or mDNS .local."""
    if not isinstance(q, str):
        return False
    if q.endswith(".local"):
        return False
    return len(q.split(".")) >= 3


# ---------------------------------------------------------------------------
# Per-protocol computation functions
# ---------------------------------------------------------------------------

def _dns_signals(dns_df: pd.DataFrame, packet_count: int) -> dict:
    out: dict = {"dns_packet_count": packet_count}
    if dns_df.empty:
        return out

    out["dns_unique_query_count"] = int(dns_df["query"].nunique())
    out["dns_avg_query_length"] = float(dns_df["query"].str.len().mean())

    # TXT / NULL query ratio
    type_counts = dns_df["qtype_name"].value_counts() if "qtype_name" in dns_df else pd.Series(dtype=int)
    txt_null = int(type_counts.get("TXT", 0)) + int(type_counts.get("NULL", 0))
    total = len(dns_df)
    out["dns_txt_null_ratio"] = round(txt_null / total, 4) if total else 0.0

    # NXDOMAIN rate
    if "rcode_name" in dns_df.columns:
        nxdomain = int((dns_df["rcode_name"] == "NXDOMAIN").sum())
        out["dns_nxdomain_rate"] = round(nxdomain / total, 4) if total else 0.0

    # Subdomain entropy — exclude mDNS .local and apex-only queries (need 3+ labels for real subdomain)
    entropies = dns_df["query"].dropna().apply(
        lambda q: _shannon_entropy(_subdomain_of(q)) if _entropy_eligible(q) else 0.0
    )
    out["dns_max_subdomain_entropy"] = round(float(entropies.max()), 4) if not entropies.empty else 0.0

    # Parent diversity — exclude RFC 2782 SRV records (_service._proto.*) and mDNS .local
    # SRV records are AD infrastructure (dozens of unique FQDNs per domain is normal) — not tunneling
    parent_to_fqdns: dict[str, set] = {}
    for q in dns_df["query"].dropna():
        if not isinstance(q, str):
            continue
        if _is_srv_record(q) or q.endswith(".local"):
            continue
        parts = q.split(".")
        if len(parts) >= 2:
            parent = ".".join(parts[-2:])
            parent_to_fqdns.setdefault(parent, set()).add(q)

    # A parent is suspicious only if it has both: many unique FQDNs AND long first-labels.
    # Real DNS tunneling encodes data in first labels (base32/base64: 20-63 chars avg).
    # Legitimate CDN/SaaS domains have many FQDNs but short human-readable first labels (< 15 chars).
    def _avg_first_label_len(fqdns: set) -> float:
        return sum(len(fqdn.split(".")[0]) for fqdn in fqdns) / len(fqdns) if fqdns else 0.0

    out["dns_suspicious_parent_count"] = sum(
        1 for v in parent_to_fqdns.values()
        if len(v) > 10 and _avg_first_label_len(v) > 15
    )
    out["dns_top_domains"] = sorted(
        [(k, len(v)) for k, v in parent_to_fqdns.items()],
        key=lambda x: x[1],
        reverse=True,
    )[:20]

    # PTR query count — mass reverse DNS lookups indicate host/network enumeration
    if "qtype_name" in dns_df.columns:
        out["dns_ptr_lookup_count"] = int((dns_df["qtype_name"] == "PTR").sum())

    # DNS labels with base64/hex encoding — indicator of DNS-based data exfil or C2 encoding.
    # Gate: label >= 24 chars, only base64url charset, Shannon entropy > 4.0.
    # This rejects short CDN tokens and human-readable strings while catching encoded payloads.
    _B64_LABEL_RE = re.compile(r'^[A-Za-z0-9+/=_-]{24,}$')
    base64_label_count = 0
    if "query" in dns_df.columns:
        for q in dns_df["query"].dropna():
            q = str(q)
            if _is_srv_record(q) or q.endswith(".local"):
                continue
            for label in q.split("."):
                if _B64_LABEL_RE.match(label) and _shannon_entropy(label) > 4.0:
                    base64_label_count += 1
                    break  # count once per query, not per label
    out["dns_base64_label_count"] = base64_label_count

    return out


def _http_signals(http_df: pd.DataFrame, pcap: str, packet_count: int) -> dict:
    out: dict = {"http_packet_count": packet_count}
    if http_df.empty:
        return out

    if "user_agent" in http_df.columns:
        out["http_unique_user_agent_count"] = int(http_df["user_agent"].nunique())

    if "method" in http_df.columns:
        out["http_plaintext_post_count"] = int((http_df["method"] == "POST").sum())
        if "id.resp_h" in http_df.columns:
            post_dests = http_df.loc[http_df["method"] == "POST", "id.resp_h"].dropna()
            out["http_post_destinations"] = [str(ip) for ip in post_dests.unique().tolist()]

    # HTTP URIs containing base64-encoded components (C2 data encoding indicator).
    # Looks for contiguous base64-alphabet runs of 24+ chars in the URI path/query.
    # The `=` padding is optional; most C2 frameworks omit it.
    if "uri" in http_df.columns:
        _B64_URI_RE = re.compile(r'[A-Za-z0-9+/]{24,}={0,2}')
        out["http_base64_uri_count"] = int(
            http_df["uri"].dropna().apply(lambda u: bool(_B64_URI_RE.search(str(u)))).sum()
        )

    # Cleartext credentials — check via tshark (HTTP Basic Auth)
    try:
        rows = tshark_fields(pcap, "http.authorization", "ip.src", "ip.dst", "http.authorization")
        if rows:
            out["http_cleartext_creds_detected"] = True
    except Exception:
        pass

    return out


def _tls_signals(ssl_df: pd.DataFrame, x509_df: pd.DataFrame, packet_count: int) -> dict:
    out: dict = {"tls_packet_count": packet_count}
    if ssl_df.empty:
        return out

    if "ja3" in ssl_df.columns:
        out["tls_unique_ja3_count"] = int(ssl_df["ja3"].nunique())

    # Missing SNI (server_name field absent/empty) — C2 indicator
    if "server_name" in ssl_df.columns:
        missing_sni = ssl_df["server_name"].isna() | (ssl_df["server_name"] == "")
        out["tls_missing_sni_count"] = int(missing_sni.sum())

    # Cert anomalies: validation_status in ssl.log (requires Zeek cert verification package),
    # OR self-signed detection via x509.log subject==issuer join.
    if "validation_status" in ssl_df.columns:
        anomalies = ssl_df[ssl_df["validation_status"] != "ok"]
        out["tls_cert_anomaly_count"] = int(len(anomalies))
        if "id.resp_h" in anomalies.columns:
            out["tls_cert_anomaly_ips"] = list(anomalies["id.resp_h"].dropna().unique())
    elif not x509_df.empty and "certificate.subject" in x509_df.columns and "certificate.issuer" in x509_df.columns:
        # Detect self-signed: subject == issuer
        self_signed = x509_df[
            x509_df["certificate.subject"].notna() &
            x509_df["certificate.issuer"].notna() &
            (x509_df["certificate.subject"] == x509_df["certificate.issuer"])
        ]
        if not self_signed.empty and "fingerprint" in self_signed.columns and "cert_chain_fps" in ssl_df.columns:
            # Collect fingerprints of self-signed certs then join to ssl.log to get server IPs
            self_signed_fps = set(self_signed["fingerprint"].dropna().astype(str))
            anomaly_ips: list[str] = []
            for _, row in ssl_df.iterrows():
                fps = row.get("cert_chain_fps")
                if isinstance(fps, list):
                    chain = fps
                elif isinstance(fps, str):
                    try:
                        import json as _json
                        chain = _json.loads(fps)
                    except Exception:
                        chain = [fps]
                else:
                    continue
                if any(fp in self_signed_fps for fp in chain) and "id.resp_h" in ssl_df.columns:
                    ip = row.get("id.resp_h")
                    if ip and str(ip) not in ("nan", ""):
                        anomaly_ips.append(str(ip))
            out["tls_cert_anomaly_count"] = len(self_signed)
            out["tls_cert_anomaly_ips"] = list(dict.fromkeys(anomaly_ips))  # dedupe, preserve order

    # Keep top sessions for deep dive
    cols = [c for c in ["id.orig_h", "id.resp_h", "server_name", "ja3", "ja3s", "version"] if c in ssl_df.columns]
    out["tls_sessions"] = ssl_df[cols].head(50).to_dict("records")

    return out


def _smb_signals(smb_mapping_df: pd.DataFrame, ctx: AnalysisContext, packet_count: int) -> dict:
    out: dict = {"smb_packet_count": packet_count}
    if smb_mapping_df.empty:
        return out

    if "path" in smb_mapping_df.columns:
        admin_shares = smb_mapping_df["path"].str.upper().str.contains(
            r"ADMIN\$|C\$|IPC\$", na=False
        )
        out["smb_admin_share_detected"] = bool(admin_shares.any())

        # Internal SMB lateral movement: internal host accessing SMB on another internal host
        if "id.orig_h" in smb_mapping_df.columns and "id.resp_h" in smb_mapping_df.columns:
            lateral = smb_mapping_df[
                smb_mapping_df["id.orig_h"].isin(ctx.internal_ips)
                & smb_mapping_df["id.resp_h"].isin(ctx.internal_ips)
            ]
            out["smb_lateral_host_count"] = int(lateral["id.resp_h"].nunique())

    return out


def _scan_signals(conn_df: pd.DataFrame, ctx: AnalysisContext) -> dict:
    out: dict = {}
    if conn_df.empty:
        return out

    port_groups = (
        conn_df.groupby("id.orig_h")
        .agg(
            unique_dst_ports=("id.resp_p", "nunique"),
            unique_dst_hosts=("id.resp_h", "nunique"),
        )
        .reset_index()
        .rename(columns={"id.orig_h": "src"})
    )

    threshold_ports = ctx.thresholds.get("scan_unique_dst_ports", 15)
    threshold_hosts = ctx.thresholds.get("scan_unique_dst_hosts", 10)

    candidates = port_groups[
        (port_groups["unique_dst_ports"] >= threshold_ports)
        | (port_groups["unique_dst_hosts"] >= threshold_hosts)
    ].sort_values("unique_dst_ports", ascending=False)

    out["scan_candidate_count"] = int(len(candidates))
    out["scan_max_unique_dst_ports"] = int(port_groups["unique_dst_ports"].max())
    out["scan_max_unique_dst_hosts"] = int(port_groups["unique_dst_hosts"].max())
    out["scan_candidates"] = candidates.head(10).to_dict("records")

    # S0/REJ/RSTO/RSTOS0 states = SYN sent but no established connection.
    # Real nmap scans produce thousands; normal Windows telemetry almost never does.
    if "conn_state" in conn_df.columns:
        syn_only_states = {"S0", "REJ", "RSTO", "RSTOS0"}
        out["scan_syn_only_connection_count"] = int(
            conn_df["conn_state"].isin(syn_only_states).sum()
        )

    return out


def _exfil_signals(conn_df: pd.DataFrame, ctx: AnalysisContext) -> dict:
    out: dict = {"max_outbound_bytes": 0, "large_outbound_transfers": []}
    if conn_df.empty:
        return out

    threshold = ctx.thresholds.get("exfil_bytes_threshold", 10_000_000)

    # Internal → external, large orig_bytes, non-encrypted port
    if "orig_bytes" in conn_df.columns:
        conn_df = conn_df.copy()
        conn_df["orig_bytes"] = pd.to_numeric(conn_df["orig_bytes"], errors="coerce").fillna(0)
        large = conn_df[
            conn_df["id.orig_h"].isin(ctx.internal_ips)
            & conn_df["id.resp_h"].isin(ctx.external_ips)
            & conn_df["orig_bytes"].astype(float) > threshold
        ]
        if not large.empty:
            cols = [c for c in ["id.orig_h", "id.resp_h", "id.resp_p", "orig_bytes", "proto"] if c in large.columns]
            out["large_outbound_transfers"] = large[cols].head(10).to_dict("records")
            out["max_outbound_bytes"] = int(conn_df["orig_bytes"].max())

    return out


def _arp_signals(pcap: str, packet_count: int) -> dict:
    out: dict = {"arp_packet_count": packet_count}
    if packet_count == 0:
        return out

    try:
        # Gratuitous ARP: sender IP == target IP
        rows = tshark_fields(
            pcap,
            "arp.opcode == 1 and arp.src.proto_ipv4 == arp.dst.proto_ipv4",
            "arp.src.proto_ipv4", "arp.src.hw_mac",
        )
        out["arp_gratuitous_count"] = len(rows)

        # IP conflict: multiple MACs claiming same IP
        ip_to_macs: dict[str, set] = {}
        all_rows = tshark_fields(pcap, "arp", "arp.src.proto_ipv4", "arp.src.hw_mac")
        for row in all_rows:
            if len(row) >= 2 and row[0] and row[1]:
                ip_to_macs.setdefault(row[0], set()).add(row[1])
        out["arp_ip_conflict_count"] = sum(1 for macs in ip_to_macs.values() if len(macs) > 1)
    except Exception:
        pass

    return out


def _kerberos_signals(kerberos_df: pd.DataFrame, packet_count: int) -> dict:
    out: dict = {"kerberos_packet_count": packet_count}
    if kerberos_df.empty:
        return out

    # TGS-REQ is ticket-granting-service request — high volume = Kerberoasting candidate
    if "request_type" in kerberos_df.columns:
        tgs = kerberos_df[kerberos_df["request_type"] == "TGS"]
        out["kerberos_tgs_req_count"] = int(len(tgs))

        # RC4 (etype 17/23 shown as "rc4-hmac" or "aes128" etc in cipher field)
        if "cipher" in tgs.columns:
            rc4_mask = tgs["cipher"].str.lower().str.contains("rc4", na=False)
            out["kerberos_rc4_tgs_count"] = int(rc4_mask.sum())

        # Unique SPNs requested
        if "service" in tgs.columns:
            out["kerberos_unique_spn_count"] = int(tgs["service"].nunique())

    # Pre-auth failures: KDC_ERR_PREAUTH_FAILED — classic credential spraying indicator
    if "error_msg" in kerberos_df.columns:
        preauth_failed = kerberos_df["error_msg"].str.contains(
            "KDC_ERR_PREAUTH_FAILED", na=False
        )
        out["kerberos_preauth_failed_count"] = int(preauth_failed.sum())

    return out


def _cleartext_creds_signals(pcap: str) -> dict:
    out: dict = {"cleartext_creds_detected": False, "cleartext_proto_list": []}
    protos_with_creds = []

    # HTTP Basic Auth
    try:
        rows = tshark_fields(pcap, "http.authorization", "ip.src")
        if rows:
            protos_with_creds.append("http-basic-auth")
    except Exception:
        pass

    # FTP credentials (USER/PASS in cleartext)
    try:
        rows = tshark_fields(pcap, "ftp.request.command == \"USER\" or ftp.request.command == \"PASS\"", "ip.src")
        if rows:
            protos_with_creds.append("ftp")
    except Exception:
        pass

    if protos_with_creds:
        out["cleartext_creds_detected"] = True
        out["cleartext_proto_list"] = protos_with_creds

    return out


# ---------------------------------------------------------------------------
# Phase 2 entry point
# ---------------------------------------------------------------------------

def run(
    pcap_path: str,
    ctx: AnalysisContext,
    zeek_log_dir: Optional[str] = None,
) -> ProtocolSignals:
    """
    Run Phase 2 protocol analysis. Returns populated ProtocolSignals.
    If zeek_log_dir is None, runs Zeek internally (logs go to a temp dir).
    """
    pcap = str(Path(pcap_path).resolve())

    # Run Zeek if no pre-existing log dir provided
    if zeek_log_dir is None:
        log_dir = run_zeek(pcap)
    else:
        log_dir = Path(zeek_log_dir)

    log_dir_str = str(log_dir)

    # Parse all relevant logs up front
    conn_df = parse_conn_log(log_dir_str)
    dns_df = parse_dns_log(log_dir_str)
    ssl_df = parse_ssl_log(log_dir_str)
    x509_df = parse_log(f"{log_dir_str}/x509.log")
    http_df = parse_http_log(log_dir_str)
    smb_df = parse_log(f"{log_dir_str}/smb_mapping.log")
    kerberos_df = parse_log(f"{log_dir_str}/kerberos.log")

    # Protocol packet counts from AnalysisContext (already computed in phase1)
    pc = ctx.protocol_packet_counts

    signals = ProtocolSignals(
        zeek_log_dir=log_dir_str,
        logs_available=available_logs(log_dir_str),
    )

    # Merge all computed dicts into the dataclass
    def _merge(d: dict) -> None:
        for k, v in d.items():
            if hasattr(signals, k):
                setattr(signals, k, v)

    _merge(_dns_signals(dns_df, pc.get("dns", 0)))
    _merge(_http_signals(http_df, pcap, pc.get("http", 0)))
    _merge(_tls_signals(ssl_df, x509_df, pc.get("tls", 0)))
    _merge(_smb_signals(smb_df, ctx, pc.get("smb2", 0) + pc.get("smb", 0)))
    _merge(_scan_signals(conn_df, ctx))
    _merge(_exfil_signals(conn_df, ctx))
    _merge(_arp_signals(pcap, pc.get("arp", 0)))
    _merge(_cleartext_creds_signals(pcap))
    _merge(_kerberos_signals(kerberos_df, pc.get("kerberos", 0)))

    signals.icmp_packet_count = pc.get("icmp", 0)
    signals.drsuapi_packet_count = pc.get("drsuapi", 0)
    signals.rdp_packet_count = pc.get("rdp", 0)
    signals.ldap_packet_count = pc.get("ldap", 0)
    signals.cldap_packet_count = pc.get("cldap", 0)

    # FTP cleartext flag — promoted from cleartext_proto_list for playbook use
    signals.ftp_cleartext_detected = "ftp" in signals.cleartext_proto_list

    # ICMP large payload — tshark query for data.len > 512
    if signals.icmp_packet_count > 0:
        try:
            rows = tshark_fields(pcap, "icmp and data.len > 512", "ip.src", "data.len")
            signals.icmp_large_payload_count = len(rows)
        except Exception:
            pass

    # Beacon scoring (RITA-style) — requires conn.log with enough rows
    try:
        beacon_candidates = phase2_beacon.run(
            conn_df,
            internal_ips=ctx.internal_ips if ctx.internal_ips else None,
        )
        signals.beacon_candidates = [vars(b) for b in beacon_candidates]
        signals.beacon_top_score = beacon_candidates[0].composite_score if beacon_candidates else 0.0
    except Exception:
        pass

    # DCSync gate: count drsuapi sources that are NOT domain controllers.
    # DCs are identified by their role as Kerberos responders (port 88).
    # DC→DC drsuapi is normal AD replication; workstation/server→DC drsuapi = DCSync attack.
    if signals.drsuapi_packet_count > 0:
        dc_ips: set[str] = set()
        if not kerberos_df.empty and "id.resp_h" in kerberos_df.columns:
            dc_ips.update(str(ip) for ip in kerberos_df["id.resp_h"].dropna())
        try:
            drsuapi_rows = tshark_fields(pcap, "drsuapi", "ip.src", "ip.dst")
            attacker_sources = {
                row[0] for row in drsuapi_rows
                if len(row) >= 1 and row[0] and row[0] not in dc_ips
            }
            signals.drsuapi_attacker_source_count = len(attacker_sources)
        except Exception:
            # Fallback: if tshark fails, treat all drsuapi as potential attacker traffic
            signals.drsuapi_attacker_source_count = signals.drsuapi_packet_count

    # Cleartext HTTP on non-standard ports (80/8080 are expected; 443 cleartext is a red flag for RATs/C2)
    if signals.http_packet_count > 0:
        try:
            ns_http = tshark_fields(
                pcap,
                "http and tcp.dstport != 80 and tcp.dstport != 8080",
                "ip.src", "ip.dst", "tcp.dstport",
            )
            signals.http_on_nonstandard_port_count = len(ns_http)
        except Exception:
            pass

    # WinRM connections (port 5985 HTTP / 5986 HTTPS) — lateral movement via Windows Remote Management
    if not conn_df.empty and "id.resp_p" in conn_df.columns:
        winrm_mask = conn_df["id.resp_p"].isin([5985, 5986])
        signals.winrm_connection_count = int(winrm_mask.sum())

    # Inbound port scans: external IPs with S0/REJ/RSTO connections to >=5 distinct internal ports.
    # Distinguishes inbound recon (T1595) from outbound scanning (T1046).
    if not conn_df.empty and ctx.internal_ips and "id.orig_h" in conn_df.columns:
        internal_set = set(ctx.internal_ips)
        if "conn_state" in conn_df.columns and "id.resp_h" in conn_df.columns:
            inbound_scan_df = conn_df[
                (~conn_df["id.orig_h"].isin(internal_set)) &
                (conn_df["id.resp_h"].isin(internal_set)) &
                (conn_df["conn_state"].isin(["S0", "REJ", "RSTO"]))
            ]
            if not inbound_scan_df.empty and "id.resp_p" in inbound_scan_df.columns:
                src_port_counts = inbound_scan_df.groupby("id.orig_h")["id.resp_p"].nunique()
                signals.inbound_scan_unique_src_count = int((src_port_counts >= 5).sum())

    # Web service C2 platform lookups — DNS queries for Telegram/Discord/Pastebin/Slack APIs.
    # Legitimate use is possible but context (post-infection, combined with other signals) matters.
    _C2_SERVICE_DOMAINS = {
        "api.telegram.org", "t.me", "core.telegram.org",
        "discord.com", "discordapp.com", "cdn.discordapp.com",
        "pastebin.com", "rentry.co", "hastebin.com",
        "api.slack.com", "hooks.slack.com",
        "raw.githubusercontent.com",
    }
    if not dns_df.empty and "query" in dns_df.columns:
        signals.dns_c2_service_lookup_count = int(sum(
            1 for q in dns_df["query"].dropna()
            if any(
                str(q).lower() == svc or str(q).lower().endswith("." + svc)
                for svc in _C2_SERVICE_DOMAINS
            )
        ))

    return signals
