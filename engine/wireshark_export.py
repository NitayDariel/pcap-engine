"""
Wireshark Filter Export.
Generates a structured Markdown file of ready-to-paste Wireshark display filters
derived from the actual analysis results: victim IPs, DC IPs, suspicious domains,
findings, and deep dive evidence are all embedded directly into each filter string.

Generated after Phase 4 (deep dive) so that specific IPs and evidence are available.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.phase4_deep_dive import DeepDiveFinding
from engine.scorer import TTPScore


# ---------------------------------------------------------------------------
# Context extraction — pull concrete values from analysis results
# ---------------------------------------------------------------------------

def _primary_victim(ctx: AnalysisContext, signals: ProtocolSignals) -> str:
    """Most active internal host — typically the compromised machine."""
    for t in ctx.top_talkers:
        if t.get("src") in ctx.internal_ips:
            return t["src"]
    return sorted(ctx.internal_ips)[0] if ctx.internal_ips else "VICTIM_IP"


def _dc_ip(deep_dives: list[DeepDiveFinding]) -> Optional[str]:
    """Infer DC IP from SMB deep dive evidence (the target of SMB connections)."""
    for dd in deep_dives:
        if dd.ttp_id == "T1021.002" and dd.evidence:
            return str(dd.evidence[0].get("id.resp_h", ""))
    return None


def _scanner_ip(signals: ProtocolSignals) -> Optional[str]:
    """Primary scanning host from scan candidates."""
    if signals.scan_candidates:
        return str(signals.scan_candidates[0].get("src", ""))
    return None


def _suspicious_domains(signals: ProtocolSignals) -> list[str]:
    """Parent domains with high subdomain diversity."""
    return [d for d, count in signals.dns_top_domains if count > 10]


def _external_ips_in_findings(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    ttp_scores: list[TTPScore],
) -> list[str]:
    """External IPs from top talkers + large outbound — the IOC IPs."""
    ips: set[str] = set()
    for t in ctx.top_talkers[:12]:
        dst = t.get("dst", "")
        if dst in ctx.external_ips:
            ips.add(dst)
    for t in signals.large_outbound_transfers:
        ip = t.get("id.resp_h", "")
        if ip and ip in ctx.external_ips:
            ips.add(ip)
    return sorted(ips)


def _capture_time(ctx: AnalysisContext) -> tuple[str, str]:
    """Return (start_ts, end_ts) formatted for Wireshark frame.time filters."""
    def _fmt(ts: str) -> str:
        try:
            dt = datetime.fromisoformat(ts[:19].replace("T", " "))
            return dt.strftime("%b %d, %Y %H:%M:%S")
        except Exception:
            return ts[:19]
    return _fmt(ctx.capture_start), _fmt(ctx.capture_end)


# ---------------------------------------------------------------------------
# Filter block builders — each returns a list of (label, filter_string)
# ---------------------------------------------------------------------------

def _victim_filters(victim: str, ctx: AnalysisContext) -> list[tuple[str, str]]:
    internal_list = " || ".join(f"ip.addr == {ip}" for ip in sorted(ctx.internal_ips))
    return [
        ("All traffic to/from victim", f"ip.addr == {victim}"),
        ("Victim outbound only", f"ip.src == {victim}"),
        ("Victim inbound only", f"ip.dst == {victim}"),
        ("Victim to external hosts", f"ip.src == {victim} && !(" + " || ".join(f"ip.dst == {ip}" for ip in sorted(ctx.internal_ips)) + ")"),
        ("All internal network traffic", f"({internal_list})"),
        ("Victim → non-victim internal (lateral movement candidates)", f"ip.src == {victim} && ip.dst != {victim} && !(" + " || ".join(f"ip.dst == {ip}" for ip in sorted(ctx.internal_ips) if ip != victim) + ")") if len(ctx.internal_ips) > 1 else None,
    ]


def _protocol_filters(victim: str, signals: ProtocolSignals) -> list[tuple[str, str]]:
    filters = []

    if signals.dns_packet_count > 0:
        filters += [
            ("DNS — all queries from victim", f"ip.src == {victim} && dns"),
            ("DNS — TXT record queries (exfil/tunnel)", f"ip.src == {victim} && dns.qry.type == 16"),
            ("DNS — NULL record queries", f"ip.src == {victim} && dns.qry.type == 10"),
            ("DNS — NXDOMAIN responses (DGA/C2 cycling)", f"dns.flags.rcode == 3 && ip.addr == {victim}"),
            ("DNS — long queries > 30 chars (encoded data)", f"dns.qry.name.len > 30 && ip.src == {victim}"),
            ("DNS — all responses to victim", f"ip.dst == {victim} && dns.flags.response == 1"),
        ]

    if signals.http_packet_count > 0:
        filters += [
            ("HTTP — all from victim", f"ip.src == {victim} && http"),
            ("HTTP — POST requests only (uploads/C2)", f"ip.src == {victim} && http.request.method == \"POST\""),
            ("HTTP — cleartext auth headers", "http.authorization"),
            ("HTTP — response errors (4xx/5xx)", f"http.response.code >= 400 && ip.addr == {victim}"),
            ("HTTP — user agent strings", f"ip.src == {victim} && http.user_agent"),
        ]

    if signals.tls_packet_count > 0:
        filters += [
            ("TLS — all from victim", f"ip.src == {victim} && tls"),
            ("TLS — ClientHello (session start)", f"ip.src == {victim} && tls.handshake.type == 1"),
            ("TLS — missing SNI (C2 implant signature)", f"tls.handshake.type == 1 && !tls.handshake.extensions_server_name"),
            ("TLS — certificate records (inspect validity)", f"ip.addr == {victim} && tls.handshake.type == 11"),
            ("TLS — application data (payload, size analysis)", f"ip.src == {victim} && tls.record.content_type == 23"),
        ]

    if signals.smb_packet_count > 0:
        filters += [
            ("SMB — all traffic involving victim", f"ip.addr == {victim} && (smb || smb2)"),
            ("SMB2 — tree connect (share enumeration)", f"ip.addr == {victim} && smb2 && smb2.cmd == 3"),
            ("SMB2 — file operations (create/read/write)", f"ip.addr == {victim} && smb2 && smb2.cmd == 5"),
            ("SMB2 — named pipe activity (DCE/RPC relay)", f"ip.addr == {victim} && smb2 && smb2.fid"),
        ]

    if signals.kerberos_packet_count > 0:
        filters += [
            ("Kerberos — all from victim", f"ip.src == {victim} && kerberos"),
            ("Kerberos — AS-REQ (initial auth)", f"ip.src == {victim} && kerberos && kerberos.msg_type == 10"),
            ("Kerberos — TGS-REQ (service tickets — Kerberoasting)", f"ip.src == {victim} && kerberos && kerberos.msg_type == 12"),
            ("Kerberos — errors (pre-auth failures — brute force)", f"ip.addr == {victim} && kerberos && kerberos.msg_type == 30"),
        ]

    if signals.arp_packet_count > 0:
        filters += [
            ("ARP — all requests", "arp && arp.opcode == 1"),
            ("ARP — from victim (sweep)", f"arp.src.proto_ipv4 == {victim}"),
            ("ARP — gratuitous (sender == target, MITM/poisoning)", "arp.opcode == 1 && arp.src.proto_ipv4 == arp.dst.proto_ipv4"),
            ("ARP — replies only", "arp.opcode == 2"),
        ]

    if signals.icmp_packet_count > 0:
        filters += [
            ("ICMP — all", "icmp"),
            ("ICMP — echo requests from victim (ping sweep)", f"icmp.type == 8 && ip.src == {victim}"),
            ("ICMP — large payloads > 512B (tunnel indicator)", f"icmp && frame.len > 560"),
        ]

    if signals.drsuapi_packet_count > 0:
        filters += [
            ("DRSUAPI — DCSync protocol ALL (always suspicious)", "drsuapi"),
            ("DRSUAPI — from victim", f"ip.src == {victim} && drsuapi"),
            ("DCERPC — underlying transport (DCSync)", f"dcerpc && ip.src == {victim}"),
        ]

    if signals.ldap_packet_count > 0 or signals.cldap_packet_count > 0:
        filters += [
            ("LDAP — all queries (AD enumeration)", f"ldap && ip.src == {victim}"),
            ("CLDAP — DC locator queries (UDP LDAP)", f"cldap && ip.src == {victim}"),
            ("LDAP — bind requests (authentication)", f"ip.src == {victim} && ldap"),
        ]

    if signals.rdp_packet_count > 0:
        filters += [
            ("RDP — all sessions", f"tcp.port == 3389"),
            ("RDP — initiated by victim", f"ip.src == {victim} && tcp.dstport == 3389"),
            ("RDP — protocol dissected", f"rdp && ip.addr == {victim}"),
        ]

    return [f for f in filters if f is not None]


def _ttp_filters(
    ttp_scores: list[TTPScore],
    deep_dives: list[DeepDiveFinding],
    victim: str,
    scanner: Optional[str],
    dc: Optional[str],
    domains: list[str],
) -> list[tuple[str, list[tuple[str, str]]]]:
    """Build per-TTP filter sections. Returns list of (ttp_label, [(label, filter)])."""
    dd_map = {dd.ttp_id: dd for dd in deep_dives}
    fired = [r for r in ttp_scores if r.score >= 0.35]
    fired_sorted = sorted(fired, key=lambda r: -r.score)
    sections = []

    for r in fired_sorted:
        filters: list[tuple[str, str]] = []
        src = scanner if scanner and r.ttp_id == "T1046" else victim

        if r.ttp_id == "T1046":
            dd = dd_map.get("T1046")
            hosts_sample = ""
            if dd and dd.evidence:
                sample = dd.evidence[0].get("unique_dst_hosts_sample", [])[:5]
                if sample:
                    hosts_sample = " || ".join(f"ip.addr == {h}" for h in sample)
            filters = [
                ("SYN-only packets (failed scan attempts, S0 state)", f"ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0"),
                ("All TCP from scanner", f"ip.src == {src} && tcp"),
                ("UDP discovery probes", f"ip.src == {src} && udp"),
                ("Scanner to specific top targets", f"ip.src == {src} && ({hosts_sample})" if hosts_sample else ""),
                ("ICMP ping sweep from scanner", f"ip.src == {src} && icmp.type == 8"),
            ]

        elif r.ttp_id == "T1071.004":
            domain_filters = []
            for d in domains[:3]:
                domain_filters.append((f"DNS queries to suspicious domain: {d}", f'dns.qry.name contains "{d}"'))
            filters = [
                ("DNS TXT queries (tunneling/exfil channel)", f"ip.src == {victim} && dns.qry.type == 16"),
                ("DNS NULL queries (alternative tunnel type)", f"ip.src == {victim} && dns.qry.type == 10"),
                ("Long subdomain queries > 40 chars", f"ip.src == {victim} && dns.qry.name.len > 40"),
                ("NXDOMAIN failures (C2 domain cycling)", f"dns.flags.rcode == 3 && ip.src == {victim}"),
                *domain_filters,
            ]

        elif r.ttp_id == "T1021.002":
            dc_part = f" && ip.addr == {dc}" if dc else ""
            filters = [
                ("All SMB between victim and DC", f"ip.addr == {victim}{dc_part} && (smb || smb2)"),
                ("SMB admin shares (IPC$, ADMIN$, C$)", f"(smb || smb2) && ip.src == {victim}"),
                ("SMB2 tree connect (share access)", f"ip.src == {victim} && smb2 && smb2.cmd == 3"),
                ("Named pipe via SMB (remote execution)", f"ip.src == {victim} && smb2 && smb2.fid"),
                ("SMB file transfers", f"ip.src == {victim} && smb2 && smb2.cmd == 5"),
            ]

        elif r.ttp_id == "T1040":
            filters = [
                ("HTTP Basic Auth (cleartext credentials in header)", "http.authorization"),
                ("FTP USER command (username in cleartext)", 'ftp.request.command == "USER"'),
                ("FTP PASS command (password in cleartext)", 'ftp.request.command == "PASS"'),
                ("All cleartext auth from victim", f"ip.src == {victim} && (http.authorization || ftp.request.command)"),
            ]

        elif r.ttp_id == "T1048.003":
            filters = [
                ("HTTP POST from victim (plaintext uploads)", f'ip.src == {victim} && http.request.method == "POST"'),
                ("Large HTTP responses (inbound data)", f"ip.dst == {victim} && http && http.content_length > 1000"),
                ("All HTTP body content", f"ip.src == {victim} && http.file_data"),
            ]

        elif r.ttp_id == "T1558.003":
            filters = [
                ("All Kerberos from victim", f"ip.src == {victim} && kerberos"),
                ("TGS-REQ (service ticket requests — Kerberoasting)", f"ip.src == {victim} && kerberos && kerberos.msg_type == 12"),
                ("TGS-REP (service ticket responses — contains hash)", f"ip.dst == {victim} && kerberos && kerberos.msg_type == 13"),
                ("AS-REQ (initial tickets)", f"ip.src == {victim} && kerberos && kerberos.msg_type == 10"),
            ]

        elif r.ttp_id == "T1110.001":
            filters = [
                ("Kerberos pre-auth failures (wrong password)", f"kerberos.msg_type == 30 && ip.addr == {victim}"),
                ("Rapid AS-REQ bursts (brute force indicator)", f"ip.src == {victim} && kerberos && kerberos.msg_type == 10"),
            ]

        elif r.ttp_id == "T1557":
            filters = [
                ("All ARP traffic", "arp"),
                ("Gratuitous ARP (sender IP == target IP — poisoning)", "arp.opcode == 1 && arp.src.proto_ipv4 == arp.dst.proto_ipv4"),
                ("ARP from victim (active poisoner)", f"arp.src.proto_ipv4 == {victim}"),
                ("ARP replies (unsolicited = suspicious)", "arp.opcode == 2"),
            ]

        elif r.ttp_id == "T1095":
            filters = [
                ("All ICMP", f"icmp && ip.addr == {victim}"),
                ("Oversized ICMP (> 512B payload — tunneling)", f"icmp && frame.len > 560 && ip.addr == {victim}"),
                ("ICMP echo requests only", f"icmp.type == 8 && ip.src == {victim}"),
                ("ICMP echo replies", f"icmp.type == 0 && ip.dst == {victim}"),
            ]

        elif r.ttp_id == "T1071.001":
            filters = [
                ("HTTP POST from victim (C2 uploads)", f'ip.src == {victim} && http.request.method == "POST"'),
                ("HTTP GET from victim (C2 polling)", f'ip.src == {victim} && http.request.method == "GET"'),
                ("HTTP user agent strings (check for static/suspicious)", f"ip.src == {victim} && http.user_agent"),
                ("HTTP cleartext credentials", f"ip.src == {victim} && http.authorization"),
            ]

        elif r.ttp_id == "T1003.006":
            dc_part = f" && ip.dst == {dc}" if dc else ""
            filters = [
                ("DRSUAPI — DCSync protocol (ANY occurrence is suspicious)", "drsuapi"),
                ("DRSUAPI from victim (non-DC host running DCSync)", f"ip.src == {victim} && drsuapi"),
                ("DCERPC calls from victim to DC", f"ip.src == {victim}{dc_part} && dcerpc"),
                ("MS-DRSR interface UUID (definitive DCSync filter)", 'dcerpc.cn_if_id == "e3514235-4b06-11d1-ab04-00c04fc2dcd2"'),
            ]

        elif r.ttp_id == "T1573.001":
            filters = [
                ("TLS without SNI — C2 implant signature", "tls.handshake.type == 1 && !tls.handshake.extensions_server_name"),
                ("TLS ClientHello from victim (all TLS initiations)", f"ip.src == {victim} && tls.handshake.type == 1"),
                ("TLS Certificate (inspect for self-signed/expired)", f"ip.addr == {victim} && tls.handshake.type == 11"),
                ("TLS data records (actual payload — size analysis)", f"ip.src == {victim} && tls.record.content_type == 23"),
            ]

        elif r.ttp_id == "T1018":
            filters = [
                ("ARP who-has requests from victim (host sweep)", f"arp.src.proto_ipv4 == {victim} && arp.opcode == 1"),
                ("ICMP ping sweep from victim", f"ip.src == {victim} && icmp.type == 8"),
                ("All outbound discovery probes", f"ip.src == {victim} && (arp || icmp.type == 8)"),
            ]

        elif r.ttp_id == "T1041":
            filters = [
                ("Large TLS outbound from victim", f"ip.src == {victim} && tls && frame.len > 1000"),
                ("TLS application data only (payload transfer)", f"ip.src == {victim} && tls.record.content_type == 23"),
                ("Sustained TLS to external IPs", f"ip.src == {victim} && tls"),
            ]

        elif r.ttp_id == "T1048.001":
            domain_filters = []
            for d in domains[:3]:
                domain_filters.append((f"Suspicious exfil domain: {d}", f'dns.qry.name contains "{d}"'))
            filters = [
                ("DNS TXT queries (exfil channel)", f"ip.src == {victim} && dns.qry.type == 16"),
                ("Long subdomain queries (encoded exfil data)", f"ip.src == {victim} && dns.qry.name.len > 50"),
                *domain_filters,
            ]

        elif r.ttp_id == "T1049":
            filters = [
                ("LDAP queries (AD enumeration)", f"ldap && ip.src == {victim}"),
                ("CLDAP (connectionless LDAP — DC locator)", f"cldap && ip.src == {victim}"),
                ("LDAP + CLDAP combined", f"(ldap || cldap) && ip.src == {victim}"),
            ]

        elif r.ttp_id == "T1135":
            dc_part = f" && ip.addr == {dc}" if dc else ""
            filters = [
                ("SMB share enumeration from victim", f"ip.src == {victim} && (smb || smb2)"),
                ("SMB2 tree connect (share listing)", f"ip.src == {victim} && smb2 && smb2.cmd == 3"),
                ("NetBIOS name queries (share discovery via NetBIOS)", f"nbns && ip.src == {victim}"),
                (f"Victim → DC SMB only", f"ip.src == {victim}{dc_part} && (smb || smb2)"),
            ]

        elif r.ttp_id == "T1008":
            filters = [
                ("All potential C2 traffic from victim (DNS+HTTP+TLS)", f"ip.src == {victim} && (dns || http || tls)"),
                ("DNS C2 component", f"ip.src == {victim} && dns.qry.type == 16"),
                ("HTTP C2 component", f'ip.src == {victim} && http.request.method == "POST"'),
                ("TLS C2 component", f"ip.src == {victim} && tls.handshake.type == 1 && !tls.handshake.extensions_server_name"),
            ]

        elif r.ttp_id == "T1021.001":
            dc_part = f" || ip.addr == {dc}" if dc else ""
            filters = [
                ("All RDP traffic", "tcp.port == 3389"),
                ("RDP initiated by victim", f"ip.src == {victim} && tcp.dstport == 3389"),
                ("RDP protocol dissected", f"rdp && ip.addr == {victim}"),
            ]

        elif r.ttp_id == "T1056.003":
            filters = [
                ("HTTP cleartext credentials (confirmed exposure)", "http.authorization"),
                ("HTTP POST with auth (portal capture pattern)", f'ip.src == {victim} && http.request.method == "POST"'),
                ("All credential-carrying HTTP", f"ip.src == {victim} && (http.authorization || http.request.method)"),
            ]

        # Remove empty strings
        filters = [(lbl, f) for lbl, f in filters if f]

        if filters:
            label = f"{r.ttp_id} — {r.name} [{r.confidence}, score={r.score:.2f}]"
            sections.append((label, filters))

    return sections


def _combination_filters(
    victim: str,
    scanner: Optional[str],
    dc: Optional[str],
    domains: list[str],
    ttp_scores: list[TTPScore],
) -> list[tuple[str, str]]:
    """Pre-built complex AND/OR filters for common investigation workflows."""
    fired_ids = {r.ttp_id for r in ttp_scores if r.score >= 0.35}
    filters = []

    filters.append((
        "Everything suspicious — all anomalous protocol mix from victim",
        f"ip.src == {victim} && (dns.qry.type == 16 || (tls.handshake.type == 1 && !tls.handshake.extensions_server_name) || http.authorization || drsuapi || kerberos.msg_type == 12)"
    ))

    if "T1046" in fired_ids:
        src = scanner or victim
        filters.append((
            "Port scan evidence — SYN-only from scanner to any external",
            f"ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0"
        ))

    if "T1003.006" in fired_ids or "T1021.002" in fired_ids:
        dc_part = f" && (ip.src == {victim} || ip.dst == {victim})" if dc else ""
        filters.append((
            "Lateral movement chain — victim SMB + Kerberos + DCSync combined",
            f"ip.addr == {victim} && (smb2 || kerberos || drsuapi)"
        ))

    if any(t in fired_ids for t in ["T1071.004", "T1048.001"]):
        filters.append((
            "DNS exfil/tunnel — all unusual DNS from victim",
            f"ip.src == {victim} && dns && (dns.qry.type == 16 || dns.qry.name.len > 30 || dns.flags.rcode == 3)"
        ))
        if domains:
            filters.append((
                f"Suspicious C2/exfil domain filter: {', '.join(domains[:3])}",
                " || ".join(f'dns.qry.name contains "{d}"' for d in domains[:3])
            ))

    if "T1558.003" in fired_ids:
        filters.append((
            "Kerberoasting session — TGS-REQ + TGS-REP pair (contains crackable hash)",
            f"ip.addr == {victim} && kerberos && (kerberos.msg_type == 12 || kerberos.msg_type == 13)"
        ))

    if "T1040" in fired_ids or "T1056.003" in fired_ids:
        filters.append((
            "Credential exposure — all cleartext auth events",
            f"ip.addr == {victim} && (http.authorization || ftp.request.command)"
        ))

    if "T1573.001" in fired_ids or "T1041" in fired_ids:
        filters.append((
            "TLS C2 / encrypted exfil — suspicious TLS from victim",
            f"ip.src == {victim} && (tls.handshake.type == 1 && !tls.handshake.extensions_server_name)"
        ))

    return filters


def _ioc_ip_filters(
    external_ips: list[str],
    victim: str,
) -> list[tuple[str, str]]:
    filters = []
    for ip in external_ips[:15]:
        filters.append((
            f"All traffic to/from {ip}",
            f"ip.addr == {ip}"
        ))
        filters.append((
            f"Victim → {ip} only (directional)",
            f"ip.src == {victim} && ip.dst == {ip}"
        ))
    # Mega-filter: all suspicious external IPs at once
    if external_ips:
        mega = " || ".join(f"ip.addr == {ip}" for ip in external_ips[:10])
        filters.append((
            "ALL suspicious external IPs in one filter",
            f"({mega}) && ip.addr == {victim}"
        ))
    return filters


def _domain_filters(domains: list[str]) -> list[tuple[str, str]]:
    filters = []
    for d in domains[:10]:
        filters.append((f"All DNS queries for domain: {d}", f'dns.qry.name contains "{d}"'))
    if domains:
        filters.append((
            "All suspicious domains in one filter",
            " || ".join(f'dns.qry.name contains "{d}"' for d in domains[:5])
        ))
    return filters


def _time_filters(ctx: AnalysisContext) -> list[tuple[str, str]]:
    start, end = _capture_time(ctx)
    filters = [
        ("Full capture window", f'frame.time >= "{start}" && frame.time <= "{end}"'),
        ("First 10 minutes of capture", f'frame.time >= "{start}" && frame.time_relative <= 600'),
        ("Last 10 minutes of capture", f'frame.time_relative >= {max(0, int(ctx.capture_duration_secs) - 600)}'),
    ]
    return filters


# ---------------------------------------------------------------------------
# Markdown assembly
# ---------------------------------------------------------------------------

def _block(label: str, filter_str: str) -> str:
    return f"**{label}**\n```\n{filter_str}\n```\n"


def generate(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    ttp_scores: list[TTPScore],
    deep_dives: list[DeepDiveFinding],
) -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_name = Path(ctx.pcap_path).name

    victim = _primary_victim(ctx, signals)
    dc = _dc_ip(deep_dives)
    scanner = _scanner_ip(signals)
    domains = _suspicious_domains(signals)
    external_ips = _external_ips_in_findings(ctx, signals, ttp_scores)
    fired_count = len([r for r in ttp_scores if r.score >= 0.35])

    lines = [
        f"# Wireshark Display Filters — {pcap_name}",
        f"",
        f"Generated: {now}  |  Victim: `{victim}`"
        + (f"  |  DC: `{dc}`" if dc else "")
        + (f"  |  Scanner: `{scanner}`" if scanner and scanner != victim else ""),
        f"",
        f"> Paste any filter directly into the Wireshark display filter bar.",
        f"> Combine with `&&` (AND) or `||` (OR). Negate with `!`.",
        f"> All filters are pre-populated with IPs and values from this specific capture.",
        f"",
        f"---",
        f"",
    ]

    # ── Quick Reference ───────────────────────────────────────────────────
    lines.append("## Quick Reference\n")
    lines.append("| Purpose | Filter |")
    lines.append("|---|---|")
    lines.append(f"| All victim traffic | `ip.addr == {victim}` |")
    lines.append(f"| Victim outbound | `ip.src == {victim}` |")
    if dc:
        lines.append(f"| Victim ↔ DC (lateral movement) | `ip.addr == {victim} && ip.addr == {dc}` |")
    lines.append(f"| DNS TXT queries (tunnel/exfil) | `ip.src == {victim} && dns.qry.type == 16` |")
    lines.append(f"| TLS without SNI (C2 implant) | `tls.handshake.type == 1 && !tls.handshake.extensions_server_name` |")
    lines.append(f"| SYN-only scan packets | `ip.src == {scanner or victim} && tcp.flags.syn == 1 && tcp.flags.ack == 0` |")
    lines.append(f"| Cleartext credentials | `http.authorization` |")
    lines.append(f"| Kerberoasting (TGS tickets) | `ip.src == {victim} && kerberos && kerberos.msg_type == 12` |")
    if signals.drsuapi_packet_count > 0:
        lines.append(f"| DCSync (DRSUAPI — CRITICAL) | `drsuapi` |")
    if domains:
        lines.append(f"| Suspicious domain | `dns.qry.name contains \"{domains[0]}\"` |")
    beacon_candidates = signals.beacon_candidates or []
    if beacon_candidates:
        top_b = beacon_candidates[0]
        lines.append(
            f"| Beacon #{1} (score {top_b['composite_score']:.3f}) "
            f"| `ip.src == {top_b['src_ip']} && ip.dst == {top_b['dst_ip']}` |"
        )
    lines.append("")

    # ── Section 1: Victim Overview ────────────────────────────────────────
    lines.append("---\n## 1. Victim Host Overview\n")
    for lbl, f in _victim_filters(victim, ctx):
        if f:
            lines.append(_block(lbl, f))

    # ── Section 2: Per-TTP Investigation ─────────────────────────────────
    lines.append("---\n## 2. Per-Finding Investigation Filters\n")
    lines.append(f"*{fired_count} TTPs fired — one section per finding, ordered by score.*\n")

    ttp_sections = _ttp_filters(ttp_scores, deep_dives, victim, scanner, dc, domains)
    for section_label, section_filters in ttp_sections:
        lines.append(f"### {section_label}\n")
        for lbl, f in section_filters:
            lines.append(_block(lbl, f))

    # ── Section 3: Suspicious External IPs ───────────────────────────────
    lines.append("---\n## 3. Suspicious External IP Filters\n")
    lines.append("*External IPs seen in significant volume or associated with findings.*\n")
    if external_ips:
        for lbl, f in _ioc_ip_filters(external_ips, victim):
            lines.append(_block(lbl, f))
    else:
        lines.append("_No suspicious external IPs identified._\n")

    # ── Section 4: Suspicious DNS Domains ────────────────────────────────
    lines.append("---\n## 4. Suspicious Domain Filters\n")
    if domains:
        for lbl, f in _domain_filters(domains):
            lines.append(_block(lbl, f))
    else:
        lines.append("_No suspicious domains with high subdomain diversity detected._\n")

    # ── Section 5: Protocol Deep Dives ────────────────────────────────────
    lines.append("---\n## 5. Protocol Deep Dive Filters\n")
    lines.append("*Comprehensive per-protocol filters with victim IP pre-filled.*\n")
    for lbl, f in _protocol_filters(victim, signals):
        lines.append(_block(lbl, f))

    # ── Section 6: Combination Filters ───────────────────────────────────
    lines.append("---\n## 6. Combination Filters (Investigation Workflows)\n")
    lines.append("*Pre-built AND/OR combinations for common investigation scenarios.*\n")
    for lbl, f in _combination_filters(victim, scanner, dc, domains, ttp_scores):
        lines.append(_block(lbl, f))

    # ── Section 7: Time Scoping ───────────────────────────────────────────
    lines.append("---\n## 7. Time-Scoped Filters\n")
    lines.append(f"*Capture window: `{ctx.capture_start[:19]}` → `{ctx.capture_end[:19]}`*\n")
    for lbl, f in _time_filters(ctx):
        lines.append(_block(lbl, f))

    # ── Section 8: Beacon Candidates ─────────────────────────────────────
    beacon_candidates = signals.beacon_candidates or []
    if beacon_candidates:
        lines.append("---\n## 8. Beacon Analysis Filters\n")
        lines.append(
            f"*{len(beacon_candidates)} beacon candidate(s) detected. "
            f"Top score: **{signals.beacon_top_score:.3f}**. "
            f"Filters isolate each beaconing conversation for Wireshark timeline analysis.*\n"
        )
        for i, b in enumerate(beacon_candidates[:5], 1):
            src = b["src_ip"]
            dst = b["dst_ip"]
            port = b["dst_port"]
            interval = b["modal_interval_secs"]
            score = b["composite_score"]
            lines.append(f"### Beacon #{i} — {src} → {dst}:{port} (score {score:.3f})\n")
            lines.append(_block(
                f"All traffic between {src} and {dst}",
                f"ip.src == {src} && ip.dst == {dst}",
            ))
            lines.append(_block(
                f"Specific port {port} only (beacon channel)",
                f"ip.src == {src} && ip.dst == {dst} && tcp.dstport == {port}",
            ))
            lines.append(_block(
                f"All outbound from beacon host {src}",
                f"ip.src == {src} && !ip.dst == {victim}",
            ))
            lines.append(_block(
                f"Beacon host {src} — any connection to port {port} (all destinations)",
                f"ip.src == {src} && tcp.dstport == {port}",
            ))
            if b.get("fft_period_secs", 0) > 0:
                lines.append(
                    f"> **FFT-detected period**: {b['fft_period_secs']:.0f}s "
                    f"(modal interval: {interval:.0f}s ±{b['interval_jitter_secs']:.0f}s jitter). "
                    f"Use Wireshark → Statistics → IO Graph with {interval:.0f}s buckets to visualize.\n"
                )
            else:
                lines.append(
                    f"> **Modal interval**: {interval:.0f}s ±{b['interval_jitter_secs']:.0f}s jitter. "
                    f"Use Wireshark → Statistics → IO Graph with {interval:.0f}s buckets to visualize.\n"
                )

    return "\n".join(lines)


def write(content: str, output_dir: str) -> str:
    """Write wireshark_filters.md to output_dir. Returns file path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "wireshark_filters.md"
    path.write_text(content)
    return str(path)
