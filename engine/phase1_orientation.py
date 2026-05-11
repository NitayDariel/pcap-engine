"""
Phase 1 — Orientation.
Builds AnalysisContext: the single source of truth that feeds all downstream phases.
All thresholds, host classifications, and protocol presence flags originate here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from engine.utils.tshark import (
    run as tshark_run,
    fields as tshark_fields,
    protocol_histogram,
    conversation_matrix,
    unique_ips,
    capture_duration,
)
from engine.phase0_whitelist import Whitelist, WhitelistResult
from engine.calibrator import calibrate


# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------

@dataclass
class AnalysisContext:
    pcap_path: str
    file_size_bytes: int
    capture_duration_secs: float
    total_packets: int
    total_flows: int

    # Host inventory
    all_ips: set[str] = field(default_factory=set)
    internal_ips: set[str] = field(default_factory=set)
    external_ips: set[str] = field(default_factory=set)
    mac_to_ip: dict[str, list[str]] = field(default_factory=dict)
    ip_to_hostname: dict[str, str] = field(default_factory=dict)
    ip_to_os_hint: dict[str, str] = field(default_factory=dict)

    # Protocol map
    protocols_present: set[str] = field(default_factory=set)
    protocol_packet_counts: dict[str, int] = field(default_factory=dict)
    protocol_byte_counts: dict[str, int] = field(default_factory=dict)
    nonstandard_port_protocols: list[dict] = field(default_factory=list)

    # Conversation matrix (sorted by bytes, descending)
    top_talkers: list[dict] = field(default_factory=list)
    internal_to_external: list[dict] = field(default_factory=list)
    internal_to_internal: list[dict] = field(default_factory=list)

    # Timing (raw strings from tshark)
    capture_start: str = ""
    capture_end: str = ""

    # Phase 0 output
    whitelist: Optional[WhitelistResult] = None

    # Calibrated thresholds (set by calibrate())
    thresholds: dict = field(default_factory=dict)

    # Visibility
    visibility_pct: float = 100.0
    encrypted_pct: float = 0.0


# ---------------------------------------------------------------------------
# Internal parsing helpers
# ---------------------------------------------------------------------------

def _parse_bytes_str(s: str) -> int:
    """Parse tshark byte strings: '570 kB', '1.2 MB', '12345' → int bytes."""
    s = s.strip()
    m = re.match(r"([\d.]+)\s*(\w*)", s)
    if not m:
        return 0
    val = float(m.group(1))
    unit = m.group(2).lower()
    multipliers = {"kb": 1_000, "mb": 1_000_000, "gb": 1_000_000_000}
    return int(val * multipliers.get(unit, 1))


def _parse_protocol_histogram(raw: str) -> tuple[int, int, dict, dict]:
    """
    Parse io,phs output.
    Returns (total_packets, total_bytes, frame_counts{proto}, byte_counts{proto})
    """
    frame_counts: dict[str, int] = {}
    byte_counts: dict[str, int] = {}
    total_packets = 0
    total_bytes = 0

    for line in raw.splitlines():
        m = re.match(r"\s*(\w[\w./-]*)\s+frames:(\d+)\s+bytes:(\d+)", line)
        if m:
            proto = m.group(1).lower()
            frames = int(m.group(2))
            byt = int(m.group(3))
            frame_counts[proto] = frames
            byte_counts[proto] = byt
            if proto == "frame":
                total_packets = frames
                total_bytes = byt

    return total_packets, total_bytes, frame_counts, byte_counts


def _parse_conversation_matrix(raw: str) -> list[dict]:
    """
    Parse conv,ip output into list of conversation dicts.
    Each dict: src, dst, frames_total, bytes_total, duration_secs, rel_start.
    """
    convs = []
    ip_pat = r"(\d{1,3}(?:\.\d{1,3}){3})"
    # Each data line: IP <-> IP  N bytes  N bytes  N bytes  rel_start  duration
    pattern = re.compile(
        rf"{ip_pat}\s+<->\s+{ip_pat}"
        r"\s+(\d+)\s+([\d.]+\s*\w*)"    # frames_back, bytes_back
        r"\s+(\d+)\s+([\d.]+\s*\w*)"    # frames_fwd,  bytes_fwd
        r"\s+(\d+)\s+([\d.]+\s*\w*)"    # frames_total, bytes_total
        r"\s+([\d.]+)\s+([\d.]+)"        # rel_start, duration
    )

    for line in raw.splitlines():
        m = pattern.search(line)
        if m:
            convs.append({
                "src": m.group(1),
                "dst": m.group(2),
                "frames_back": int(m.group(3)),
                "bytes_back": _parse_bytes_str(m.group(4)),
                "frames_fwd": int(m.group(5)),
                "bytes_fwd": _parse_bytes_str(m.group(6)),
                "frames_total": int(m.group(7)),
                "bytes_total": _parse_bytes_str(m.group(8)),
                "rel_start": float(m.group(9)),
                "duration_secs": float(m.group(10)),
            })

    return sorted(convs, key=lambda x: x["bytes_total"], reverse=True)


def _clean_ips(raw_ips: set[str]) -> set[str]:
    """
    Remove non-IP junk tshark sometimes emits (comma-joined values, blank strings).
    Only returns strings that look like valid IPv4 addresses.
    """
    ipv4_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    clean = set()
    for entry in raw_ips:
        for part in entry.split(","):
            part = part.strip()
            if ipv4_re.match(part):
                clean.add(part)
    return clean


def _ttl_to_os(ttl_str: str) -> str:
    """Map a raw TTL value to a likely OS family."""
    try:
        ttl = int(ttl_str)
    except (ValueError, TypeError):
        return "unknown"
    if ttl <= 32:
        return "windows-old/printer"
    elif ttl <= 64:
        return "linux/macos"
    elif ttl <= 128:
        return "windows"
    else:
        return "network-device"


def _calc_visibility(byte_counts: dict[str, int]) -> tuple[float, float]:
    """
    Estimate visibility and encryption percentages.
    Encrypted = TLS + QUIC. Everything else is potentially analyzable.
    Returns (visibility_pct, encrypted_pct).
    """
    total = byte_counts.get("frame", 1)
    encrypted = byte_counts.get("tls", 0) + byte_counts.get("quic", 0)
    encrypted_pct = round(min(encrypted / total * 100, 100.0), 1)
    return round(100.0 - encrypted_pct, 1), encrypted_pct


# ---------------------------------------------------------------------------
# Phase 1 entry point
# ---------------------------------------------------------------------------

def run(
    pcap_path: str,
    whitelist_config: Optional[str] = None,
) -> AnalysisContext:
    """
    Run full Phase 1 orientation against a PCAP.
    Returns a populated AnalysisContext ready for Phase 2+.
    """
    pcap = str(Path(pcap_path).resolve())

    # --- File metadata ---
    file_size = os.path.getsize(pcap)

    # --- Protocol histogram ---
    hist_raw = protocol_histogram(pcap)
    total_packets, total_bytes, frame_counts, byte_counts = _parse_protocol_histogram(hist_raw)

    # --- Conversation matrix ---
    conv_raw = conversation_matrix(pcap)
    conversations = _parse_conversation_matrix(conv_raw)
    total_flows = len(conversations)

    # --- Capture timing ---
    cap_start, cap_end = capture_duration(pcap)

    # Derive duration from conversation data (more reliable than timestamp diff)
    if conversations:
        last = max(c["rel_start"] + c["duration_secs"] for c in conversations)
        duration_secs = last
    else:
        duration_secs = 0.0

    # --- Host inventory ---
    raw_ips = unique_ips(pcap)
    all_ips = _clean_ips(raw_ips)

    # --- MAC → IP mapping ---
    mac_rows = tshark_fields(pcap, "eth.src", "eth.src", "ip.src")
    mac_to_ip: dict[str, list[str]] = {}
    for row in mac_rows:
        if len(row) >= 2 and row[0] and row[1]:
            mac = row[0]
            ip = row[1].split(",")[0].strip()
            if ip:
                mac_to_ip.setdefault(mac, [])
                if ip not in mac_to_ip[mac]:
                    mac_to_ip[mac].append(ip)

    # --- DNS hostname → IP mapping (from A responses) ---
    dns_rows = tshark_fields(
        pcap,
        "dns.flags.response==1 and dns.a",
        "dns.qry.name", "dns.a",
    )
    ip_to_hostname: dict[str, str] = {}
    for row in dns_rows:
        if len(row) >= 2 and row[0] and row[1]:
            name = row[0].rstrip(".")
            for ip in row[1].split(","):
                ip = ip.strip()
                if ip and ip not in ip_to_hostname:
                    ip_to_hostname[ip] = name

    # --- TTL-based OS fingerprinting ---
    ttl_rows = tshark_fields(pcap, "ip", "ip.src", "ip.ttl")
    ip_to_os: dict[str, str] = {}
    for row in ttl_rows:
        if len(row) >= 2 and row[0]:
            ip = row[0].split(",")[0].strip()
            ttl_raw = row[1].split(",")[0].strip() if row[1] else ""
            if ip and ttl_raw and ip not in ip_to_os:
                ip_to_os[ip] = _ttl_to_os(ttl_raw)

    # --- Protocol presence ---
    protocols_present = {p for p in frame_counts if frame_counts[p] > 0}

    # --- Non-standard port protocols ---
    nonstandard = []
    if "http" in protocols_present:
        rows = tshark_fields(
            pcap,
            "http and tcp.dstport != 80 and tcp.dstport != 8080 and tcp.dstport != 443",
            "ip.src", "ip.dst", "tcp.dstport",
        )
        for row in rows[:20]:  # cap at 20 samples
            if len(row) >= 3:
                nonstandard.append({"proto": "http", "src": row[0], "dst": row[1], "port": row[2]})

    if "dns" in protocols_present:
        rows = tshark_fields(
            pcap,
            "dns and udp.dstport != 53 and tcp.dstport != 53",
            "ip.src", "ip.dst", "udp.dstport",
        )
        for row in rows[:20]:
            if len(row) >= 3:
                nonstandard.append({"proto": "dns", "src": row[0], "dst": row[1], "port": row[2]})

    # --- Phase 0 whitelist ---
    wl = Whitelist(whitelist_config)
    internal_ips, external_ips = wl.classify_ips(all_ips)
    whitelist_result = wl.apply(all_ips)

    # --- Visibility ---
    visibility_pct, encrypted_pct = _calc_visibility(byte_counts)

    # --- Conversation classification ---
    internal_to_external = [
        c for c in conversations
        if c["src"] in internal_ips and c["dst"] in external_ips
        or c["dst"] in internal_ips and c["src"] in external_ips
    ]
    internal_to_internal = [
        c for c in conversations
        if c["src"] in internal_ips and c["dst"] in internal_ips
    ]

    # --- Assemble context ---
    ctx = AnalysisContext(
        pcap_path=pcap,
        file_size_bytes=file_size,
        capture_duration_secs=duration_secs,
        total_packets=total_packets,
        total_flows=total_flows,
        all_ips=all_ips,
        internal_ips=internal_ips,
        external_ips=external_ips,
        mac_to_ip=mac_to_ip,
        ip_to_hostname=ip_to_hostname,
        ip_to_os_hint=ip_to_os,
        protocols_present=protocols_present,
        protocol_packet_counts=frame_counts,
        protocol_byte_counts=byte_counts,
        nonstandard_port_protocols=nonstandard,
        top_talkers=conversations[:20],
        internal_to_external=internal_to_external[:20],
        internal_to_internal=internal_to_internal[:20],
        capture_start=cap_start,
        capture_end=cap_end,
        whitelist=whitelist_result,
        visibility_pct=visibility_pct,
        encrypted_pct=encrypted_pct,
    )

    # --- Calibrate thresholds ---
    ctx.thresholds = calibrate(ctx)

    return ctx
