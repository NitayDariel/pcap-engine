"""
Reporter — Assembles all phase outputs into a structured Markdown report.
Also writes findings.json and anomalies.json alongside the report.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path

import pandas as pd

from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.phase4_deep_dive import DeepDiveFinding
from engine.phase6_ioc_enrichment import IOCResult
from engine.phase7_anomaly import Anomaly
from engine.scorer import TTPScore
from engine.utils.zeek import parse_log

CONFIDENCE_ORDER = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "ANOMALY": 4}
DEEP_DIVE_THRESHOLD = 0.60

# Protocol names that are Wireshark/Zeek internals — not meaningful to an analyst
_NOISE_PROTOCOLS = frozenset({
    "_ws.malformed", "data", "data-text-lines", "epm", "browser",
    "frame", "eth", "ip", "tcp", "udp", "icmp", "raw",
})

# Canonical playbook count — update when playbooks/ directory changes
_TOTAL_PLAYBOOKS = 30


def _score_bar(score: float, width: int = 20) -> str:
    filled = int(score * width)
    return "█" * filled + "░" * (width - filled)


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _section(title: str, level: int = 2) -> str:
    return f"\n{'#' * level} {title}\n"


# ---------------------------------------------------------------------------
# Victim intelligence extraction (DHCP + Kerberos logs)
# ---------------------------------------------------------------------------

def _extract_victim_details(signals: ProtocolSignals, ctx: AnalysisContext | None = None) -> dict:
    """Pull hostname, MAC, Windows user from Zeek logs + ARP/mDNS fallbacks."""
    details: dict = {
        "hostname": None,
        "ip": None,
        "mac": None,
        "windows_user": None,
        "domain": None,
    }

    if not signals.zeek_log_dir:
        return details

    log_dir = signals.zeek_log_dir

    # DHCP gives us IP → hostname + MAC (most reliable when present)
    dhcp_df = parse_log(f"{log_dir}/dhcp.log")
    if not dhcp_df.empty:
        for _, row in dhcp_df.iterrows():
            ip = row.get("assigned_addr") or row.get("client_addr")
            if pd.notna(ip) and str(ip) not in ("", "nan"):
                details["ip"] = str(ip)
                if pd.notna(row.get("host_name")):
                    details["hostname"] = str(row["host_name"])
                if pd.notna(row.get("mac")):
                    details["mac"] = str(row["mac"])
                if pd.notna(row.get("domain")):
                    details["domain"] = str(row["domain"])
                break

    # Kerberos: Windows user and, if DHCP absent, victim IP and domain
    kerb_df = parse_log(f"{log_dir}/kerberos.log")
    if not kerb_df.empty and "client" in kerb_df.columns:
        valid_kerb = kerb_df[kerb_df["client"].notna()]
        # Filter out machine/computer accounts (end with '$') — we want human user accounts.
        # Machine accounts look like "DESKTOP-ABC123$/REALM" and are not the incident victim user.
        human_kerb = valid_kerb[
            ~valid_kerb["client"].apply(lambda x: str(x).split("/")[0].endswith("$"))
        ]
        target_kerb = human_kerb if not human_kerb.empty else valid_kerb
        if not target_kerb.empty:
            first_row = target_kerb.iloc[0]
            raw = str(first_row["client"])
            parts = raw.split("/")
            details["windows_user"] = parts[0]
            # Kerberos realm is uppercase domain (e.g. NEMOTODES.HEALTH → nemotodes.health)
            if len(parts) > 1 and details["domain"] is None:
                details["domain"] = parts[1].lower()
            # If DHCP was absent, use the Kerberos client's source IP as victim IP
            if details["ip"] is None and "id.orig_h" in target_kerb.columns:
                kip = str(first_row.get("id.orig_h", ""))
                if kip and kip != "nan":
                    details["ip"] = kip

    # AD domain from SMB DC server FQDN — always override DHCP/Kerberos domain.
    # SMB server FQDNs contain the actual AD DNS domain and are the most authoritative
    # source. DHCP may provide a generic name (e.g. mshome.net); Kerberos gives the
    # NetBIOS realm (short name). The DC's FQDN always reflects the real AD domain.
    smb_df_raw = parse_log(f"{log_dir}/smb_mapping.log")
    if not smb_df_raw.empty and "path" in smb_df_raw.columns:
        for _, row in smb_df_raw.iterrows():
            path = str(row.get("path", ""))
            if path.startswith("\\\\"):
                server = path[2:].split("\\")[0]  # SERVER.domain.tld
                parts = server.split(".")
                if len(parts) >= 3:  # hostname.domain.tld — 3+ labels required
                    details["domain"] = ".".join(parts[1:]).lower()
                    break

    # mDNS .local hostname — fallback when DHCP is absent.
    # Hosts query their own .local name; the leftmost label IS the hostname.
    if details["hostname"] is None and details["ip"]:
        dns_df_raw = parse_log(f"{log_dir}/dns.log")
        if not dns_df_raw.empty and "query" in dns_df_raw.columns and "id.orig_h" in dns_df_raw.columns:
            local_q = dns_df_raw[
                dns_df_raw["query"].str.endswith(".local", na=False)
                & (dns_df_raw["id.orig_h"] == details["ip"])
            ]
            if not local_q.empty:
                fqdn = str(local_q["query"].iloc[0])
                details["hostname"] = fqdn.removesuffix(".local").split(".")[0]

    # MAC address from ARP → ethernet layer already captured in Phase 1 mac_to_ip map.
    # No extra PCAP read needed — just reverse the map for the victim IP.
    if details["mac"] is None and details["ip"] and ctx is not None:
        victim_ip = details["ip"]
        for mac, ips in ctx.mac_to_ip.items():
            if victim_ip in ips:
                details["mac"] = mac
                break

    return details


# ---------------------------------------------------------------------------
# IOC extraction from findings + DNS + files
# ---------------------------------------------------------------------------

_DOMAIN_IN_PARENS = re.compile(r'\(([a-z0-9][a-z0-9\-._]{2,}\s*\.[a-z]{2,10})\)', re.IGNORECASE)
_SAFE_IOC_DOMAINS = {
    "microsoft.com", "msn.com", "office.com", "office.net", "windows.com",
    "windowsupdate.com", "bing.com", "google.com", "googleapis.com",
    "apple.com", "amazon.com", "akamai.com", "cloudflare.com",
    "gvt1.com", "gvt2.com", "youtube.com", "githubusercontent.com",
    "msedge.net", "azure.com", "azureedge.net", "azurefd.net",
    "teamviewer.com", "zoom.us", "slack.com", "dropbox.com",
}


def _extract_iocs(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    ttp_scores: list[TTPScore],
    ioc_results: dict[str, IOCResult],
    suricata_result=None,
) -> dict:
    """Collect IPs, domains, and file hashes associated with confirmed threats."""
    ioc_ips: set[str] = set()
    ioc_domains: set[str] = set()
    ioc_hashes: list[dict] = []

    # External IPs from top talkers (high volume = relevant)
    for t in ctx.top_talkers[:15]:
        ip = t.get("dst", "")
        if ip in ctx.external_ips:
            ioc_ips.add(ip)

    # Scan candidates (active scanners) — only external sources
    for c in signals.scan_candidates:
        ip = c.get("src", "")
        if ip and ip not in ctx.internal_ips:
            ioc_ips.add(ip)

    # Large outbound transfer destinations
    for t in signals.large_outbound_transfers:
        ip = t.get("id.resp_h", "")
        if ip and ip in ctx.external_ips:
            ioc_ips.add(ip)

    # HTTP POST destinations — catches C2 that uses many small requests below the byte-volume threshold
    for ip in getattr(signals, "http_post_destinations", []):
        if ip in ctx.external_ips:
            ioc_ips.add(ip)

    # External IPs with TLS cert anomalies (self-signed, generic CN) — C2 infrastructure indicator
    for ip in getattr(signals, "tls_cert_anomaly_ips", []):
        if ip in ctx.external_ips:
            ioc_ips.add(ip)

    # Confirmed/enriched malicious IPs take priority — always include
    for ip, r in ioc_results.items():
        if r.is_confirmed_malicious:
            ioc_ips.add(ip)

    # Suspicious DNS parent domains — only those with very high unique FQDN diversity (tunneling indicator)
    # Gate: >10 unique FQDNs (same gate as dns_suspicious_parent_count signal) to avoid FPs on
    # legitimate high-FQDN services like TeamViewer, CDNs, or SaaS platforms.
    for domain, count in signals.dns_top_domains[:20]:
        dl = domain.lower()
        if count > 10 and not any(dl == s or dl.endswith("." + s) for s in _SAFE_IOC_DOMAINS):
            ioc_domains.add(dl)

    # File hashes from Zeek files.log
    if signals.zeek_log_dir:
        files_df = parse_log(f"{signals.zeek_log_dir}/files.log")
        if not files_df.empty and "sha256" in files_df.columns:
            for _, row in files_df.iterrows():
                h = row.get("sha256")
                if pd.notna(h) and str(h) not in ("", "nan", "-"):
                    ioc_hashes.append({
                        "sha256": str(h),
                        "mime_type": str(row.get("mime_type", "unknown")),
                        "source": str(row.get("tx_hosts", "")),
                        "filename": str(row.get("extracted", "")),
                    })

    # Suricata-derived IOCs: domains named in signature text + C2 destination IPs.
    # Alert signatures often embed the malicious domain in parentheses, e.g.:
    #   "ET MALWARE Observed Win32/Lumma Stealer Related Domain (whitepepper.su)"
    # This is the most reliable way to get C2 domains offline, without VT lookups.
    if suricata_result and suricata_result.available and suricata_result.alerts:
        for alert in suricata_result.alerts:
            # Extract domains from parenthesised names in signature text
            for raw_domain in _DOMAIN_IN_PARENS.findall(alert.signature):
                dl = raw_domain.replace(" ", "").lower()
                if not any(dl == s or dl.endswith("." + s) for s in _SAFE_IOC_DOMAINS):
                    ioc_domains.add(dl)
            # Outbound alert destinations from internal hosts are C2 candidates
            if (ctx.internal_ips and
                    alert.src_ip in ctx.internal_ips and
                    alert.dst_ip not in ctx.internal_ips and
                    alert.dst_ip):
                ioc_ips.add(alert.dst_ip)

    return {
        "ips": sorted(ioc_ips),
        "domains": sorted(ioc_domains),
        "hashes": ioc_hashes,
    }


# ---------------------------------------------------------------------------
# Narrative executive summary
# ---------------------------------------------------------------------------

def _prose_executive_summary(
    ctx: AnalysisContext,
    ttp_scores: list[TTPScore],
    victim: dict,
    ioc_results: dict[str, IOCResult],
    suricata_result=None,
) -> str:
    """Generate a plain-language narrative: what, who, when."""
    high_conf = [r for r in ttp_scores if r.confidence in ("CONFIRMED", "HIGH")]
    medium_conf = [r for r in ttp_scores if r.confidence == "MEDIUM"]
    low_conf = [r for r in ttp_scores if r.confidence == "LOW"]
    confirmed_malicious = [ip for ip, r in ioc_results.items() if r.is_confirmed_malicious]

    # Parse capture window
    try:
        start_dt = datetime.fromisoformat(ctx.capture_start[:19].replace("T", " "))
        end_dt = datetime.fromisoformat(ctx.capture_end[:19].replace("T", " "))
        window = f"{start_dt.strftime('%Y-%m-%d %H:%M')} – {end_dt.strftime('%H:%M UTC')}"
    except Exception:
        window = f"{ctx.capture_start[:19]} – {ctx.capture_end[:19]}"

    # Identify victim anchor
    victim_ref = victim.get("ip") or "unknown host"
    if victim.get("hostname"):
        victim_ref = f"{victim['hostname']} ({victim_ref})"
    if victim.get("user"):
        victim_ref += f" · user **{victim['user']}**"

    lines = []

    # Lead with primary finding: Suricata malware family OR highest-confidence TTP
    primary_label = None
    if suricata_result and suricata_result.available and suricata_result.alerts:
        # Extract malware family name from alert signatures (look for Win32/X or just "MALWARE X")
        for alert in suricata_result.alerts:
            sig = alert.signature or ""
            import re as _re
            m = _re.search(r'(Win\d+/[\w\s]+?\w)', sig)
            if m:
                primary_label = m.group(1).strip()
                break
            m = _re.search(r'ET MALWARE ([\w\s/]+?) (?:C2|Related|Victim|CnC)', sig)
            if m:
                primary_label = m.group(1).strip()
                break

    top = sorted(ttp_scores, key=lambda r: (CONFIDENCE_ORDER.get(r.confidence, 99), -r.score))

    if primary_label:
        lines.append(f"**Malware identified: {primary_label}** · Host: **{victim_ref}**")
    elif high_conf:
        lines.append(f"**{high_conf[0].name}** detected on **{victim_ref}**")
    else:
        lines.append(f"Suspicious activity on **{victim_ref}**")

    # Context: capture window + tactic spread
    tactic_count = len(set(r.category for r in ttp_scores))
    severity_word = "high-severity" if high_conf else ("medium-severity" if medium_conf else "low-severity")
    lines.append(
        f"Capture window: **{window}** · "
        f"{severity_word} activity across **{tactic_count} MITRE tactic area(s)**."
    )

    # Top techniques (skip the primary if already shown)
    technique_names = [r.name for r in top if not (primary_label and r == top[0])][:3]
    if technique_names:
        lines.append("Additional techniques: " + "; ".join(technique_names) + ("." if len(top) <= 4 else f"; and {len(top)-3} more."))

    if confirmed_malicious:
        lines.append(
            f"**{len(confirmed_malicious)} C2 IP(s) confirmed malicious**: "
            + ", ".join(f"`{ip}`" for ip in confirmed_malicious) + "."
        )

    # Confidence breakdown
    parts = []
    if high_conf:
        parts.append(f"**{len(high_conf)} HIGH**")
    if medium_conf:
        parts.append(f"**{len(medium_conf)} MEDIUM**")
    if low_conf:
        parts.append(f"**{len(low_conf)} LOW**")
    if parts:
        lines.append(f"Finding breakdown: {', '.join(parts)} ({len(ttp_scores)} total).")

    return "\n\n".join(lines)


# ---------------------------------------------------------------------------
# Evidence formatter — strips Zeek internals, humanises timestamps/field names
# ---------------------------------------------------------------------------

_FIELD_RENAMES = {
    "id.orig_h": "src", "id.orig_p": "src_port",
    "id.resp_h": "dst", "id.resp_p": "dst_port",
}
_SKIP_FIELDS = {"uid", "proto"}
_ARRAY_PREVIEW_LIMIT = 6


def _format_evidence(entries: list) -> str:
    """Convert raw Zeek evidence dicts into a readable text block."""
    import datetime as _dt

    lines = []
    for i, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            lines.append(str(entry))
            continue
        if len(entries) > 1:
            lines.append(f"[{i}]")
        for k, v in entry.items():
            if k in _SKIP_FIELDS:
                continue
            label = _FIELD_RENAMES.get(k, k.replace("_", " "))
            # Humanise epoch timestamps
            if k == "ts" and isinstance(v, (int, float)) and v > 1e9:
                try:
                    v = _dt.datetime.fromtimestamp(v).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    pass
            # Truncate long arrays — show count, not a string element inside the list
            if isinstance(v, list) and len(v) > _ARRAY_PREVIEW_LIMIT:
                overflow = len(v) - _ARRAY_PREVIEW_LIMIT
                v = f"{v[:_ARRAY_PREVIEW_LIMIT]} (+{overflow} more)"
            lines.append(f"  {label}: {v}")
        if i < len(entries):
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Per-finding block
# ---------------------------------------------------------------------------

def _finding_block(
    result: TTPScore,
    deep_dive: DeepDiveFinding | None,
    ioc_results: dict[str, IOCResult],
) -> str:
    lines = []
    conf_icon = {"CONFIRMED": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "ANOMALY": "⚪"}.get(
        result.confidence, "⚪"
    )
    lines.append(
        f"### {conf_icon} [{result.confidence}] {result.ttp_id} — {result.name}  "
        f"`score: {result.score:.3f}`"
    )
    lines.append(f"**MITRE Tactic**: {result.mitre_tactic} · **Category**: {result.category}")
    lines.append(f"**Score bar**: `{_score_bar(result.score)}`")
    lines.append("")

    if result.signals_fired:
        # Strip _weak suffix — it's a scoring-tier detail, not meaningful in the report
        _fired_display = [s[:-5] if s.endswith("_weak") else s for s in result.signals_fired]
        lines.append(f"**Signals fired** ({len(result.signals_fired)}): "
                     f"`{'`, `'.join(_fired_display)}`")

    if result.raw_values:
        lines.append("\n**Indicators:**")
        for k, v in result.raw_values.items():
            # Skip zero/false values that didn't contribute to the score
            if v == 0 or v is False or v == "False" or v == "0":
                continue
            if isinstance(v, float):
                lines.append(f"- `{k}` = `{v:.4f}`")
            elif v is True or v == 1 or v == "True":
                lines.append(f"- `{k}` — detected")
            else:
                lines.append(f"- `{k}` = `{v}`")

    if deep_dive and deep_dive.summary:
        lines.append(f"\n**Deep dive summary**: {deep_dive.summary}")
        if deep_dive.evidence:
            lines.append("\n**Evidence (top entries):**")
            lines.append("```")
            lines.append(_format_evidence(deep_dive.evidence[:3]))
            lines.append("```")

    if result.fp_notes:
        lines.append(f"\n> **False-positive guidance**: {result.fp_notes}")

    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main generate function
# ---------------------------------------------------------------------------

def generate(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    ttp_scores: list[TTPScore],
    deep_dives: list[DeepDiveFinding],
    ioc_results: dict[str, IOCResult],
    anomalies: list[Anomaly],
    suricata_result=None,   # Optional[SuricataResult]
    artifact_result=None,   # Optional[ArtifactResult]
    ja3_hits=None,          # Optional[list[JA3Result]]
    sigma_result=None,      # Optional[SigmaResult]
) -> str:
    """Generate the full Markdown report as a string."""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pcap_name = Path(ctx.pcap_path).name
    deep_dive_map = {f.ttp_id: f for f in deep_dives}

    confirmed_malicious_ips = [
        ip for ip, r in ioc_results.items() if r.is_confirmed_malicious
    ]

    sorted_scores = sorted(
        ttp_scores,
        key=lambda r: (CONFIDENCE_ORDER.get(r.confidence, 99), -r.score),
    )

    # Pre-compute enriched data
    victim = _extract_victim_details(signals, ctx)
    iocs = _extract_iocs(ctx, signals, ttp_scores, ioc_results, suricata_result=suricata_result)

    # ── Header ────────────────────────────────────────────────────────────
    lines = [
        f"# PCAP Threat Analysis Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **File** | `{pcap_name}` |",
        f"| **Size** | {_fmt_bytes(ctx.file_size_bytes)} |",
        f"| **Generated** | {now} |",
        f"| **Duration** | {ctx.capture_duration_secs/3600:.1f}h ({ctx.capture_duration_secs:.0f}s) |",
        f"| **Packets** | {ctx.total_packets:,} |",
        f"| **Flows** | {ctx.total_flows:,} |",
        f"| **Capture start** | {ctx.capture_start[:30]} |",
        f"| **Capture end** | {ctx.capture_end[:30]} |",
        f"",
    ]

    # ── Executive Summary ─────────────────────────────────────────────────
    lines.append(_section("Executive Summary"))
    lines.append(_prose_executive_summary(ctx, ttp_scores, victim, ioc_results, suricata_result=suricata_result))
    lines.append("")

    # ── Victim Details ────────────────────────────────────────────────────
    lines.append(_section("Victim Details"))
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| **Hostname** | `{victim['hostname'] or 'unknown'}` |")
    lines.append(f"| **IP Address** | `{victim['ip'] or ', '.join(sorted(ctx.internal_ips)[:3])}` |")
    lines.append(f"| **MAC Address** | `{victim['mac'] or 'unknown'}` |")
    lines.append(f"| **Windows User** | `{victim['windows_user'] or 'unknown'}` |")
    lines.append(f"| **Domain** | `{victim['domain'] or 'unknown'}` |")
    # Filter out broadcast, multicast, link-local — only meaningful unicast internal hosts
    _meaningful_internal = sorted(
        ip for ip in ctx.internal_ips
        if ip not in ("0.0.0.0",) and not ip.startswith("169.254.") and not ip.endswith(".255")
    )
    lines.append(f"| **LAN segment** | {', '.join(f'`{ip}`' for ip in _meaningful_internal) or 'unknown'} |")
    lines.append("")

    # ── Indicators of Compromise ──────────────────────────────────────────
    lines.append(_section("Indicators of Compromise (IOCs)"))

    lines.append("**IP Addresses**")
    lines.append("")
    if iocs["ips"]:
        enriched_ips = [(ip, ioc_results[ip]) for ip in iocs["ips"] if ip in ioc_results]
        unenriched_ips = [ip for ip in iocs["ips"] if ip not in ioc_results]

        if enriched_ips:
            lines.append("| IP | Enrichment |")
            lines.append("|---|---|")
            for ip, r in enriched_ips:
                if r.is_confirmed_malicious:
                    enrich = (
                        f"**MALICIOUS** — VT:{r.vt_malicious} engines"
                        + (f" · {r.threatfox_malware}" if r.threatfox_malware else "")
                    )
                else:
                    enrich = f"VT:{r.vt_malicious} detections"
                lines.append(f"| `{ip}` | {enrich} |")
            if unenriched_ips:
                lines.append("")
                lines.append(
                    "_Not enriched (max-iocs limit reached — increase with `--max-iocs`): "
                    + " · ".join(f"`{ip}`" for ip in unenriched_ips) + "_"
                )
        else:
            # No enrichment data — clean flat list, one line
            lines.append(" · ".join(f"`{ip}`" for ip in iocs["ips"]))
            lines.append("")
            lines.append("_Run without `--offline` for VirusTotal / ThreatFox enrichment._")
    else:
        lines.append("_No external IOC IPs extracted._")
    lines.append("")

    lines.append("**Domains / URLs**")
    lines.append("")
    if iocs["domains"]:
        for d in sorted(iocs["domains"]):
            lines.append(f"- `{d}`")
    else:
        lines.append("_No suspicious domains extracted._")
    lines.append("")

    lines.append("**File Hashes (SHA256)**")
    lines.append("")
    # Prefer artifact_result hashes (richer), fall back to zeek files.log hashes
    artifact_hashes = (artifact_result.extracted_files if artifact_result else [])
    if artifact_hashes:
        # Deduplicate by sha256 — group identical hashes, show representative filename + count
        from collections import defaultdict as _defaultdict
        _hash_groups: dict = _defaultdict(list)
        for _f in artifact_hashes:
            _hash_groups[_f.sha256].append(_f)
        _unique_hashes = sorted(_hash_groups.items(), key=lambda x: -len(x[1]))
        total_unique = len(_unique_hashes)
        total_files = len(artifact_hashes)
        if total_unique < total_files:
            lines.append(
                f"_{total_files} files extracted · {total_unique} unique hash(es) "
                f"({total_files - total_unique} duplicates collapsed)_\n"
            )
        lines.append("| SHA256 | File | Count | MIME | Size |")
        lines.append("|---|---|---|---|---|")
        for _sha, _files in _unique_hashes[:15]:
            _first = _files[0]
            _fname = _first.filename[:35]
            _count = f"×{len(_files)}" if len(_files) > 1 else "1"
            lines.append(
                f"| `{_sha[:20]}…` | `{_fname}` | {_count} "
                f"| {_first.mime_type} | {_fmt_bytes(_first.size_bytes)} |"
            )
        if len(_unique_hashes) > 15:
            lines.append(f"_… and {len(_unique_hashes) - 15} more unique hashes_")
    elif iocs["hashes"]:
        lines.append("| SHA256 | MIME | Source IP |")
        lines.append("|---|---|---|")
        for h in iocs["hashes"]:
            lines.append(f"| `{h['sha256'][:20]}...` | {h['mime_type']} | `{h['source']}` |")
    else:
        lines.append("_No file hashes extracted from this capture._")
    lines.append("")

    # ── Coverage ──────────────────────────────────────────────────────────
    _visible_protos = [p for p in sorted(ctx.protocols_present) if p not in _NOISE_PROTOCOLS]
    lines.append(_section("Coverage"))
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Visibility | **{ctx.visibility_pct}%** analyzable ({ctx.encrypted_pct}% encrypted) |")
    lines.append(f"| Playbooks evaluated | {_TOTAL_PLAYBOOKS} |")
    lines.append(f"| Findings (above threshold) | {len(ttp_scores)} |")
    lines.append(f"| Protocols observed | {', '.join(_visible_protos[:15]) or 'unknown'} |")
    lines.append(f"| External hosts | {len(ctx.external_ips)} |")
    lines.append(f"| Whitelist cleared | {len(ctx.whitelist.cleared_ips) if ctx.whitelist else 0} IPs |")
    lines.append(f"| IOCs enriched | {len(ioc_results)} IPs |")
    lines.append("")

    # ── Artifact Extraction ───────────────────────────────────────────────
    lines.append(_section("Extracted Artifacts (Phase 5)"))

    if artifact_result is None:
        lines.append("_Phase 5 not run._\n")
    else:
        # TLS certificates — highlight anomalous ones
        suspicious_certs = artifact_result.suspicious_certs
        if suspicious_certs:
            lines.append(f"**{len(suspicious_certs)} anomalous TLS certificate(s)**\n")
            lines.append("| Subject | Issuer | Anomalies | Fingerprint |")
            lines.append("|---|---|---|---|")
            for c in suspicious_certs[:10]:
                subj = c.subject[:50] if c.subject else "unknown"
                issuer = c.issuer[:30] if c.issuer else "unknown"
                anomaly_str = ", ".join(c.anomalies)
                fp = c.fingerprint[:16] + "..."
                lines.append(f"| `{subj}` | `{issuer}` | {anomaly_str} | `{fp}` |")
            lines.append("")
        else:
            total_certs = len(artifact_result.tls_certificates)
            lines.append(f"_TLS certificates: {total_certs} seen, none anomalous._\n")

        # SMB file writes — lateral movement artifact evidence
        smb_writes = artifact_result.suspicious_smb_writes
        if smb_writes:
            lines.append(f"**{len(smb_writes)} SMB WRITE event(s)** — files transferred during lateral movement\n")
            lines.append("| Timestamp | Src | Dst | Path | Size |")
            lines.append("|---|---|---|---|---|")
            for e in smb_writes[:10]:
                import datetime as _dt
                ts_str = _dt.datetime.fromtimestamp(e.ts).strftime("%H:%M:%S") if e.ts else "?"
                lines.append(
                    f"| {ts_str} | `{e.src_ip}` | `{e.dst_ip}` "
                    f"| `{e.path[:50]}` | {_fmt_bytes(e.size_bytes)} |"
                )
            lines.append("")
        else:
            lines.append("_SMB WRITE events: none detected._\n")

        # Extracted files
        n_files = len(artifact_result.extracted_files)
        if n_files:
            lines.append(f"**{n_files} file(s) extracted from protocol streams** — see IOC hashes above.\n")
        else:
            lines.append("_No files extracted via tshark (no HTTP/SMB object streams found)._\n")

        if artifact_result.extraction_errors:
            lines.append(f"_Extraction warnings: {'; '.join(artifact_result.extraction_errors[:3])}_\n")

    # ── JA3 Fingerprint Hits ─────────────────────────────────────────────
    lines.append(_section("JA3/JA3S TLS Fingerprint Matches"))
    if not ja3_hits:
        # Check if JA3 was available at all (tls_sessions present but no ja3 fields)
        has_ja3 = any(
            s.get("ja3") and str(s.get("ja3")) not in ("", "-", "nan")
            for s in (signals.tls_sessions or [])
        )
        if has_ja3:
            lines.append("_No known-bad JA3 fingerprints matched. JA3 is active._\n")
        else:
            lines.append(
                "_JA3 fingerprinting not active — install Zeek JA3 package: "
                "`echo Y | python3.14 /opt/homebrew/bin/zkg install zeek/salesforce/ja3`_\n"
            )
    else:
        lines.append(f"**{len(ja3_hits)} known-bad TLS fingerprint(s) detected**\n")
        lines.append("| JA3 Hash | JA3S Hash | Family | Src → Dst | SNI |")
        lines.append("|---|---|---|---|---|")
        for hit in ja3_hits:
            ja3_display = f"`{hit.ja3[:20]}…`" if hit.ja3 else "-"
            ja3s_display = f"`{hit.ja3s[:20]}…`" if hit.ja3s else "-"
            label = hit.ja3_family or hit.ja3s_family or "unknown"
            conn = f"`{hit.src_ip}` → `{hit.dst_ip}`"
            sni = hit.server_name or "-"
            lines.append(f"| {ja3_display} | {ja3s_display} | {label} | {conn} | {sni} |")
        lines.append("")

    # ── Sigma Rule Hits ───────────────────────────────────────────────────
    lines.append(_section("Sigma Rule Scan"))
    if sigma_result is None or not sigma_result.available:
        err = getattr(sigma_result, "error", "") if sigma_result else ""
        lines.append(
            f"_Sigma unavailable{': ' + err if err else ''}. "
            "Install with: `pip3 install sigma-cli`_\n"
        )
    elif not sigma_result.hits:
        lines.append(
            f"_Sigma scanned {sigma_result.rules_evaluated} network/zeek rules — no matches._\n"
        )
    else:
        hi = len(sigma_result.high_hits)
        total_hits = len(sigma_result.hits)
        techniques = ", ".join(f"`{t}`" for t in sorted(sigma_result.techniques)) or "none"
        lines.append(
            f"**{total_hits} rule(s) matched** — {hi} high-severity · "
            f"MITRE techniques: {techniques}\n"
        )
        lines.append("| Level | Rule | Log | Matches | Src IPs |")
        lines.append("|---|---|---|---|---|")
        for h in sorted(sigma_result.hits, key=lambda x: {"high": 0, "medium": 1, "low": 2}.get(x.level, 3)):
            sev = {"high": "**HIGH**", "medium": "MEDIUM", "low": "low"}.get(h.level, h.level)
            src = " · ".join(f"`{ip}`" for ip in h.sample_src_ips[:2]) or "—"
            lines.append(f"| {sev} | {h.rule_title} | {h.log_type} | {h.match_count} | {src} |")
        lines.append("")

    # ── Suricata Signature Alerts ─────────────────────────────────────────
    lines.append(_section("Suricata Signature Scan"))
    if suricata_result is None or not suricata_result.available:
        lines.append(
            "_Suricata not installed — signature-based detection unavailable. "
            "Install with: `brew install suricata` for ET Open rule coverage._\n"
        )
    elif suricata_result.error:
        lines.append(f"_Suricata scan failed: {suricata_result.error}_\n")
    elif not suricata_result.alerts:
        lines.append(
            f"_Suricata ran successfully ({suricata_result.rules_path}) but produced no alerts._\n"
        )
    else:
        hi = suricata_result.high_severity_count
        total = suricata_result.alert_count
        techniques = ", ".join(f"`{t}`" for t in sorted(suricata_result.unique_techniques)) or "none"
        lines.append(
            f"**{total} alert(s)** — {hi} high-severity · MITRE techniques: {techniques}\n"
        )
        # Deduplicate: group by (src_ip, dst_ip, signature), keep worst severity + count
        _seen_sigs: dict = {}
        for _a in sorted(suricata_result.alerts, key=lambda a: a.severity):
            _key = (_a.src_ip, _a.dst_ip, _a.signature)
            if _key not in _seen_sigs:
                _seen_sigs[_key] = [_a, 1]
            else:
                _seen_sigs[_key][1] += 1
                if _a.severity < _seen_sigs[_key][0].severity:
                    _seen_sigs[_key][0] = _a  # keep highest-severity instance
        _deduped = sorted(_seen_sigs.values(), key=lambda x: x[0].severity)[:15]
        lines.append("| Src | Dst | Sev | Count | Technique | Signature |")
        lines.append("|---|---|---|---|---|---|")
        for _a, _cnt in _deduped:
            sev_label = {1: "**HIGH**", 2: "MEDIUM", 3: "low"}.get(_a.severity, str(_a.severity))
            tech = f"`{_a.mitre_technique}`" if _a.mitre_technique else "—"
            sig = _a.signature[:55] + ("…" if len(_a.signature) > 55 else "")
            _cnt_str = f"×{_cnt}" if _cnt > 1 else "1"
            lines.append(
                f"| `{_a.src_ip}:{_a.src_port}` | `{_a.dst_ip}:{_a.dst_port}` "
                f"| {sev_label} | {_cnt_str} | {tech} | {sig} |"
            )
        if len(_seen_sigs) > 15:
            lines.append(f"_… {len(_seen_sigs) - 15} more unique signatures_")
        lines.append("")

    # ── Findings ──────────────────────────────────────────────────────────
    lines.append(_section("Findings"))
    if not ttp_scores:
        lines.append("_No TTPs reached the report threshold._")
    else:
        for result in sorted_scores:
            dd = deep_dive_map.get(result.ttp_id)
            lines.append(_finding_block(result, dd, ioc_results))

    # ── Beacon Analysis ───────────────────────────────────────────────────
    lines.append(_section("Beacon Analysis"))

    # RITA (Docker gold-standard) — shown when available
    if getattr(signals, "rita_available", False):
        lines.append(
            f"**RITA (gold-standard):** {signals.rita_beacon_pairs} high-confidence pair(s) "
            f"· top score **{signals.rita_top_beacon_score:.3f}**\n"
        )
        rita_beacons = getattr(signals, "rita_beacons", [])
        if rita_beacons:
            lines.append("| Src | Dst | Connections | Top Interval | RITA Score |")
            lines.append("|---|---|---|---|---|")
            for b in rita_beacons[:10]:
                lines.append(
                    f"| `{b.get('src_ip', '?')}` | `{b.get('dst_ip', '?')}` "
                    f"| {b.get('connections', 0)} | {b.get('top_interval_secs', 0):.0f}s "
                    f"| **{b.get('score', 0):.3f}** |"
                )
            lines.append("")
    else:
        lines.append("_RITA (Docker) not available — start Colima for gold-standard beacon scoring._\n")

    # In-engine RITA-style composite (always runs)
    beacon_candidates = signals.beacon_candidates or []
    if not beacon_candidates:
        lines.append("_In-engine beacon scoring: no candidates (no pair reached 0.50 threshold)._\n")
    else:
        lines.append(
            f"**In-engine beacon scoring:** {len(beacon_candidates)} candidate(s) "
            f"· top score **{signals.beacon_top_score:.3f}**\n"
        )
        lines.append("| Src | Dst | Port | Count | Modal Interval | Jitter | Avg Bytes | Duration | Score |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for b in beacon_candidates[:10]:
            interval_str = f"{b['modal_interval_secs']:.0f}s"
            jitter_str = f"±{b['interval_jitter_secs']:.0f}s"
            fft_note = f" *(FFT: {b['fft_period_secs']:.0f}s)*" if b.get("fft_period_secs", 0) > 0 else ""
            lines.append(
                f"| `{b['src_ip']}` | `{b['dst_ip']}` | {b['dst_port']} "
                f"| {b['connection_count']} | {interval_str}{fft_note} | {jitter_str} "
                f"| {b['avg_bytes_orig']:.0f}B | {b['duration_hours']:.1f}h "
                f"| **{b['composite_score']:.3f}** |"
            )
        lines.append("")
        lines.append("Score components (interval CV / payload CV / frequency / persistence):")
        for b in beacon_candidates[:5]:
            lines.append(
                f"- `{b['src_ip']}` → `{b['dst_ip']}:{b['dst_port']}` — "
                f"I:{b['interval_score']:.2f} S:{b['size_score']:.2f} "
                f"F:{b['freq_score']:.2f} P:{b['persist_score']:.2f}"
            )
        lines.append("")

    # ── IOC Enrichment Detail ─────────────────────────────────────────────
    lines.append(_section("IOC Enrichment Detail"))
    if not ioc_results:
        lines.append("_IOC enrichment skipped (offline mode or no results)._\n")
    else:
        lines.append("| IP | Owner | Country | VT Malicious | ThreatFox | Malware | Confirmed |")
        lines.append("|---|---|---|---|---|---|---|")
        for ip, r in sorted(
            ioc_results.items(),
            key=lambda x: (-x[1].vt_malicious, -x[1].threatfox_confidence),
        ):
            confirmed = "**YES**" if r.is_confirmed_malicious else "no"
            tf = f"✓ ({r.threatfox_confidence}%)" if r.threatfox_found else "—"
            malware = r.threatfox_malware or "—"
            lines.append(
                f"| `{ip}` | {r.vt_owner[:25]} | {r.vt_country} | {r.vt_malicious} "
                f"| {tf} | {malware} | {confirmed} |"
            )
        lines.append("")

    # ── Anomalies ─────────────────────────────────────────────────────────
    lines.append(_section("Anomalies"))
    if not anomalies:
        lines.append("_No anomalies detected outside playbook coverage._\n")
    else:
        for a in anomalies:
            lines.append(f"#### {a.anomaly_id} — {a.anomaly_type}")
            lines.append(f"{a.description}")
            lines.append(f"\n> **Reason not classified**: {a.reason_not_classified}")
            if a.ai_hypothesis:
                lines.append(f"\n**🤖 Gemini Analysis**\n\n{a.ai_hypothesis}")
            lines.append("")

    # ── Top Talkers ───────────────────────────────────────────────────────
    lines.append(_section("Top Network Talkers"))
    lines.append("| Src | Dst | Total Bytes | Duration |")
    lines.append("|---|---|---|---|")
    for t in ctx.top_talkers[:10]:
        lines.append(
            f"| `{t['src']}` | `{t['dst']}` "
            f"| {_fmt_bytes(t['bytes_total'])} | {t['duration_secs']:.0f}s |"
        )
    lines.append("")

    # ── Structural Limitations ────────────────────────────────────────────
    lines.append(_section("Structural Limitations", level=2))
    lines.append(
        f"- **TLS opacity**: {ctx.encrypted_pct}% of traffic is encrypted — payload unreadable\n"
        f"- **No baseline**: thresholds are absolute, not relative to this environment's normal\n"
        f"- **Playbook coverage**: {_TOTAL_PLAYBOOKS} playbooks evaluated — novel techniques outside this set will silently miss\n"
        f"- **JA3 fingerprinting**: {'Active — known-bad hash list checked' if ja3_hits is not None else 'Zeek JA3 package not installed'}\n"
    )

    return "\n".join(lines)


def write(
    report_md: str,
    ttp_scores: list[TTPScore],
    anomalies: list[Anomaly],
    output_dir: str,
) -> dict[str, str]:
    """Write report.md, findings.json, anomalies.json to output_dir. Returns paths dict."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    paths = {}

    report_path = out / "report.md"
    report_path.write_text(report_md)
    paths["report"] = str(report_path)

    findings_data = [
        {
            "ttp_id": r.ttp_id,
            "name": r.name,
            "category": r.category,
            "score": r.score,
            "confidence": r.confidence,
            "signals_fired": r.signals_fired,
            "categories_hit": list(r.categories_hit),
            "raw_values": {k: (float(v) if isinstance(v, (int, float)) else v) for k, v in r.raw_values.items()},
        }
        for r in ttp_scores
    ]
    findings_path = out / "findings.json"
    findings_path.write_text(json.dumps(findings_data, indent=2))
    paths["findings"] = str(findings_path)

    anomaly_data = [
        {
            "anomaly_id": a.anomaly_id,
            "type": a.anomaly_type,
            "description": a.description,
            "raw_signals": a.raw_signals,
            "ai_prompt": a.ai_prompt,
            "ai_hypothesis": a.ai_hypothesis,
        }
        for a in anomalies
    ]
    anomaly_path = out / "anomalies.json"
    anomaly_path.write_text(json.dumps(anomaly_data, indent=2))
    paths["anomalies"] = str(anomaly_path)

    return paths
