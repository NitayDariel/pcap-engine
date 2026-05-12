#!/usr/bin/env python3
"""
PCAP Threat Analysis Engine — Entry Point.
Usage: python engine/main.py --pcap <path> [options]
"""

from __future__ import annotations

import argparse
import sys
import time
import warnings
from pathlib import Path

# Suppress only well-understood noisy warnings from optional dependencies.
# Do NOT use a blanket ignore — real warnings from our own code must surface.
warnings.filterwarnings("ignore", category=FutureWarning, module="pandas")
warnings.filterwarnings("ignore", category=FutureWarning, module="numpy")
warnings.filterwarnings("ignore", message=".*Unverified HTTPS.*")       # urllib3 dev noise
warnings.filterwarnings("ignore", message=".*google.*Python version.*") # google SDK on py3.9
warnings.filterwarnings("ignore", message=".*end of life.*")            # google SDK eol notice

# Add project root to path so `engine.*` imports resolve
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import phase1_orientation, phase2_protocol, phase3_ttp_sweep
from engine import phase4_deep_dive, phase5_artifacts, phase6_ioc_enrichment, phase7_anomaly, reporter
from engine import wireshark_export
from engine.utils.suricata import run as suricata_run, is_available as suricata_available
from engine.utils.sigma import run as sigma_run


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="PCAP Threat Analysis Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python engine/main.py --pcap capture.pcap
  python engine/main.py --pcap capture.pcap --offline
  python engine/main.py --pcap capture.pcap --output-dir ./outputs/my_analysis
  python engine/main.py --pcap capture.pcap --zeek-logs ./existing_zeek_logs/
  python engine/main.py --pcap capture.pcap --max-iocs 5
""",
    )
    p.add_argument("--pcap", required=True, help="Path to PCAP or PCAPNG file")
    p.add_argument("--output-dir", default=None, help="Output directory for report + JSON files")
    p.add_argument("--zeek-logs", default=None, help="Pre-existing Zeek log directory (skip re-running Zeek)")
    p.add_argument("--offline", action="store_true", help="Skip all external API calls (VT, ThreatFox)")
    p.add_argument(
        "--no-anomaly", action="store_true",
        help="Skip Phase 7 anomaly detection (heuristic pattern flagging, no LLM call)",
    )
    p.add_argument(
        "--no-ai", action="store_true",
        help=argparse.SUPPRESS,  # kept for backwards-compat; identical to --no-anomaly
    )
    p.add_argument("--max-iocs", type=int, default=10, help="Max IPs to enrich via VT/ThreatFox (default: 10)")
    p.add_argument("--playbooks", default=None, help="Path to playbooks directory")
    p.add_argument("--no-suricata", action="store_true", help="Skip Suricata signature scan")
    return p.parse_args()


def banner() -> None:
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║        PCAP Threat Analysis Engine  v0.1            ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()


def main() -> None:
    args = parse_args()
    banner()

    pcap = str(Path(args.pcap).resolve())
    if not Path(pcap).exists():
        print(f"[ERROR] PCAP file not found: {pcap}")
        sys.exit(1)

    # Derive output directory
    if args.output_dir:
        out_dir = str(Path(args.output_dir))
    else:
        pcap_stem = Path(pcap).stem
        out_dir = str(Path(pcap).parent / "engine_output" / pcap_stem)

    playbook_dir = args.playbooks or str(Path(__file__).resolve().parents[1] / "playbooks")
    total_start = time.time()

    print(f"[INPUT]  {pcap}")
    print(f"[OUTPUT] {out_dir}")
    print(f"[MODE]   offline={args.offline}  max_iocs={args.max_iocs}")
    print()

    # ── Phase 1: Orientation ──────────────────────────────────────────────
    print("[Phase 1] Orientation — building host inventory and protocol map...")
    t0 = time.time()
    ctx = phase1_orientation.run(pcap)
    print(
        f"          {ctx.total_packets:,} packets · {ctx.total_flows} flows · "
        f"{len(ctx.all_ips)} IPs · {ctx.capture_duration_secs/3600:.1f}h capture"
    )
    print(f"          Visibility: {ctx.visibility_pct}%  |  {ctx.encrypted_pct}% encrypted")
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 2: Protocol Analysis ────────────────────────────────────────
    print("[Phase 2] Protocol analysis — computing signals from Zeek logs...")
    t0 = time.time()
    signals = phase2_protocol.run(pcap, ctx, zeek_log_dir=args.zeek_logs)
    print(f"          DNS: {signals.dns_packet_count} pkts · HTTP: {signals.http_packet_count} pkts · "
          f"TLS: {signals.tls_packet_count} pkts · SMB: {signals.smb_packet_count} pkts")
    print(f"          Zeek logs: {signals.zeek_log_dir}")
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 2.5: Suricata Signature Scan ───────────────────────────────
    suricata_result = None
    if not args.no_suricata and suricata_available():
        print("[Phase 2.5] Suricata — running signature scan (ET Open rules)...")
        t0 = time.time()
        suricata_result = suricata_run(pcap)
        if suricata_result.error:
            print(f"          WARNING: {suricata_result.error}")
        else:
            hi = suricata_result.high_severity_count
            total = suricata_result.alert_count
            techniques = ", ".join(sorted(suricata_result.unique_techniques)) or "none"
            print(f"          {total} alerts ({hi} high-severity) · Techniques: {techniques}")
        print(f"          Done in {time.time()-t0:.1f}s\n")
    elif not args.no_suricata:
        print("[Phase 2.5] Suricata — not installed, skipping (brew install suricata)\n")

    # ── Phase 2.6: Sigma Rule Scan ────────────────────────────────────────
    print("[Phase 2.6] Sigma — evaluating network/zeek rules...")
    t0 = time.time()
    sigma_result = sigma_run(signals.zeek_log_dir)
    if not sigma_result.available:
        print(f"          Sigma unavailable: {sigma_result.error}")
    elif sigma_result.hits:
        techniques_str = ", ".join(sorted(sigma_result.techniques)) or "none"
        print(
            f"          {sigma_result.rules_evaluated} rules evaluated · "
            f"{len(sigma_result.hits)} hit(s) · "
            f"Techniques: {techniques_str}"
        )
    else:
        print(f"          {sigma_result.rules_evaluated} rules evaluated · No hits")
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 3: TTP Sweep ────────────────────────────────────────────────
    print("[Phase 3] TTP sweep — parallel scoring all playbooks...")
    t0 = time.time()
    ttp_scores = phase3_ttp_sweep.run(
        ctx, signals, playbook_dir=playbook_dir,
        suricata_result=suricata_result, sigma_result=sigma_result,
    )
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 4: Deep Dive ────────────────────────────────────────────────
    print("[Phase 4] Deep dive — targeted evidence on high-score TTPs...")
    t0 = time.time()
    deep_dives = phase4_deep_dive.run(pcap, ttp_scores, signals)
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Wireshark Filter Export ───────────────────────────────────────────
    print("[Filters] Generating Wireshark display filters...")
    t0 = time.time()
    ws_content = wireshark_export.generate(ctx, signals, ttp_scores, deep_dives)
    ws_path = wireshark_export.write(ws_content, out_dir)
    print(f"          Filters: {ws_path}")
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 5: Artifact Extraction ──────────────────────────────────────
    print("[Phase 5] Artifact extraction — files, TLS certs, SMB events...")
    t0 = time.time()
    # Parse capture start timestamp for cert validity checks
    try:
        from datetime import datetime as _dt
        _cap_ts = _dt.fromisoformat(ctx.capture_start[:19].replace("T", " ")).timestamp()
    except Exception:
        _cap_ts = 0.0
    artifact_result = phase5_artifacts.run(pcap, signals.zeek_log_dir, capture_start_ts=_cap_ts)
    n_files = len(artifact_result.extracted_files)
    n_certs = len(artifact_result.tls_certificates)
    n_smb = len(artifact_result.smb_file_events)
    suspicious_certs = len(artifact_result.suspicious_certs)
    print(
        f"          Files: {n_files} extracted ({len(artifact_result.sha256_hashes)} hashed) · "
        f"Certs: {n_certs} ({suspicious_certs} anomalous) · SMB events: {n_smb}"
    )
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 6: IOC Enrichment ───────────────────────────────────────────
    print("[Phase 6] IOC enrichment — VT + ThreatFox lookups...")
    t0 = time.time()
    ioc_results = phase6_ioc_enrichment.run(
        ctx, ttp_scores, signals,
        max_ips=args.max_iocs,
        offline=args.offline,
    )
    # JA3/JA3S fingerprint check (offline, always runs)
    ja3_hits = phase6_ioc_enrichment.check_ja3(signals)
    if ja3_hits:
        print(f"  [Phase 6] JA3 fingerprint matches: {len(ja3_hits)} known-bad signature(s)")
        for hit in ja3_hits:
            label = hit.ja3_family or hit.ja3s_family
            print(f"    JA3 {hit.ja3[:16]}… → {label} (dst={hit.dst_ip})")
    print(f"          Done in {time.time()-t0:.1f}s\n")

    # ── Phase 7: Anomaly Layer ────────────────────────────────────────────
    skip_anomaly = getattr(args, "no_anomaly", False) or getattr(args, "no_ai", False)
    if not skip_anomaly:
        print("[Phase 7] Anomaly layer — identifying uncategorised patterns...")
        t0 = time.time()
        anomalies = phase7_anomaly.run(ctx, signals, ttp_scores)
        print(f"          Done in {time.time()-t0:.1f}s\n")
    else:
        anomalies = []

    # ── Report ────────────────────────────────────────────────────────────
    print("[Report] Generating report...")
    report_md = reporter.generate(
        ctx, signals, ttp_scores, deep_dives, ioc_results, anomalies,
        suricata_result=suricata_result,
        artifact_result=artifact_result,
        ja3_hits=ja3_hits,
        sigma_result=sigma_result,
    )
    paths = reporter.write(report_md, ttp_scores, anomalies, out_dir)

    total_elapsed = time.time() - total_start
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print(f"║  Analysis complete in {total_elapsed:.1f}s")
    print(f"║  Findings:  {len(ttp_scores)} TTPs  ·  {len(anomalies)} anomalies")
    conf_ips = sum(1 for r in ioc_results.values() if r.is_confirmed_malicious)
    print(f"║  Malicious: {conf_ips} confirmed IP(s)")
    print(f"║  Report:    {paths['report']}")
    print(f"║  Filters:   {ws_path}")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Print top findings to terminal
    print("Top findings:")
    for r in ttp_scores[:5]:
        print(f"  [{r.confidence:9}] {r.ttp_id:12} {r.name[:40]:40} score={r.score:.3f}")


if __name__ == "__main__":
    main()
