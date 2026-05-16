"""
Zeek runner and log parser.
run_zeek() invokes zeek as subprocess and writes JSON logs to output_dir.
parse_*() functions are independent of zeek being run — they just read log files.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import pandas as pd

ZEEK_BIN = shutil.which("zeek") or "/opt/homebrew/bin/zeek"

# 'packages' loads all zkg-installed packages (e.g. JA3/JA3S) when present.
# Zeek silently succeeds even if no packages are installed, so this is always safe.
_ZEEK_PACKAGES_SCRIPT = "packages"


class ZeekError(Exception):
    pass


def run_zeek(
    pcap_path: str,
    output_dir: Optional[str] = None,
    timeout: int = 300,
) -> Path:
    """
    Run zeek against a PCAP. Returns Path to directory containing JSON logs.
    If output_dir is None, creates a temp directory (caller is responsible for cleanup).
    Uses -C to ignore checksum errors (common in captures from VMs or taps).
    """
    if not Path(ZEEK_BIN).exists() and not shutil.which("zeek"):
        raise ZeekError(
            f"zeek not found at {ZEEK_BIN}. Install with: brew install zeek"
        )

    out = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="zeek_"))
    out.mkdir(parents=True, exist_ok=True)

    # Zeek wants Log::default_logdir as a string literal passed as a script fragment
    cmd = [
        ZEEK_BIN,
        "-C",                           # ignore checksum errors
        "-r", str(pcap_path),
        "LogAscii::use_json=T",         # emit JSON instead of TSV
        f"Log::default_logdir={out}",
        _ZEEK_PACKAGES_SCRIPT,          # load zkg packages (JA3/JA3S if installed)
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(out),  # run from output dir so relative log paths resolve
        )
    except subprocess.TimeoutExpired:
        raise ZeekError(
            f"Zeek timed out after {timeout}s. The PCAP may be too large. "
            f"Try --zeek-timeout {timeout * 2} or --max-pcap-mb to reject oversized files."
        )

    # zeek exits 0 on success, 1 on non-fatal warnings, higher on real errors
    if result.returncode > 1:
        raise ZeekError(
            f"zeek exited {result.returncode}\n"
            f"stderr: {result.stderr[:1000]}"
        )

    return out


def _parse_json_log(path: Path) -> list[dict]:
    """Read a zeek JSON log line by line. Skips comment lines (TSV compat remnants)."""
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def parse_log(log_path: str) -> pd.DataFrame:
    """Parse any zeek JSON log into a DataFrame. Returns empty DF if file missing."""
    p = Path(log_path)
    if not p.exists():
        return pd.DataFrame()
    records = _parse_json_log(p)
    return pd.DataFrame(records) if records else pd.DataFrame()


def parse_conn_log(log_dir: str) -> pd.DataFrame:
    """conn.log — one row per completed TCP/UDP/ICMP connection."""
    return parse_log(f"{log_dir}/conn.log")


def parse_dns_log(log_dir: str) -> pd.DataFrame:
    """dns.log — one row per DNS query+response pair."""
    return parse_log(f"{log_dir}/dns.log")


def parse_ssl_log(log_dir: str) -> pd.DataFrame:
    """ssl.log — TLS sessions with cert info, JA3, SNI."""
    return parse_log(f"{log_dir}/ssl.log")


def parse_http_log(log_dir: str) -> pd.DataFrame:
    """http.log — HTTP requests and responses."""
    return parse_log(f"{log_dir}/http.log")


def parse_files_log(log_dir: str) -> pd.DataFrame:
    """files.log — extracted files with MD5/SHA1/SHA256 hashes."""
    return parse_log(f"{log_dir}/files.log")


def parse_weird_log(log_dir: str) -> pd.DataFrame:
    """weird.log — protocol anomalies detected by zeek."""
    return parse_log(f"{log_dir}/weird.log")


def available_logs(log_dir: str) -> list[str]:
    """Return list of log file names present in log_dir (*.log only)."""
    return sorted(p.name for p in Path(log_dir).glob("*.log"))
