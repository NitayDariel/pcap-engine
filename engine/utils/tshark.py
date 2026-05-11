"""
tshark subprocess wrapper.
All callers go through run() — never shell out to tshark directly.
"""

from __future__ import annotations

import subprocess
import shutil
from pathlib import Path
from typing import Optional

TSHARK_BIN = shutil.which("tshark") or "/opt/homebrew/bin/tshark"
DEFAULT_TIMEOUT = 120  # seconds


class TsharkError(Exception):
    pass


def run(
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    pcap: Optional[str] = None,
) -> str:
    """
    Run tshark with the given args. Prepends the binary path automatically.
    If pcap is given, injects -r <pcap> as the first arg (convenience shortcut).
    Returns stdout as a stripped string. Raises TsharkError on non-zero exit.
    """
    cmd = [TSHARK_BIN]
    if pcap:
        cmd += ["-r", pcap]
    cmd += args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise TsharkError(f"tshark timed out after {timeout}s: {' '.join(cmd)}")
    except FileNotFoundError:
        raise TsharkError(f"tshark not found at {TSHARK_BIN}. Install with: brew install wireshark")

    if result.returncode not in (0, 1):
        raise TsharkError(
            f"tshark exited {result.returncode}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )

    return result.stdout.strip()


def fields(pcap: str, display_filter: str, *field_names: str, timeout: int = DEFAULT_TIMEOUT) -> list[list[str]]:
    """
    Extract specific fields from packets matching a display filter.
    Returns a list of rows, each row is a list of field values (tab-split).
    Empty-string fields are preserved; blank rows are skipped.
    """
    args = ["-Y", display_filter, "-T", "fields"]
    for f in field_names:
        args += ["-e", f]
    args += ["-E", "separator=\t"]

    raw = run(args, pcap=pcap, timeout=timeout)
    rows = []
    for line in raw.splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def stat(pcap: str, stat_name: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Run a -z statistics query and return the raw output string."""
    return run(["-q", "-z", stat_name], pcap=pcap, timeout=timeout)


def protocol_histogram(pcap: str) -> str:
    """Return the full protocol hierarchy statistics block."""
    return stat(pcap, "io,phs")


def conversation_matrix(pcap: str) -> str:
    """Return the IP conversation matrix."""
    return stat(pcap, "conv,ip")


def unique_ips(pcap: str) -> set[str]:
    """Return all unique source and destination IPs in the capture."""
    raw = run(
        ["-T", "fields", "-e", "ip.src", "-e", "ip.dst"],
        pcap=pcap,
    )
    ips: set[str] = set()
    for line in raw.splitlines():
        for ip in line.split("\t"):
            ip = ip.strip()
            if ip:
                ips.add(ip)
    return ips


def capture_duration(pcap: str) -> tuple[str, str]:
    """Return (first_timestamp, last_timestamp) as raw strings."""
    raw = run(["-T", "fields", "-e", "frame.time"], pcap=pcap)
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return ("", "")
    return (lines[0], lines[-1])
