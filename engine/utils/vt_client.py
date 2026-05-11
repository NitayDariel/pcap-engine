"""
VirusTotal API v3 client.
Rate-limited to 4 requests/minute (free tier). Key loaded from .env.
"""

from __future__ import annotations

import time
import os
from typing import Optional
from pathlib import Path

import requests
from dotenv import load_dotenv

# Load .env from project root (pcap-engine/../.env or pcap-engine/.env)
_here = Path(__file__).resolve()
for _candidate in [
    _here.parents[3] / ".env",  # NetworkAnalysis-Research/.env
    _here.parents[2] / ".env",  # pcap-engine/.env
]:
    if _candidate.exists():
        load_dotenv(_candidate)
        break

VT_BASE = "https://www.virustotal.com/api/v3"
_MIN_INTERVAL = 15.0  # 4 req/min = 1 req per 15s
_last_call: float = 0.0


class VTError(Exception):
    pass


def _get_key() -> str:
    key = os.getenv("VirusTotal_API_KEY", "")
    if not key:
        raise VTError("VirusTotal_API_KEY not set in environment / .env")
    return key


def _throttle() -> None:
    global _last_call
    elapsed = time.time() - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.time()


def _get(endpoint: str) -> dict:
    _throttle()
    headers = {"x-apikey": _get_key()}
    resp = requests.get(f"{VT_BASE}/{endpoint}", headers=headers, timeout=30)
    if resp.status_code == 429:
        raise VTError("VT rate limit hit. Slow down or reduce batch size.")
    if resp.status_code == 404:
        return {}
    if not resp.ok:
        raise VTError(f"VT API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def lookup_ip(ip: str) -> dict:
    """
    Returns summarised reputation data for an IP.
    Keys: owner, country, malicious, suspicious, harmless, undetected, reputation, tags.
    Returns empty dict if IP not found.
    """
    data = _get(f"ip_addresses/{ip}")
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "owner": attrs.get("as_owner", ""),
        "country": attrs.get("country", ""),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
    }


def lookup_domain(domain: str) -> dict:
    """Returns summarised reputation data for a domain."""
    data = _get(f"domains/{domain}")
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "domain": domain,
        "registrar": attrs.get("registrar", ""),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "categories": attrs.get("categories", {}),
        "tags": attrs.get("tags", []),
    }


def lookup_hash(file_hash: str) -> dict:
    """Returns summarised threat data for a file hash (MD5/SHA1/SHA256)."""
    data = _get(f"files/{file_hash}")
    if not data:
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "hash": file_hash,
        "name": attrs.get("meaningful_name", ""),
        "type": attrs.get("type_description", ""),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "reputation": attrs.get("reputation", 0),
        "tags": attrs.get("tags", []),
    }


def is_malicious(result: dict, threshold: int = 3) -> bool:
    """True if malicious engine count meets threshold."""
    return result.get("malicious", 0) >= threshold
