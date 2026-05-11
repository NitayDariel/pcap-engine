"""
abuse.ch ThreatFox API client.
Key loaded from .env as AbuseCh_API_KEY.

API quirk: when no results, 'data' is a string ("Your search did not yield any results"),
not an empty list. Always call _parse_data() instead of accessing 'data' directly.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

_here = Path(__file__).resolve()
for _candidate in [
    _here.parents[3] / ".env",  # NetworkAnalysis-Research/.env
    _here.parents[2] / ".env",  # pcap-engine/.env
]:
    if _candidate.exists():
        load_dotenv(_candidate)
        break

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


class AbusechError(Exception):
    pass


def _get_key() -> str:
    key = os.getenv("AbuseCh_API_KEY", "")
    if not key:
        raise AbusechError("AbuseCh_API_KEY not set in environment / .env")
    return key


def _post(payload: dict) -> dict:
    headers = {"Auth-Key": _get_key()}
    resp = requests.post(THREATFOX_URL, json=payload, headers=headers, timeout=30)
    if not resp.ok:
        raise AbusechError(f"ThreatFox HTTP {resp.status_code}: {resp.text[:200]}")
    return resp.json()


def _parse_data(raw: dict) -> list[dict]:
    """
    ThreatFox returns data as:
      - list[dict]  when query_status == 'ok' (hits found)
      - str         when query_status == 'no_result' or 'illegal_search_term'
    Always returns a list (empty on no result).
    """
    data = raw.get("data", [])
    if isinstance(data, list):
        return data
    return []


def search_ioc(term: str) -> list[dict]:
    """
    Search ThreatFox for an IOC (IP, domain, URL, hash).
    Returns a list of matching IOC dicts, empty if none found.
    Each dict includes: ioc, threat_type, malware, malware_printable,
    confidence_level, first_seen, tags, malware_samples.
    """
    raw = _post({"query": "search_ioc", "search_term": term})
    return _parse_data(raw)


def search_hash(file_hash: str) -> list[dict]:
    """Search by file hash (MD5 or SHA256)."""
    raw = _post({"query": "search_hash", "hash": file_hash})
    return _parse_data(raw)


def search_tag(tag: str) -> list[dict]:
    """Search all IOCs with a given tag (e.g. 'Cobalt Strike', 'NetSupport')."""
    raw = _post({"query": "search_iocs", "search_term": tag})
    return _parse_data(raw)


def summarise(ioc_results: list[dict]) -> Optional[dict]:
    """
    Collapse a list of ThreatFox hits into a single summary dict.
    Returns None if the list is empty.
    """
    if not ioc_results:
        return None
    best = max(ioc_results, key=lambda x: x.get("confidence_level", 0))
    return {
        "ioc": best.get("ioc", ""),
        "threat_type": best.get("threat_type", ""),
        "malware": best.get("malware_printable", best.get("malware", "")),
        "confidence": best.get("confidence_level", 0),
        "first_seen": best.get("first_seen", ""),
        "tags": best.get("tags", []),
        "total_hits": len(ioc_results),
        "has_samples": any(r.get("malware_samples") for r in ioc_results),
    }


def is_malicious(term: str) -> tuple[bool, Optional[dict]]:
    """
    Convenience: check if an IOC is in ThreatFox.
    Returns (found: bool, summary: dict | None).
    """
    hits = search_ioc(term)
    return bool(hits), summarise(hits)
