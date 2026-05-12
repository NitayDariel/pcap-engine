"""
Gemini API client for AI-driven anomaly hypothesis generation.
Uses the current google-genai SDK (replaces deprecated google-generativeai).
Key priority: GOOGLE_API_GENERAL_KEY → GOOGLE_API_KEY (loaded from .env).
Falls back silently if key is absent or quota is exhausted.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_here = Path(__file__).resolve()
for _candidate in [
    _here.parents[3] / ".env",   # NetworkAnalysis-Research/.env
    _here.parents[2] / ".env",   # pcap-engine/.env
]:
    if _candidate.exists():
        load_dotenv(_candidate)
        break

_MODEL = "gemini-3.1-flash-lite"
_TIMEOUT = 30       # seconds per call
_MAX_RETRIES = 2    # retry once after a quota-suggested delay


def _get_api_key() -> str:
    """Return the best available Gemini API key."""
    return (
        os.getenv("GOOGLE_API_GENERAL_KEY", "")
        or os.getenv("GOOGLE_API_KEY", "")
    )


def is_available() -> bool:
    """True if a Gemini API key is set and google-genai is importable."""
    if not _get_api_key():
        return False
    try:
        from google import genai  # noqa: F401
        return True
    except ImportError:
        return False


def generate_hypothesis(prompt: str) -> Optional[str]:
    """
    Send a structured anomaly prompt to Gemini and return the hypothesis text.
    Retries once if the API suggests a retry delay (rate limit / quota exhausted).
    Returns None on any unrecoverable error.
    """
    key = _get_api_key()
    if not key:
        return None

    try:
        from google import genai
        from google.genai import types
    except ImportError:
        return None

    client = genai.Client(api_key=key)
    config = types.GenerateContentConfig(
        temperature=0.3,
        max_output_tokens=512,
    )

    for attempt in range(_MAX_RETRIES):
        try:
            response = client.models.generate_content(
                model=_MODEL,
                contents=prompt,
                config=config,
            )
            text = response.text
            return text.strip() if text else None

        except Exception as e:
            err_str = str(e)
            # Extract suggested retry delay from the error message if present
            retry_secs = _parse_retry_delay(err_str)
            if retry_secs and attempt < _MAX_RETRIES - 1:
                print(f"  [Gemini] rate limited — retrying in {retry_secs}s...")
                time.sleep(retry_secs + 1)
                continue
            # Quota exhausted or unrecoverable — log brief error and bail
            brief = err_str[:120].split("\n")[0]
            print(f"  [Gemini] hypothesis call failed: {brief}")
            return None

    return None


def _parse_retry_delay(err_str: str) -> Optional[int]:
    """Extract suggested retry delay (seconds) from a quota error message."""
    import re
    m = re.search(r'retry_delay\s*\{[^}]*seconds:\s*(\d+)', err_str)
    if m:
        return int(m.group(1))
    m = re.search(r'retry in (\d+)', err_str)
    if m:
        return int(m.group(1))
    return None
