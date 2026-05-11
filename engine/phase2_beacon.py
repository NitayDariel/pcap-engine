"""
Phase 2 Beacon Scoring — RITA-style 4-factor composite.

Reads Zeek conn.log and scores every (src → dst) pair for C2 beaconing.
Four independent factors, each in [0, 1]:

  1. interval_score  — timestamp consistency (low jitter → high score)
  2. size_score      — datasize consistency (same-payload keepalive → high score)
  3. freq_score      — histogram frequency (fraction of intervals near modal bucket)
  4. persist_score   — duration/persistence (beacons run for hours, not seconds)

Composite = geometric mean of the four factors.
FFT is applied on the interval sequence to detect sub-harmonic periodicity and
handle jitter that would fool a pure coefficient-of-variation check.

Caller: phase2_protocol.run() — appends beacon_candidates to ProtocolSignals.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_CONNECTIONS = 10          # statistical floor — fewer = unreliable
MAX_INTERVAL_SECS = 3600      # ignore gaps > 1 h (host went offline)
PERSIST_NORM_HOURS = 4.0      # 4 h of beaconing → persist_score == 1.0
FREQ_BIN_WIDTH_RATIO = 0.10   # ±10 % of modal interval = "same bin"
FFT_NOISE_RATIO = 3.0         # dominant FFT component must be 3× background
FFT_WEIGHT = 0.10             # FFT boosts composite by up to this much
SCORE_THRESHOLD = 0.50        # minimum composite to be a beacon candidate
TOP_N = 20                    # maximum candidates returned


# ---------------------------------------------------------------------------
# Output structure
# ---------------------------------------------------------------------------

@dataclass
class BeaconCandidate:
    src_ip: str
    dst_ip: str
    dst_port: int
    connection_count: int
    modal_interval_secs: float    # dominant inter-arrival time
    interval_jitter_secs: float   # stddev of inter-arrival times
    avg_bytes_orig: float         # mean payload from src→dst
    duration_hours: float         # total span of observed connections
    interval_score: float         # [0, 1] — regularity
    size_score: float             # [0, 1] — payload consistency
    freq_score: float             # [0, 1] — histogram concentration
    persist_score: float          # [0, 1] — long-running
    fft_period_secs: float        # dominant FFT period (0 if not detected)
    composite_score: float        # geometric mean + FFT bonus


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _geomean(values: list[float]) -> float:
    """Geometric mean of values in [0, 1]. Returns 0 if any value is 0."""
    if not values or any(v <= 0.0 for v in values):
        return 0.0
    log_sum = sum(math.log(v) for v in values)
    return math.exp(log_sum / len(values))


def _interval_score(iats: np.ndarray) -> float:
    """
    Coefficient of variation (CV) inverted and clamped.
    CV = stddev / mean — beacon traffic has CV close to 0.
    """
    if len(iats) < 2:
        return 0.0
    mean = float(np.mean(iats))
    if mean <= 0:
        return 0.0
    cv = float(np.std(iats)) / mean
    # CV 0→0.1 maps to score 1.0→0.5; CV ≥ 1.0 → score 0
    score = max(0.0, 1.0 - cv)
    return min(1.0, score)


def _size_score(byte_series: np.ndarray) -> float:
    """Inverted CV on per-connection bytes. Consistent payload = beaconing keepalive."""
    if len(byte_series) < 2:
        return 0.0
    mean = float(np.mean(byte_series))
    if mean <= 0:
        return 0.5  # zero-byte connections are consistent by definition
    cv = float(np.std(byte_series)) / mean
    return max(0.0, min(1.0, 1.0 - cv))


def _freq_score(iats: np.ndarray, modal: float) -> float:
    """Fraction of intervals that fall within ±10% of the modal interval."""
    if len(iats) == 0 or modal <= 0:
        return 0.0
    tol = modal * FREQ_BIN_WIDTH_RATIO
    in_bin = np.sum((iats >= modal - tol) & (iats <= modal + tol))
    return float(in_bin) / len(iats)


def _persist_score(duration_secs: float) -> float:
    """Normalize duration to PERSIST_NORM_HOURS."""
    return min(1.0, duration_secs / (PERSIST_NORM_HOURS * 3600))


def _fft_analysis(iats: np.ndarray, sample_interval: float) -> tuple[float, float]:
    """
    Run FFT on inter-arrival sequence to detect jitter-masked periodicity.
    Returns (dominant_period_secs, fft_score [0,1]).
    fft_score > 0 means a dominant frequency was detected above noise floor.
    """
    if len(iats) < 8:
        return 0.0, 0.0

    try:
        # Resample IAT sequence onto a regular grid (needed for FFT)
        n = len(iats)
        spectrum = np.abs(np.fft.rfft(iats - np.mean(iats)))
        freqs = np.fft.rfftfreq(n, d=sample_interval)

        if len(spectrum) < 2:
            return 0.0, 0.0

        # Remove DC component (index 0)
        ac_spectrum = spectrum[1:]
        ac_freqs = freqs[1:]

        if len(ac_spectrum) == 0:
            return 0.0, 0.0

        # Dominant component
        dom_idx = int(np.argmax(ac_spectrum))
        dom_power = float(ac_spectrum[dom_idx])

        # Background = median of remaining components
        mask = np.ones(len(ac_spectrum), dtype=bool)
        mask[dom_idx] = False
        bg_components = ac_spectrum[mask]
        background = float(np.median(bg_components)) if len(bg_components) > 0 else dom_power

        if background <= 0 or dom_power < FFT_NOISE_RATIO * background:
            return 0.0, 0.0

        dom_freq = float(ac_freqs[dom_idx])
        period = 1.0 / dom_freq if dom_freq > 0 else 0.0

        # Normalize score: ratio capped at 10× → score 1.0
        ratio = dom_power / (background + 1e-9)
        fft_score = min(1.0, (ratio - FFT_NOISE_RATIO) / (10.0 - FFT_NOISE_RATIO))

        return period, max(0.0, fft_score)

    except Exception:
        return 0.0, 0.0


# ---------------------------------------------------------------------------
# Per-pair scoring
# ---------------------------------------------------------------------------

def _score_pair(
    src: str,
    dst: str,
    port: int,
    group_df: pd.DataFrame,
) -> Optional[BeaconCandidate]:
    """Score a single (src, dst, port) conversation group."""
    if len(group_df) < MIN_CONNECTIONS:
        return None

    ts = group_df["ts"].sort_values().values.astype(float)
    duration_secs = float(ts[-1] - ts[0])

    # Inter-arrival times — cap at MAX_INTERVAL_SECS to handle host-offline gaps
    raw_iats = np.diff(ts)
    iats = raw_iats[raw_iats <= MAX_INTERVAL_SECS]

    if len(iats) < 2:
        return None

    modal_interval = float(np.median(iats))
    jitter = float(np.std(iats))

    # Payload sizes
    bytes_col = "orig_bytes" if "orig_bytes" in group_df.columns else None
    if bytes_col:
        byte_vals = pd.to_numeric(group_df[bytes_col], errors="coerce").fillna(0).values
    else:
        byte_vals = np.zeros(len(group_df))

    avg_bytes = float(np.mean(byte_vals))

    # Four factors
    i_score = _interval_score(iats)
    s_score = _size_score(byte_vals)
    f_score = _freq_score(iats, modal_interval)
    p_score = _persist_score(duration_secs)

    # FFT
    sample_interval = modal_interval if modal_interval > 0 else 1.0
    fft_period, fft_score = _fft_analysis(iats, sample_interval)

    # Composite: geometric mean of four factors
    composite = _geomean([i_score, s_score, f_score, p_score])

    # FFT bonus: adds up to FFT_WEIGHT if strong periodicity detected
    composite = min(1.0, composite + fft_score * FFT_WEIGHT)

    if composite < SCORE_THRESHOLD:
        return None

    return BeaconCandidate(
        src_ip=src,
        dst_ip=dst,
        dst_port=port,
        connection_count=len(group_df),
        modal_interval_secs=round(modal_interval, 2),
        interval_jitter_secs=round(jitter, 2),
        avg_bytes_orig=round(avg_bytes, 1),
        duration_hours=round(duration_secs / 3600, 2),
        interval_score=round(i_score, 3),
        size_score=round(s_score, 3),
        freq_score=round(f_score, 3),
        persist_score=round(p_score, 3),
        fft_period_secs=round(fft_period, 2),
        composite_score=round(composite, 3),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(
    conn_df: pd.DataFrame,
    internal_ips: Optional[set] = None,
    internal_cidrs: Optional[list[str]] = None,
) -> list[BeaconCandidate]:
    """
    Score all (src, dst, port) pairs in conn_df for beaconing.

    Args:
        conn_df: Zeek conn.log as a DataFrame (must have ts, id.orig_h,
                 id.resp_h, id.resp_p, orig_bytes columns).
        internal_ips: set of known internal IP strings. If provided, only score
                      internal→external pairs. Takes precedence over internal_cidrs.
        internal_cidrs: list of CIDR strings like ["10.0.0.0/8"] — fallback if
                        internal_ips is not provided.

    Returns:
        List of BeaconCandidate, sorted by composite_score descending, up to TOP_N.
    """
    if conn_df is None or conn_df.empty:
        return []

    # Normalise column names (Zeek JSON uses dotted names like id.orig_h)
    col_map = {
        "id.orig_h": "src",
        "id.resp_h": "dst",
        "id.resp_p": "port",
    }
    df = conn_df.rename(columns=col_map)

    required = {"src", "dst", "port", "ts"}
    if not required.issubset(df.columns):
        return []

    df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    df = df.dropna(subset=["ts", "src", "dst"])
    df["port"] = pd.to_numeric(df["port"], errors="coerce").fillna(0).astype(int)

    # Filter internal→external only
    if internal_ips:
        # Fast set-based lookup
        df = df[df["src"].isin(internal_ips) & ~df["dst"].isin(internal_ips)]
    elif internal_cidrs:
        import ipaddress
        nets = []
        for cidr in internal_cidrs:
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

        def _is_internal(ip_str: str) -> bool:
            try:
                addr = ipaddress.ip_address(ip_str)
                return any(addr in net for net in nets)
            except ValueError:
                return False

        df = df[df["src"].apply(_is_internal) & ~df["dst"].apply(_is_internal)]

    candidates: list[BeaconCandidate] = []

    for (src, dst, port), grp in df.groupby(["src", "dst", "port"], sort=False):
        candidate = _score_pair(str(src), str(dst), int(port), grp)
        if candidate:
            candidates.append(candidate)

    candidates.sort(key=lambda c: c.composite_score, reverse=True)
    return candidates[:TOP_N]
