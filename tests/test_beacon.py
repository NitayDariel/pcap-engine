"""
Unit tests for engine/phase2_beacon.py.
Run:  python -m pytest tests/test_beacon.py -v
"""
import numpy as np
import pandas as pd
import pytest

from engine.phase2_beacon import (
    run,
    _interval_score,
    _size_score,
    _freq_score,
    _persist_score,
    _fft_analysis,
    SCORE_THRESHOLD,
    MIN_CONNECTIONS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conn_df(src, dst, port, timestamps, bytes_per_conn=100):
    n = len(timestamps)
    return pd.DataFrame({
        "ts": timestamps,
        "id.orig_h": [src] * n,
        "id.resp_h": [dst] * n,
        "id.resp_p": [port] * n,
        "orig_bytes": [bytes_per_conn] * n,
    })


def _regular_timestamps(n, interval_secs, base=1_700_000_000.0):
    return [base + i * interval_secs for i in range(n)]


# ---------------------------------------------------------------------------
# Factor functions — unit tests
# ---------------------------------------------------------------------------

def test_interval_score_perfect_regularity():
    iats = np.full(20, 60.0)
    s = _interval_score(iats)
    assert s == pytest.approx(1.0)


def test_interval_score_random_is_low():
    rng = np.random.default_rng(0)
    iats = rng.uniform(1, 3600, 50)
    s = _interval_score(iats)
    assert s < 0.5


def test_size_score_uniform_bytes():
    bv = np.full(20, 128.0)
    assert _size_score(bv) == pytest.approx(1.0)


def test_size_score_zero_bytes():
    bv = np.zeros(20)
    assert _size_score(bv) == pytest.approx(0.5)  # zero-byte handled as consistent


def test_freq_score_all_in_bin():
    modal = 60.0
    iats = np.full(20, 60.0)
    assert _freq_score(iats, modal) == pytest.approx(1.0)


def test_persist_score_4h_is_max():
    # 4 h = PERSIST_NORM_HOURS → score 1.0
    assert _persist_score(4 * 3600) == pytest.approx(1.0)


def test_persist_score_short_is_low():
    assert _persist_score(60.0) < 0.1


# ---------------------------------------------------------------------------
# FFT — correctness after resample fix
# ---------------------------------------------------------------------------

def test_fft_detects_bimodal_alternating_intervals():
    # FFT on IAT values detects periodicity IN the IAT sequence itself —
    # e.g. an implant that alternates short keep-alive and long data-pull intervals.
    # For simple "constant ± small jitter", _interval_score (CV) handles detection;
    # that signal has no AC component after DC removal and correctly yields fft_score=0.
    #
    # Here: strictly alternating 30 s / 90 s → strong 2-sample period that FFT catches.
    iats = np.tile([30.0, 90.0], 16)  # 32 values, strict alternation
    period, fft_score = _fft_analysis(iats, float(np.median(iats)))
    assert fft_score > 0.0, (
        "FFT should detect the alternating short/long interval pattern. "
        f"Got fft_score={fft_score}, period={period:.1f}s"
    )


def test_fft_no_signal_on_noise():
    rng = np.random.default_rng(42)
    iats = rng.uniform(10, 3600, 30)
    _, fft_score = _fft_analysis(iats, float(np.median(iats)))
    # Random traffic should rarely clear the 3× noise floor threshold
    assert fft_score < 0.5, f"Random IATs should not score high in FFT: {fft_score}"


def test_fft_too_few_samples_returns_zero():
    iats = np.array([60.0, 60.0, 60.0])
    period, score = _fft_analysis(iats, 60.0)
    assert period == 0.0
    assert score == 0.0


# ---------------------------------------------------------------------------
# run() — integration
# ---------------------------------------------------------------------------

def test_regular_beacon_detected():
    """60-second interval beacon over 20 min should score above threshold."""
    ts = _regular_timestamps(20, 60.0)
    df = _conn_df("10.0.0.1", "1.2.3.4", 443, ts)
    candidates = run(df, internal_ips={"10.0.0.1"})
    assert len(candidates) >= 1
    top = candidates[0]
    assert top.composite_score >= SCORE_THRESHOLD
    assert top.src_ip == "10.0.0.1"
    assert top.dst_ip == "1.2.3.4"
    assert top.dst_port == 443


def test_random_traffic_no_false_positive():
    rng = np.random.default_rng(99)
    base = 1_700_000_000.0
    ts = sorted(base + rng.uniform(0, 7200, 30))
    df = _conn_df("10.0.0.1", "1.2.3.4", 80, ts)
    candidates = run(df, internal_ips={"10.0.0.1"})
    for c in candidates:
        assert c.composite_score < 0.85, f"Random traffic scored too high: {c.composite_score}"


def test_too_few_connections_skipped():
    ts = _regular_timestamps(MIN_CONNECTIONS - 1, 60.0)
    df = _conn_df("10.0.0.1", "1.2.3.4", 443, ts)
    candidates = run(df, internal_ips={"10.0.0.1"})
    assert len(candidates) == 0


def test_internal_to_internal_excluded():
    ts = _regular_timestamps(20, 60.0)
    df = _conn_df("10.0.0.1", "10.0.0.2", 443, ts)
    candidates = run(df, internal_ips={"10.0.0.1", "10.0.0.2"})
    assert len(candidates) == 0


def test_internal_cidr_filter():
    ts = _regular_timestamps(20, 60.0)
    df = _conn_df("192.168.1.5", "8.8.8.8", 443, ts)
    candidates = run(df, internal_cidrs=["192.168.1.0/24"])
    assert len(candidates) >= 1
    assert candidates[0].src_ip == "192.168.1.5"


def test_results_sorted_descending():
    base = 1_700_000_000.0
    # Regular beacon to 1.1.1.1
    ts_reg = _regular_timestamps(20, 60.0, base=base)
    # Irregular traffic to 2.2.2.2
    rng = np.random.default_rng(7)
    ts_irr = sorted(base + 7200 + rng.uniform(0, 7200, 20))
    df_reg = _conn_df("10.0.0.1", "1.1.1.1", 443, ts_reg)
    df_irr = _conn_df("10.0.0.2", "2.2.2.2", 80, ts_irr)
    df = pd.concat([df_reg, df_irr], ignore_index=True)
    candidates = run(df, internal_ips={"10.0.0.1", "10.0.0.2"})
    for i in range(len(candidates) - 1):
        assert candidates[i].composite_score >= candidates[i + 1].composite_score


def test_modal_interval_extracted():
    ts = _regular_timestamps(20, 30.0)
    df = _conn_df("10.0.0.5", "5.6.7.8", 4444, ts)
    candidates = run(df, internal_ips={"10.0.0.5"})
    if candidates:
        assert abs(candidates[0].modal_interval_secs - 30.0) < 5.0


def test_empty_dataframe_returns_empty():
    df = pd.DataFrame(columns=["ts", "id.orig_h", "id.resp_h", "id.resp_p", "orig_bytes"])
    candidates = run(df, internal_ips={"10.0.0.1"})
    assert candidates == []


def test_missing_required_columns_returns_empty():
    df = pd.DataFrame({"src": ["10.0.0.1"], "dst": ["1.2.3.4"]})
    candidates = run(df, internal_ips={"10.0.0.1"})
    assert candidates == []
