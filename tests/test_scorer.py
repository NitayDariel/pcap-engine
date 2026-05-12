"""
Unit tests for engine/scorer.py.
Run:  python -m pytest tests/test_scorer.py -v
"""
import pytest

from engine.scorer import (
    score,
    TTPScore,
    CONFIDENCE_CONFIRMED,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_LOW,
    CONFIDENCE_ANOMALY,
)
from engine.phase2_protocol import ProtocolSignals


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pb(**overrides) -> dict:
    base = {
        "ttp_id": "T9999",
        "name": "Test TTP",
        "category": "test",
        "mitre_tactic": "TA0000",
        "signals": [],
        "combination_bonuses": [],
    }
    base.update(overrides)
    return base


def _sig(sid, source, threshold, weight, attack_category="A", **extra) -> dict:
    s = {"id": sid, "source": source, "threshold": threshold, "weight": weight, "attack_category": attack_category}
    s.update(extra)
    return s


# ---------------------------------------------------------------------------
# Basic scoring
# ---------------------------------------------------------------------------

def test_no_signals_scores_zero():
    result = score(_pb(), ProtocolSignals())
    assert result.score == 0.0
    assert result.signals_fired == []


def test_strong_signal_fires():
    pb = _pb(signals=[_sig("s1", "dns_packet_count", ">= 10", 0.5)])
    result = score(pb, ProtocolSignals(dns_packet_count=100))
    assert result.score == pytest.approx(0.5)
    assert "s1" in result.signals_fired


def test_signal_below_threshold_does_not_fire():
    pb = _pb(signals=[_sig("s1", "dns_packet_count", ">= 1000", 0.5)])
    result = score(pb, ProtocolSignals(dns_packet_count=5))
    assert result.score == 0.0
    assert result.signals_fired == []


def test_score_capped_at_1():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 1", 0.7, attack_category="A"),
        _sig("s2", "http_packet_count", ">= 1", 0.7, attack_category="B"),
    ])
    result = score(pb, ProtocolSignals(dns_packet_count=10, http_packet_count=10))
    assert result.score <= 1.0


def test_boolean_signal_true():
    pb = _pb(signals=[_sig("s1", "smb_admin_share_detected", "== True", 0.6)])
    result = score(pb, ProtocolSignals(smb_admin_share_detected=True))
    assert result.score == pytest.approx(0.6)
    assert "s1" in result.signals_fired


def test_boolean_signal_false_does_not_fire():
    pb = _pb(signals=[_sig("s1", "smb_admin_share_detected", "== True", 0.6)])
    result = score(pb, ProtocolSignals(smb_admin_share_detected=False))
    assert result.score == 0.0


# ---------------------------------------------------------------------------
# Tiered thresholds (weak fire)
# ---------------------------------------------------------------------------

def test_weak_signal_fires_with_suffix():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 1000", 0.5,
             threshold_low=">= 10", weight_low=0.2)
    ])
    result = score(pb, ProtocolSignals(dns_packet_count=100))
    assert result.score == pytest.approx(0.2)
    assert "s1_weak" in result.signals_fired
    assert "s1" not in result.signals_fired


def test_strong_fires_over_weak_when_both_met():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 10", 0.5,
             threshold_low=">= 1", weight_low=0.2)
    ])
    result = score(pb, ProtocolSignals(dns_packet_count=100))
    assert result.score == pytest.approx(0.5)
    assert "s1" in result.signals_fired
    assert "s1_weak" not in result.signals_fired


# ---------------------------------------------------------------------------
# Combination bonuses
# ---------------------------------------------------------------------------

def test_combination_bonus_applied():
    pb = _pb(
        signals=[
            _sig("s1", "dns_packet_count", ">= 10", 0.3, attack_category="A"),
            _sig("s2", "http_packet_count", ">= 10", 0.3, attack_category="B"),
        ],
        combination_bonuses=[{"signals": ["s1", "s2"], "bonus": 0.2}],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=100, http_packet_count=100))
    assert result.score == pytest.approx(0.8)


def test_combination_bonus_not_applied_when_signal_missing():
    pb = _pb(
        signals=[
            _sig("s1", "dns_packet_count", ">= 10", 0.3, attack_category="A"),
            _sig("s2", "http_packet_count", ">= 10", 0.3, attack_category="B"),
        ],
        combination_bonuses=[{"signals": ["s1", "s2"], "bonus": 0.2}],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=100, http_packet_count=0))
    assert result.score == pytest.approx(0.3)


def test_combination_bonus_fires_on_weak_signal():
    """Weak signal base IDs still qualify for combination bonuses."""
    pb = _pb(
        signals=[
            _sig("s1", "dns_packet_count", ">= 1000", 0.3,
                 threshold_low=">= 10", weight_low=0.15, attack_category="A"),
            _sig("s2", "http_packet_count", ">= 10", 0.3, attack_category="B"),
        ],
        combination_bonuses=[{"signals": ["s1", "s2"], "bonus": 0.1}],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=100, http_packet_count=50))
    assert "s1_weak" in result.signals_fired
    assert result.score == pytest.approx(0.55)  # 0.15 + 0.30 + 0.10 bonus


# ---------------------------------------------------------------------------
# Minimum presence gate
# ---------------------------------------------------------------------------

def test_minimum_presence_gate_skips():
    pb = _pb(
        minimum_presence={"dns_packet_count": 100},
        signals=[_sig("s1", "http_packet_count", ">= 1", 1.0)],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=0, http_packet_count=100))
    assert result.skipped is True
    assert result.score == 0.0


def test_minimum_presence_gate_passes_when_met():
    pb = _pb(
        minimum_presence={"dns_packet_count": 10},
        signals=[_sig("s1", "http_packet_count", ">= 1", 0.5)],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=100, http_packet_count=100))
    assert result.skipped is False
    assert result.score == pytest.approx(0.5)


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

def test_one_signal_is_low_confidence():
    pb = _pb(signals=[_sig("s1", "dns_packet_count", ">= 1", 0.4, attack_category="A")])
    result = score(pb, ProtocolSignals(dns_packet_count=10))
    assert result.confidence == CONFIDENCE_LOW


def test_two_signals_one_category_is_medium():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 1", 0.4, attack_category="A"),
        _sig("s2", "http_packet_count", ">= 1", 0.4, attack_category="A"),
    ])
    result = score(pb, ProtocolSignals(dns_packet_count=10, http_packet_count=10))
    assert result.confidence == CONFIDENCE_MEDIUM


def test_three_signals_two_categories_is_high():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 1", 0.3, attack_category="A"),
        _sig("s2", "http_packet_count", ">= 1", 0.3, attack_category="B"),
        _sig("s3", "smb_packet_count", ">= 1", 0.3, attack_category="A"),
    ])
    result = score(pb, ProtocolSignals(dns_packet_count=10, http_packet_count=10, smb_packet_count=10))
    assert result.confidence == CONFIDENCE_HIGH


def test_ioc_match_upgrades_to_confirmed():
    pb = _pb(signals=[
        _sig("s1", "dns_packet_count", ">= 1", 0.3, attack_category="A"),
        _sig("s2", "http_packet_count", ">= 1", 0.3, attack_category="B"),
        _sig("s3", "smb_packet_count", ">= 1", 0.3, attack_category="A"),
    ])
    result = score(
        pb,
        ProtocolSignals(dns_packet_count=10, http_packet_count=10, smb_packet_count=10),
        ioc_match=True,
    )
    assert result.confidence == CONFIDENCE_CONFIRMED


# ---------------------------------------------------------------------------
# confidence_ceiling enforcement
# ---------------------------------------------------------------------------

def test_confidence_ceiling_caps_confirmed_to_high():
    pb = _pb(
        confidence_ceiling="HIGH",
        signals=[
            _sig("s1", "dns_packet_count", ">= 1", 0.3, attack_category="A"),
            _sig("s2", "http_packet_count", ">= 1", 0.3, attack_category="B"),
            _sig("s3", "smb_packet_count", ">= 1", 0.3, attack_category="A"),
        ],
    )
    result = score(
        pb,
        ProtocolSignals(dns_packet_count=10, http_packet_count=10, smb_packet_count=10),
        ioc_match=True,
    )
    # Without ceiling this would be CONFIRMED; ceiling must cap it at HIGH
    assert result.confidence == CONFIDENCE_HIGH


def test_confidence_ceiling_does_not_upgrade_low():
    """ceiling=HIGH must not upgrade a LOW finding to HIGH."""
    pb = _pb(
        confidence_ceiling="HIGH",
        signals=[_sig("s1", "dns_packet_count", ">= 1", 0.3, attack_category="A")],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=10))
    assert result.confidence == CONFIDENCE_LOW


# ---------------------------------------------------------------------------
# false_positive_notes propagation
# ---------------------------------------------------------------------------

def test_fp_notes_propagated():
    pb = _pb(
        false_positive_notes="Legitimate EDR agents beacon regularly.",
        signals=[_sig("s1", "dns_packet_count", ">= 1", 0.5, attack_category="A")],
    )
    result = score(pb, ProtocolSignals(dns_packet_count=10))
    assert "EDR" in result.fp_notes


def test_fp_notes_empty_when_absent():
    pb = _pb(signals=[_sig("s1", "dns_packet_count", ">= 1", 0.5, attack_category="A")])
    result = score(pb, ProtocolSignals(dns_packet_count=10))
    assert result.fp_notes == ""


# ---------------------------------------------------------------------------
# T1573.001 — JA3 signal integration (uses real playbook YAML)
# ---------------------------------------------------------------------------

import yaml
from pathlib import Path

_T1573_PATH = (
    Path(__file__).resolve().parents[1]
    / "playbooks/c2_and_beaconing/T1573.001_tls_c2.yaml"
)


def _load_t1573() -> dict:
    with open(_T1573_PATH) as f:
        return yaml.safe_load(f)


def test_t1573_ja3_signal_present_in_playbook():
    pb = _load_t1573()
    signal_ids = [s["id"] for s in pb["signals"]]
    assert "diverse_ja3_fingerprints" in signal_ids


def test_t1573_ja3_signal_uses_correct_source():
    pb = _load_t1573()
    sig = next(s for s in pb["signals"] if s["id"] == "diverse_ja3_fingerprints")
    assert sig["source"] == "tls_unique_ja3_count"


def test_t1573_ja3_fires_on_high_ja3_count():
    pb = _load_t1573()
    signals = ProtocolSignals(
        tls_packet_count=600,
        tls_unique_ja3_count=4,   # above threshold of 3
        tls_missing_sni_count=0,
        tls_cert_anomaly_count=0,
    )
    result = score(pb, signals)
    assert result.score > 0.0


def test_t1573_ja3_combo_bonus_fires():
    """cert_anomalies + diverse_ja3_fingerprints should grant +0.10 bonus."""
    pb = _load_t1573()
    # Only cert_anomalies + JA3 — no missing SNI — so only the JA3 combo fires
    signals_with_bonus = ProtocolSignals(
        tls_packet_count=50,
        tls_unique_ja3_count=4,
        tls_cert_anomaly_count=5,
        tls_missing_sni_count=0,
    )
    signals_no_bonus = ProtocolSignals(
        tls_packet_count=50,
        tls_unique_ja3_count=4,
        tls_cert_anomaly_count=0,   # no cert anomaly → no bonus
        tls_missing_sni_count=0,
    )
    with_bonus = score(pb, signals_with_bonus)
    without_bonus = score(pb, signals_no_bonus)
    assert with_bonus.score > without_bonus.score


def test_t1573_ja3_zero_does_not_fire():
    """If JA3 package absent (count=0), signal must not contribute."""
    pb = _load_t1573()
    signals = ProtocolSignals(
        tls_packet_count=600,
        tls_unique_ja3_count=0,
        tls_missing_sni_count=0,
        tls_cert_anomaly_count=0,
    )
    result = score(pb, signals)
    assert result.score == pytest.approx(0.20, abs=0.05)  # only high_tls_volume fires
