"""
Tests for singleton suspicious domain detection:
- _is_suspicious_singleton() heuristic
- dns_singleton_suspicious_count signal in _dns_signals()
- Anomaly 6 (singleton_suspicious_domains) in phase7_anomaly.run()
"""

from __future__ import annotations

import pandas as pd
import pytest

from engine.phase2_protocol import _is_suspicious_singleton, _dns_signals
from engine.phase7_anomaly import run as anomaly_run, Anomaly
from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.scorer import TTPScore


# ---------------------------------------------------------------------------
# _is_suspicious_singleton — unit tests
# ---------------------------------------------------------------------------

class TestIsSuspiciousSingleton:
    def test_high_risk_tld_su(self):
        assert _is_suspicious_singleton("whitepepper.su") is True

    def test_high_risk_tld_cyou(self):
        assert _is_suspicious_singleton("whooptm.cyou") is True

    def test_high_risk_tld_xyz(self):
        assert _is_suspicious_singleton("randomstuff.xyz") is True

    def test_delivery_keyword_crack(self):
        assert _is_suspicious_singleton("classiccrack.com") is True

    def test_delivery_keyword_netsupport(self):
        assert _is_suspicious_singleton("netsupportsoftware.com") is True

    def test_delivery_keyword_modapk(self):
        assert _is_suspicious_singleton("modandcrackedapk.com") is True

    def test_high_entropy_apex(self):
        # "qxzjvwfbkpmn" — 12 unique chars → H = log2(12) ≈ 3.58 > 3.5 threshold
        assert _is_suspicious_singleton("qxzjvwfbkpmn.net") is True

    def test_benign_google(self):
        assert _is_suspicious_singleton("google.com") is False

    def test_benign_microsoft(self):
        assert _is_suspicious_singleton("microsoft.com") is False

    def test_benign_apple(self):
        assert _is_suspicious_singleton("apple.com") is False

    def test_mdns_excluded(self):
        assert _is_suspicious_singleton("somehost.local") is False

    def test_arpa_excluded(self):
        assert _is_suspicious_singleton("1.168.192.in-addr.arpa") is False

    def test_srv_record_excluded(self):
        assert _is_suspicious_singleton("_ldap._tcp.domain.com") is False

    def test_empty_string(self):
        assert _is_suspicious_singleton("") is False

    def test_none_like_value(self):
        assert _is_suspicious_singleton(None) is False  # type: ignore

    def test_short_benign_domain_low_entropy(self):
        # "abc" has entropy ~1.58 — not random-looking enough
        assert _is_suspicious_singleton("abc.com") is False

    def test_keyword_embedded_in_domain(self):
        # "crackedapps" contains "crack"
        assert _is_suspicious_singleton("crackedapps.net") is True


# ---------------------------------------------------------------------------
# _dns_signals — singleton computation
# ---------------------------------------------------------------------------

def _make_dns_df(queries: list[str]) -> pd.DataFrame:
    return pd.DataFrame({"query": queries, "qtype_name": ["A"] * len(queries)})


class TestDnsSignalsSingletons:
    def test_singleton_suspicious_counted(self):
        df = _make_dns_df([
            "google.com",
            "google.com",       # queried twice → not singleton
            "netsupportsoftware.com",   # queried once, suspicious keyword
        ])
        out = _dns_signals(df, packet_count=3)
        assert out["dns_singleton_suspicious_count"] == 1
        assert "netsupportsoftware.com" in out["dns_singleton_suspicious_domains"]

    def test_repeated_suspicious_domain_excluded(self):
        df = _make_dns_df([
            "whooptm.cyou",
            "whooptm.cyou",     # queried twice → not singleton, not counted
        ])
        out = _dns_signals(df, packet_count=2)
        assert out["dns_singleton_suspicious_count"] == 0

    def test_benign_singleton_not_counted(self):
        df = _make_dns_df(["maps.google.com"])  # queried once but benign
        out = _dns_signals(df, packet_count=1)
        assert out["dns_singleton_suspicious_count"] == 0

    def test_multiple_suspicious_singletons(self):
        df = _make_dns_df([
            "whitepepper.su",
            "qxzjvwfbkpmn.net",   # high-entropy apex: H = log2(12) ≈ 3.58
            "modandcrackedapk.com",
            "microsoft.com",
            "microsoft.com",
        ])
        out = _dns_signals(df, packet_count=5)
        assert out["dns_singleton_suspicious_count"] == 3

    def test_empty_dataframe(self):
        out = _dns_signals(pd.DataFrame(), packet_count=0)
        assert out.get("dns_singleton_suspicious_count", 0) == 0

    def test_singleton_list_contents(self):
        df = _make_dns_df(["loader.su", "safe.com", "safe.com"])
        out = _dns_signals(df, packet_count=3)
        assert "loader.su" in out["dns_singleton_suspicious_domains"]
        assert "safe.com" not in out["dns_singleton_suspicious_domains"]


# ---------------------------------------------------------------------------
# phase7_anomaly.run() — Anomaly 6 integration
# ---------------------------------------------------------------------------

def _make_ctx() -> AnalysisContext:
    ctx = AnalysisContext.__new__(AnalysisContext)
    ctx.total_packets = 1000
    ctx.total_flows = 50
    ctx.capture_duration_secs = 300.0
    ctx.internal_ips = {"10.0.0.1"}
    ctx.all_ips = {"10.0.0.1", "8.8.8.8"}
    ctx.visibility_pct = 80
    ctx.capture_start = "2024-01-01T00:00:00"
    return ctx


def _make_signals(**kwargs) -> ProtocolSignals:
    s = ProtocolSignals()
    for k, v in kwargs.items():
        setattr(s, k, v)
    return s


class TestAnomaly6SingletonDomains:
    def test_anomaly_fires_on_suspicious_singletons(self):
        signals = _make_signals(
            dns_singleton_suspicious_count=2,
            dns_singleton_suspicious_domains=["whitepepper.su", "xqjzmvfp.net"],
        )
        anomalies = anomaly_run(_make_ctx(), signals, [])
        types = [a.anomaly_type for a in anomalies]
        assert "singleton_suspicious_domains" in types

    def test_anomaly_not_fired_when_zero(self):
        signals = _make_signals(dns_singleton_suspicious_count=0)
        anomalies = anomaly_run(_make_ctx(), signals, [])
        types = [a.anomaly_type for a in anomalies]
        assert "singleton_suspicious_domains" not in types

    def test_anomaly_description_contains_domains(self):
        signals = _make_signals(
            dns_singleton_suspicious_count=1,
            dns_singleton_suspicious_domains=["whooptm.cyou"],
        )
        anomalies = anomaly_run(_make_ctx(), signals, [])
        a = next(x for x in anomalies if x.anomaly_type == "singleton_suspicious_domains")
        assert "whooptm.cyou" in a.description

    def test_anomaly_has_ai_prompt_populated(self):
        signals = _make_signals(
            dns_singleton_suspicious_count=1,
            dns_singleton_suspicious_domains=["loader.su"],
        )
        anomalies = anomaly_run(_make_ctx(), signals, [])
        a = next(x for x in anomalies if x.anomaly_type == "singleton_suspicious_domains")
        assert a.ai_prompt != ""

    def test_anomaly_raw_signals_include_domain_list(self):
        signals = _make_signals(
            dns_singleton_suspicious_count=1,
            dns_singleton_suspicious_domains=["cracked.xyz"],
        )
        anomalies = anomaly_run(_make_ctx(), signals, [])
        a = next(x for x in anomalies if x.anomaly_type == "singleton_suspicious_domains")
        assert "cracked.xyz" in a.raw_signals.get("domains", [])
