"""
TTP Scorer.
Evaluates a single playbook YAML against pre-computed ProtocolSignals.
Returns a TTPScore with: score, signals_fired, categories_hit, confidence level.

Tiered thresholds:
  Each signal may define a secondary weak tier via 'threshold_low' + 'weight_low'.
  Strong fire  → signal_id added to signals_fired, full weight applied.
  Weak fire    → signal_id + "_weak" added to signals_fired, weight_low applied.
  Combination bonuses compare against base IDs (ignoring _weak suffix) so a weak
  signal still participates in bonus logic, just at reduced individual weight.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from engine.phase2_protocol import ProtocolSignals

CONFIDENCE_CONFIRMED = "CONFIRMED"
CONFIDENCE_HIGH = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW = "LOW"
CONFIDENCE_ANOMALY = "ANOMALY"

# Ranking used to enforce confidence_ceiling: lower rank = higher confidence.
_CONFIDENCE_RANK: dict[str, int] = {
    CONFIDENCE_CONFIRMED: 0,
    CONFIDENCE_HIGH: 1,
    CONFIDENCE_MEDIUM: 2,
    CONFIDENCE_LOW: 3,
    CONFIDENCE_ANOMALY: 4,
}


@dataclass
class TTPScore:
    ttp_id: str
    name: str
    category: str
    mitre_tactic: str
    score: float
    signals_fired: list[str] = field(default_factory=list)
    categories_hit: set[str] = field(default_factory=set)
    confidence: str = CONFIDENCE_ANOMALY
    skipped: bool = False
    skip_reason: str = ""
    raw_values: dict[str, Any] = field(default_factory=dict)
    fp_notes: str = ""


def _eval_threshold(value: Any, threshold_str: str) -> bool:
    """
    Evaluate 'value op rhs' where threshold_str is like '>= 30', '< 0.5', '== True'.
    Returns True if the value meets the threshold.
    """
    threshold_str = threshold_str.strip()
    m = re.match(r"([<>]=?|==|!=)\s*(.+)", threshold_str)
    if not m:
        return False
    op = m.group(1)
    rhs_raw = m.group(2).strip()

    try:
        rhs: Any = float(rhs_raw)
    except ValueError:
        if rhs_raw in ("True", "true"):
            rhs = True
        elif rhs_raw in ("False", "false"):
            rhs = False
        else:
            return False

    try:
        if isinstance(rhs, bool):
            cmp_val: Any = bool(value)
        else:
            cmp_val = float(value)
    except (TypeError, ValueError):
        return False

    ops = {
        ">=": lambda a, b: a >= b,
        "<=": lambda a, b: a <= b,
        ">":  lambda a, b: a > b,
        "<":  lambda a, b: a < b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }
    fn = ops.get(op)
    return fn(cmp_val, rhs) if fn else False


def _confidence(signals_fired: list, categories_hit: set, ioc_match: bool = False) -> str:
    """Determine confidence level per Ground Truth document §3.4."""
    n = len(signals_fired)
    c = len(categories_hit)

    if n >= 3 and c >= 2 and ioc_match:
        return CONFIDENCE_CONFIRMED
    if n >= 3 and c >= 2:
        return CONFIDENCE_HIGH
    if n >= 2 and c >= 1:
        return CONFIDENCE_MEDIUM
    if n >= 1:
        return CONFIDENCE_LOW
    return CONFIDENCE_ANOMALY


def _check_minimum_presence(playbook: dict, signals: ProtocolSignals) -> tuple[bool, str]:
    """Check if minimum presence gates are met. Returns (passes, reason_if_not)."""
    gates = playbook.get("minimum_presence", {})
    for field_name, minimum in gates.items():
        actual = getattr(signals, field_name, 0)
        if actual < minimum:
            return False, f"{field_name}={actual} < required {minimum}"
    return True, ""


def _base_id(signal_id: str) -> str:
    """Strip _weak suffix for bonus matching."""
    return signal_id[:-5] if signal_id.endswith("_weak") else signal_id


def score(playbook: dict, signals: ProtocolSignals, ioc_match: bool = False) -> TTPScore:
    """
    Score a single TTP playbook against pre-computed ProtocolSignals.

    Tiered threshold logic per signal:
      - Meets 'threshold'     → strong fire: full 'weight', appends sig_id
      - Meets 'threshold_low' → weak fire:   'weight_low', appends sig_id + '_weak'
      - Meets neither         → no contribution
    Combination bonuses match on base IDs (ignoring _weak) so weak signals still
    participate in bonus computation.
    """
    ttp_id = playbook.get("ttp_id", "UNKNOWN")
    name = playbook.get("name", "")
    category = playbook.get("category", "")
    mitre_tactic = playbook.get("mitre_tactic", "")

    result = TTPScore(
        ttp_id=ttp_id,
        name=name,
        category=category,
        mitre_tactic=mitre_tactic,
        score=0.0,
    )

    passes, reason = _check_minimum_presence(playbook, signals)
    if not passes:
        result.skipped = True
        result.skip_reason = reason
        return result

    raw_score = 0.0
    signals_fired: list[str] = []
    categories_hit: set[str] = set()
    raw_values: dict[str, Any] = {}

    for sig in playbook.get("signals", []):
        sig_id = sig.get("id", "")
        source = sig.get("source", "")
        threshold_str = sig.get("threshold", "")
        weight = float(sig.get("weight", 0.0))
        attack_cat = sig.get("attack_category", "")

        # Optional weak tier
        threshold_low = sig.get("threshold_low", "")
        weight_low = float(sig.get("weight_low", 0.0))

        if not source or not threshold_str:
            continue

        value = getattr(signals, source, None)
        if value is None:
            continue

        raw_values[sig_id] = value

        if _eval_threshold(value, threshold_str):
            # Strong fire
            raw_score += weight
            signals_fired.append(sig_id)
            if attack_cat:
                categories_hit.add(attack_cat)
        elif threshold_low and weight_low > 0 and _eval_threshold(value, threshold_low):
            # Weak fire — real evidence, softer confidence contribution
            raw_score += weight_low
            signals_fired.append(sig_id + "_weak")
            if attack_cat:
                categories_hit.add(attack_cat)

    # Combination bonuses — compare base IDs so weak signals still qualify
    fired_base = {_base_id(s) for s in signals_fired}
    for bonus_rule in playbook.get("combination_bonuses", []):
        required = set(bonus_rule.get("signals", []))
        bonus = float(bonus_rule.get("bonus", 0.0))
        if required.issubset(fired_base):
            raw_score += bonus

    result.score = round(min(raw_score, 1.0), 4)
    result.signals_fired = signals_fired
    result.categories_hit = categories_hit
    result.confidence = _confidence(signals_fired, categories_hit, ioc_match)
    result.raw_values = raw_values

    # Enforce confidence_ceiling: playbook authors can cap the maximum confidence
    # their technique can achieve (e.g. "this signal is never CONFIRMED without host telemetry").
    ceiling = playbook.get("confidence_ceiling")
    if ceiling and ceiling in _CONFIDENCE_RANK:
        if _CONFIDENCE_RANK.get(result.confidence, 99) < _CONFIDENCE_RANK[ceiling]:
            result.confidence = ceiling

    # Carry false-positive guidance into the score object so the reporter can surface it.
    result.fp_notes = str(playbook.get("false_positive_notes", "")).strip()

    return result
