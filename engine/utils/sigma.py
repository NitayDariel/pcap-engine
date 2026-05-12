"""
Sigma rule evaluator for Zeek log DataFrames.

Runs SigmaHQ network/zeek rules directly against Zeek JSON logs without a SIEM
backend. Uses pySigma to parse rules, then evaluates conditions via Pandas.

Supported condition modifiers:
  contains, startswith, endswith, re (regex), all (AND across multiple values)
Supported condition expressions:
  selection, selection and not filter, 1 of op*, all of them, A and B, A or B

Results feed into:
  - phase3_ttp_sweep.py  (signal boost, same pattern as Suricata)
  - reporter.py          (Sigma Hits section)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

try:
    from sigma.rule import SigmaRule
    from sigma.modifiers import (
        SigmaContainsModifier,
        SigmaStartswithModifier,
        SigmaEndswithModifier,
        SigmaRegularExpressionModifier,
        SigmaAllModifier,
    )
    _SIGMA_AVAILABLE = True
except ImportError:
    _SIGMA_AVAILABLE = False

from engine.utils.zeek import parse_log


# ---------------------------------------------------------------------------
# Output structures
# ---------------------------------------------------------------------------

@dataclass
class SigmaHit:
    rule_title: str
    rule_id: str
    level: str              # high / medium / low / informational
    techniques: list[str]   # MITRE T-numbers e.g. ['T1003.002']
    tactics: list[str]      # e.g. ['credential_access']
    log_type: str           # Zeek log service name: x509, dns, smb_files, …
    match_count: int
    sample_src_ips: list[str]
    sample_dst_ips: list[str]


@dataclass
class SigmaResult:
    available: bool = True
    hits: list[SigmaHit] = field(default_factory=list)
    rules_evaluated: int = 0
    error: str = ""

    @property
    def techniques(self) -> set[str]:
        return {t for h in self.hits for t in h.techniques}

    @property
    def high_hits(self) -> list[SigmaHit]:
        return [h for h in self.hits if h.level == "high"]

    @property
    def alert_count(self) -> int:
        return sum(h.match_count for h in self.hits)


# ---------------------------------------------------------------------------
# Zeek service name → log file mapping
# ---------------------------------------------------------------------------

_LOG_MAP: dict[str, str] = {
    "x509": "x509.log",
    "ssl": "ssl.log",
    "dns": "dns.log",
    "http": "http.log",
    "smb_files": "smb_files.log",
    "smb_mapping": "smb_mapping.log",
    "dce_rpc": "dce_rpc.log",
    "kerberos": "kerberos.log",
    "conn": "conn.log",
    "ssh": "ssh.log",
    "ftp": "ftp.log",
    "rdp": "rdp.log",
    "ntlm": "ntlm.log",
}


# ---------------------------------------------------------------------------
# Value extraction — strip Sigma wildcard `*` markers per modifier type
# ---------------------------------------------------------------------------

def _sigma_plain(sigma_str, modifiers: list) -> str:
    """Return the searchable plain-text content of a SigmaString."""
    raw = str(sigma_str)
    mod_names = {m.__name__ for m in modifiers}
    if "SigmaContainsModifier" in mod_names:
        return raw.strip("*")
    if "SigmaStartswithModifier" in mod_names:
        return raw.rstrip("*")
    if "SigmaEndswithModifier" in mod_names:
        return raw.lstrip("*")
    # Exact or regex — return as-is (no `*` expected for these)
    return raw.strip("*")


# ---------------------------------------------------------------------------
# Single detection item → Pandas boolean mask
# ---------------------------------------------------------------------------

def _eval_item(df: pd.DataFrame, item) -> pd.Series:
    """Apply one SigmaDetectionItem to df, return boolean mask."""
    # Locate column (case-insensitive fallback)
    col = item.field
    if col not in df.columns:
        lower_map = {c.lower(): c for c in df.columns}
        col = lower_map.get(item.field.lower())
        if col is None:
            return pd.Series([False] * len(df), index=df.index)

    series = df[col].fillna("").astype(str)
    mod_names = {m.__name__ for m in item.modifiers}
    is_all = "SigmaAllModifier" in mod_names  # values combined with AND
    is_re = "SigmaRegularExpressionModifier" in mod_names
    is_contains = "SigmaContainsModifier" in mod_names
    is_startswith = "SigmaStartswithModifier" in mod_names
    is_endswith = "SigmaEndswithModifier" in mod_names

    masks: list[pd.Series] = []
    for v in item.value:
        plain = _sigma_plain(v, item.modifiers)
        if not plain:
            continue
        if is_re:
            try:
                m = series.str.contains(plain, regex=True, case=False, na=False)
            except re.error:
                continue
        elif is_contains:
            m = series.str.contains(re.escape(plain), case=False, na=False)
        elif is_startswith:
            m = series.str.startswith(plain, na=False)
        elif is_endswith:
            m = series.str.endswith(plain, na=False)
        else:
            m = series == plain
        masks.append(m)

    if not masks:
        return pd.Series([False] * len(df), index=df.index)

    # Use value_linking to determine AND vs OR across multiple values
    vlink = item.value_linking
    use_and = is_all or (vlink is not None and "AND" in getattr(vlink, "__name__", ""))

    result = masks[0]
    for m in masks[1:]:
        result = (result & m) if use_and else (result | m)
    return result


# ---------------------------------------------------------------------------
# Named detection group → mask (items within group are AND'd)
# ---------------------------------------------------------------------------

def _eval_group(df: pd.DataFrame, detection) -> pd.Series:
    if df.empty:
        return pd.Series([], dtype=bool)
    result = pd.Series([True] * len(df), index=df.index)
    for item in detection.detection_items:
        result = result & _eval_item(df, item)
    return result


# ---------------------------------------------------------------------------
# Full rule condition evaluator
# ---------------------------------------------------------------------------

def _eval_rule(rule, df: pd.DataFrame) -> pd.Series | None:
    if df.empty:
        return None

    detections = rule.detection.detections
    cond = (rule.detection.condition[0] if rule.detection.condition else "selection").strip()

    # Evaluate all named groups
    groups: dict[str, pd.Series] = {name: _eval_group(df, det) for name, det in detections.items()}

    # Simple single-group reference
    if cond in groups:
        return groups[cond]

    # "1 of <prefix>*" — any group matching prefix
    m = re.match(r"^1 of (\w+)\*$", cond)
    if m:
        prefix = m.group(1)
        matching = [mask for name, mask in groups.items() if name.startswith(prefix)]
        if not matching:
            return None
        result = matching[0]
        for mask in matching[1:]:
            result = result | mask
        return result

    # "all of them"
    if cond == "all of them":
        result = pd.Series([True] * len(df), index=df.index)
        for mask in groups.values():
            result = result & mask
        return result

    # "A and not B"
    m = re.match(r"^(\w+) and not (\w+)$", cond)
    if m:
        pos = groups.get(m.group(1), pd.Series([False] * len(df), index=df.index))
        neg = groups.get(m.group(2), pd.Series([False] * len(df), index=df.index))
        return pos & ~neg

    # "A and B"
    m = re.match(r"^(\w+) and (\w+)$", cond)
    if m:
        a = groups.get(m.group(1), pd.Series([False] * len(df), index=df.index))
        b = groups.get(m.group(2), pd.Series([False] * len(df), index=df.index))
        return a & b

    # "A or B"
    m = re.match(r"^(\w+) or (\w+)$", cond)
    if m:
        a = groups.get(m.group(1), pd.Series([False] * len(df), index=df.index))
        b = groups.get(m.group(2), pd.Series([False] * len(df), index=df.index))
        return a | b

    # Fallback: try first group
    first = next(iter(groups.values()), None)
    return first


# ---------------------------------------------------------------------------
# MITRE tag extraction
# ---------------------------------------------------------------------------

def _parse_tags(tags) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for tag in tags:
        s = str(tag).lower()
        if re.match(r"attack\.t\d", s):
            # Normalise to T1234 or T1234.001
            raw = s[len("attack."):]
            techniques.append(raw.upper())
        elif s.startswith("attack.") and not s.startswith("attack.s"):
            tactics.append(s[len("attack."):].replace("-", "_"))
    return techniques, tactics


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(zeek_log_dir: str, rules_dir: str | None = None) -> SigmaResult:
    """
    Evaluate Sigma network/zeek rules against Zeek logs.

    Args:
        zeek_log_dir: Directory containing Zeek JSON log files.
        rules_dir: Override path to *.yml sigma rules. If None, uses
                   <project_root>/sigma/rules/network/zeek/.

    Returns:
        SigmaResult with all matched rules.
    """
    if not _SIGMA_AVAILABLE:
        return SigmaResult(
            available=False,
            error="pySigma not installed — run: pip3 install sigma-cli",
        )

    result = SigmaResult()
    log_dir = Path(zeek_log_dir)

    if rules_dir is None:
        # Relative to this file: engine/utils/sigma.py → ../../../sigma/rules/network/zeek
        rules_path = Path(__file__).parent.parent.parent / "sigma" / "rules" / "network" / "zeek"
    else:
        rules_path = Path(rules_dir)

    if not rules_path.exists():
        return SigmaResult(available=False, error=f"Sigma rules dir not found: {rules_path}")

    rule_files = sorted(rules_path.glob("*.yml")) + sorted(rules_path.glob("*.yaml"))
    if not rule_files:
        return SigmaResult(available=False, error=f"No .yml rules found in {rules_path}")

    # Lazy-load Zeek logs — only parse each log file once
    _log_cache: dict[str, pd.DataFrame] = {}

    def _load(service: str) -> pd.DataFrame:
        if service not in _log_cache:
            fname = _LOG_MAP.get(service, "")
            _log_cache[service] = parse_log(str(log_dir / fname)) if fname else pd.DataFrame()
        return _log_cache[service]

    for rule_file in rule_files:
        try:
            rule = SigmaRule.from_yaml(rule_file.read_text())
        except Exception:
            continue

        result.rules_evaluated += 1
        service = rule.logsource.service or ""
        df = _load(service)

        try:
            mask = _eval_rule(rule, df)
        except Exception:
            continue

        if mask is None or df.empty or not mask.any():
            continue

        matched = df[mask]
        techniques, tactics = _parse_tags(rule.tags)

        src_ips: list[str] = []
        for col in ("id.orig_h", "src", "c-ip"):
            if col in matched.columns:
                src_ips = [str(x) for x in matched[col].dropna().unique()[:5]]
                break

        dst_ips: list[str] = []
        for col in ("id.resp_h", "dst", "s-ip"):
            if col in matched.columns:
                dst_ips = [str(x) for x in matched[col].dropna().unique()[:5]]
                break

        level_raw = str(rule.level).lower()
        # pySigma may return "sigmaleveneum.high" — normalise
        for lvl in ("high", "medium", "low", "informational", "critical"):
            if lvl in level_raw:
                level_raw = lvl
                break

        result.hits.append(SigmaHit(
            rule_title=rule.title,
            rule_id=str(rule.id),
            level=level_raw,
            techniques=techniques,
            tactics=tactics,
            log_type=service,
            match_count=int(mask.sum()),
            sample_src_ips=src_ips,
            sample_dst_ips=dst_ips,
        ))

    return result
