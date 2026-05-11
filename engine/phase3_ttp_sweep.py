"""
Phase 3 — Parallel TTP Sweep.
Loads all playbooks, checks minimum presence, scores in parallel via ThreadPoolExecutor.
Returns results ranked by score descending — all scores above report_threshold.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

import yaml

from engine.phase1_orientation import AnalysisContext
from engine.phase2_protocol import ProtocolSignals
from engine.scorer import TTPScore, score as score_ttp

REPORT_THRESHOLD = 0.35   # minimum score to include in output
DEEP_DIVE_THRESHOLD = 0.60  # minimum score to trigger Phase 4 deep dive


def load_playbooks(playbook_dir: str) -> list[dict]:
    """Load all YAML playbooks from directory tree. Returns list of playbook dicts."""
    playbooks = []
    for path in sorted(Path(playbook_dir).rglob("*.yaml")):
        try:
            with open(path) as f:
                pb = yaml.safe_load(f)
            if pb and "ttp_id" in pb:
                pb["_path"] = str(path)
                playbooks.append(pb)
        except Exception as e:
            print(f"  [WARN] Failed to load playbook {path}: {e}")
    return playbooks


def _score_one(pb: dict, signals: ProtocolSignals) -> TTPScore:
    """Worker function: score a single playbook. Called in thread pool."""
    return score_ttp(pb, signals)


def run(
    ctx: AnalysisContext,
    signals: ProtocolSignals,
    playbook_dir: Optional[str] = None,
    max_workers: int = 8,
    report_threshold: float = REPORT_THRESHOLD,
    suricata_result=None,  # Optional[SuricataResult] — avoids circular import
) -> list[TTPScore]:
    """
    Sweep all playbooks in parallel. Returns TTPScore list sorted by score descending.
    Only includes scores >= report_threshold.
    """
    if playbook_dir is None:
        here = Path(__file__).resolve()
        playbook_dir = str(here.parents[1] / "playbooks")

    playbooks = load_playbooks(playbook_dir)
    if not playbooks:
        print(f"  [WARN] No playbooks found in {playbook_dir}")
        return []

    print(f"  [Phase 3] Loaded {len(playbooks)} playbooks — starting parallel sweep...")
    t0 = time.time()

    results: list[TTPScore] = []
    skipped = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_score_one, pb, signals): pb["ttp_id"]
            for pb in playbooks
        }

        for future in as_completed(futures):
            ttp_id = futures[future]
            try:
                result = future.result()
                if result.skipped:
                    skipped += 1
                elif result.score >= report_threshold:
                    results.append(result)
            except Exception as e:
                print(f"  [WARN] {ttp_id} scoring raised: {e}")

    # Apply Suricata signature confirmation boost
    if suricata_result and suricata_result.available and suricata_result.alerts:
        confirmed_techniques = {
            a.mitre_technique for a in suricata_result.alerts if a.mitre_technique
        }
        # Map base TTP IDs (T1046) and sub-technique IDs (T1046.001) to confirmed set
        for result in results:
            base = result.ttp_id.split(".")[0]
            if result.ttp_id in confirmed_techniques or base in confirmed_techniques:
                if result.confidence != "HIGH":
                    result.confidence = "HIGH"
                    result.signals_fired.append("suricata_signature_confirmed")
                result.score = min(1.0, result.score + 0.10)

    elapsed = time.time() - t0
    above_deep_dive = [r for r in results if r.score >= DEEP_DIVE_THRESHOLD]

    print(
        f"  [Phase 3] Done in {elapsed:.1f}s — "
        f"{len(results)} findings (≥{report_threshold}), "
        f"{len(above_deep_dive)} deep-dive candidates (≥{DEEP_DIVE_THRESHOLD}), "
        f"{skipped} skipped (presence gate)"
    )

    return sorted(results, key=lambda r: r.score, reverse=True)
