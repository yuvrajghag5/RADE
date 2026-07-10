"""
Layer 3 — Intelligence / payload selection.

For each injection point found by recon, pick candidate payloads from the labelled
arsenal (data/cleaned/dataset_final.jsonl). The agent NEVER invents payloads — it
only chooses from the dataset.

Selection rule (transparent, per injection point):
  1. keep only attack payloads whose `attack_class` is worth trying here,
  2. prefer payloads whose `context_bucket` matches the injection point,
  3. **stratify by `type`** — group the candidates by technique and take the
     `k_per_type` best from EACH technique, ranked by severity then length.

Step 3 is the fairness fix. The old rule ranked the whole class by severity+length
and took the top-k, so short high-severity blind-time payloads always won every slot
and whole techniques (`union`, `error-based`, `boolean-blind`, `stacked-queries`)
were never selected. Stratifying by technique guarantees every technique present at a
point gets a slot, so a target vulnerable only to (say) union-based SQLi is no longer
reported clean. Any technique still missing after this is a *recon* gap — its bucket is
not exposed by the target profile — not a selection bias.
"""
from __future__ import annotations
import json
from collections import defaultdict

from config.paths import CLEAN

DATASET = CLEAN / "dataset_final.jsonl"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def load_arsenal() -> list[dict]:
    rows = [json.loads(l) for l in DATASET.open(encoding="utf-8")]
    return [r for r in rows if r["label"] == "attack"]


def _rank_key(p: dict):
    """Severity first (critical → high → medium), then shortest payload as tie-break."""
    return (SEVERITY_RANK.get(p["severity"], 9), len(p["payload"]))


def select_for_point(point, arsenal: list[dict], k_per_type: int = 2) -> list[dict]:
    """Stratified selection: for each class, take the k_per_type best of EVERY technique."""
    selected = []
    for cls in point.classes:
        cands = [p for p in arsenal if p["attack_class"] == cls]
        # prefer bucket match; fall back to the whole class if none match
        matched = [p for p in cands if p["context_bucket"] == point.bucket]
        pool = matched if matched else cands

        # group by technique, best-first within each technique
        by_type: dict[str, list[dict]] = defaultdict(list)
        for p in pool:
            by_type[p["type"]].append(p)
        for group in by_type.values():
            group.sort(key=_rank_key)

        # order techniques by their strongest payload so critical techniques lead,
        # then emit round-robin: every technique contributes its best before any
        # technique contributes a second — so no technique is ever skipped.
        ordered = sorted(by_type.values(), key=lambda g: _rank_key(g[0]))
        for rank in range(k_per_type):
            for group in ordered:
                if rank < len(group):
                    selected.append(group[rank])
    return selected


def select_all(points, k_per_type: int = 2) -> list:
    """Return a list of (injection_point, [selected payloads]) pairs."""
    arsenal = load_arsenal()
    return [(pt, select_for_point(pt, arsenal, k_per_type)) for pt in points]
