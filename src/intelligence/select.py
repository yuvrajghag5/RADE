"""
Layer 3 — Intelligence / payload selection.

For each injection point found by recon, pick candidate payloads from the labelled
arsenal (data/cleaned/dataset_final.jsonl). The agent NEVER invents payloads — it
only chooses from the dataset.

Selection rule (transparent, per injection point):
  1. keep only attack payloads whose `attack_class` is worth trying here,
  2. prefer payloads whose `context_bucket` matches the injection point,
  3. rank by severity (critical > high > medium), then by payload length (simplest first),
  4. take up to `k_per_class` per attack class.
"""
from __future__ import annotations
import json

from config.paths import CLEAN

DATASET = CLEAN / "dataset_final.jsonl"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def load_arsenal() -> list[dict]:
    rows = [json.loads(l) for l in DATASET.open(encoding="utf-8")]
    return [r for r in rows if r["label"] == "attack"]


def select_for_point(point, arsenal: list[dict], k_per_class: int = 3) -> list[dict]:
    selected = []
    for cls in point.classes:
        cands = [p for p in arsenal if p["attack_class"] == cls]
        # prefer bucket match; fall back to the whole class if none match
        matched = [p for p in cands if p["context_bucket"] == point.bucket]
        pool = matched if matched else cands
        pool.sort(key=lambda p: (SEVERITY_RANK.get(p["severity"], 9), len(p["payload"])))
        selected.extend(pool[:k_per_class])
    return selected


def select_all(points, k_per_class: int = 3) -> list:
    """Return a list of (injection_point, [selected payloads]) pairs."""
    arsenal = load_arsenal()
    return [(pt, select_for_point(pt, arsenal, k_per_class)) for pt in points]
