"""Layer 5 — execution (fire payloads, capture responses)."""
from .execute import FireResult, fire, baseline, BENIGN_VALUE

__all__ = ["FireResult", "fire", "baseline", "BENIGN_VALUE"]
