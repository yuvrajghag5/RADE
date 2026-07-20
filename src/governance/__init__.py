"""Layer 4 — governance gate (safety holds + rate limits)."""
from .gate import GateResult, govern

__all__ = ["GateResult", "govern"]
