"""
Layer 4 — governance gate (AUTOMATED policy, no human in the loop).

The agent fires autonomously, so the gate makes its safety decision **by rule, not
by waiting for a person**. A human review step only scales to a handful of
payloads; the number selected varies and can be large, so a person-in-the-loop
would be a bottleneck that defeats autonomy.

Policy on an authorized, disposable, loopback sandbox:
  * **approve every payload to fire** — the target is self-owned and throwaway;
  * still **flag destructive payloads** in the result (and the audit log) so the
    risk is visible and accountable, even though they are fired;
  * keep two automated knobs for a real (non-sandbox) engagement:
      - `allow_destructive=False` re-imposes an automatic hold on destructive
        payloads (no human needed — the rule decides),
      - `max_per_point` caps per-point volume (a rate limit).

So governance is preserved as *policy-as-code* and transparency, without a manual
review gate.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class GateResult:
    approved: list = field(default_factory=list)   # [(point, payload), ...] -> will fire
    held: list = field(default_factory=list)       # [(point, payload, reason), ...] (only if a knob holds)
    flagged: list = field(default_factory=list)    # [(point, payload), ...] destructive but fired

    def summary(self) -> str:
        s = f"{len(self.approved)} approved to fire (autonomous)"
        if self.flagged:
            s += f"; {len(self.flagged)} destructive flagged"
        if self.held:
            s += f"; {len(self.held)} held by policy"
        return s


def govern(selection, allow_destructive: bool = True, max_per_point: int | None = None) -> GateResult:
    """Apply the automated policy to Layer-3 selection: (point, [payloads]) pairs."""
    result = GateResult()
    for point, payloads in selection:
        fired_here = 0
        for p in payloads:
            if p.get("is_destructive") and not allow_destructive:
                result.held.append((point, p, "destructive — automatic hold (allow_destructive=False)"))
                continue
            if max_per_point is not None and fired_here >= max_per_point:
                result.held.append((point, p, f"automated rate limit (> {max_per_point}/point)"))
                continue
            result.approved.append((point, p))
            if p.get("is_destructive"):
                result.flagged.append((point, p))   # fired, but recorded as risky
            fired_here += 1
    return result
