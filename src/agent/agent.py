"""
The agent: working memory + a perceive -> decide -> act loop.

The Agent owns no domain logic. Each step it asks the POLICY what to do next
given the current STATE, invokes the chosen TOOL through the registry, folds the
result back into state (perceive), and records both in the AUDIT log. It stops
when the policy returns no action, when a step aborts the run (scope rejection or
recon failure), or when the step budget is exhausted.

Swapping `DeterministicPolicy` for an `LLMPolicy` changes the "decide" step only;
the loop, tools, memory, and audit trail are unchanged.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from .tools import ToolRegistry
from .policy import Policy, Action


@dataclass
class AgentState:
    goal: str                        # the target URL the agent is working on
    profile: str | None = None       # crawl profile (learned from authorization)
    authorized: bool | None = None   # None = not yet checked
    points: list | None = None       # injection points (None = recon not done)
    selection: list | None = None    # (point, payloads) pairs (None = not selected)
    status: str = "running"          # running | done | aborted
    abort_reason: str = ""
    steps: int = 0
    trace: list = field(default_factory=list)  # (Action, ToolResult) per step


class Agent:
    def __init__(self, registry: ToolRegistry, policy: Policy,
                 audit=None, max_steps: int = 12):
        self.registry = registry
        self.policy = policy
        self.audit = audit
        self.max_steps = max_steps

    def _log(self, event: str, data: dict) -> None:
        if self.audit is not None:
            self.audit.record(event, data)

    def run(self, goal: str) -> AgentState:
        state = AgentState(goal=goal)
        self._log("run_start", {"goal": goal, "tools": self.registry.names()})

        while state.status == "running" and state.steps < self.max_steps:
            action = self.policy.decide(state)          # DECIDE
            if action is None:
                state.status = "done"
                break

            result = self.registry.invoke(action.tool, action.args)  # ACT
            state.steps += 1
            state.trace.append((action, result))
            self._log("action", {
                "step": state.steps,
                "tool": action.tool,
                "rationale": action.rationale,
                "ok": result.ok,
                "summary": result.summary or result.error,
            })

            self._perceive(state, action, result)       # PERCEIVE

        if state.status == "running":                    # ran out of budget
            state.status = "aborted"
            state.abort_reason = f"step budget ({self.max_steps}) exhausted"

        self._log("run_end", {
            "status": state.status,
            "steps": state.steps,
            "abort_reason": state.abort_reason,
        })
        return state

    def _perceive(self, state: AgentState, action: Action, result) -> None:
        """Fold a tool result back into working memory, branching on outcomes."""
        if action.tool == "authorize":
            decision = result.output
            state.authorized = decision.approved
            state.profile = decision.profile or state.profile
            if not decision.approved:
                state.status = "aborted"
                state.abort_reason = decision.reason

        elif action.tool == "recon":
            if not result.ok:
                state.status = "aborted"
                state.abort_reason = result.error
            else:
                state.points = result.output

        elif action.tool == "select_payloads":
            state.selection = result.output
