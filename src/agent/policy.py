"""
Decision policy — the agent's "brain".

`Policy` is the swappable interface: given the current state, decide the next
action (which tool + args), or return None to stop. This is the seam that keeps
the agent hybrid-ready — `DeterministicPolicy` encodes explicit, auditable rules
today; an `LLMPolicy` implementing the same `decide()` (reading
`registry.list_specs()` and calling the Anthropic tool-use loop) could drop in
later without touching the agent, tools, or audit log.

What makes this an AGENT and not a pipeline: the policy chooses each step from
the observed STATE, and branches — a rejection or a recon failure ends the run;
it does not blindly execute a fixed sequence.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class Action:
    tool: str
    args: dict
    rationale: str = ""     # why the policy chose this (recorded in the audit log)


class Policy:
    def decide(self, state) -> Action | None:
        raise NotImplementedError


class DeterministicPolicy(Policy):
    """Bounded L1 -> L2 -> L3 plan expressed as state-driven decisions."""

    def __init__(self, k_per_type: int = 2):
        self.k_per_type = k_per_type

    def decide(self, state) -> Action | None:
        # 1. Nothing known yet -> establish scope.
        if state.authorized is None:
            return Action("authorize", {"target_url": state.goal},
                          "no decision yet -> check scope before touching the target")

        # 2. Rejected -> stop (the agent must not proceed out of scope).
        if not state.authorized:
            return None

        # 3. Authorized but no injection points -> reconnoitre.
        if state.points is None:
            return Action("recon",
                          {"target_url": state.goal, "profile": state.profile or "dvwa"},
                          "authorized -> discover injection points on the target")

        # 4. Injection points found but no payloads chosen -> select.
        if state.selection is None:
            return Action("select_payloads",
                          {"points": state.points, "k_per_type": self.k_per_type},
                          "injection points known -> select payloads (stratified by technique)")

        # 5. Goal reached (Layers 1-3 complete) -> stop.
        return None


def _eligible_tools(state) -> list[str]:
    """The tools that are a VALID next step given current state.

    Offering the model only these (a) prevents it re-calling a completed step in
    a loop, and (b) enforces the dependency order regardless of what it asks for.
    An empty list means the goal is reached — the agent stops.
    """
    if state.authorized is None:
        return ["authorize"]
    if state.authorized is False:
        return []                       # rejected — nothing more may run
    if state.points is None:
        return ["recon"]
    if state.selection is None:
        return ["select_payloads"]
    return []                           # Layers 1-3 complete


class LLMPolicy(Policy):
    """
    LLM orchestrator (open-source model via Ollama). The model is given the tool
    specs + the agent's current state and chooses the next tool to call. It is
    deliberately **bounded**:

      * it may only pick from the registered tools (scope is still enforced by
        the authorize tool + allowlist, regardless of what the model wants);
      * structured arguments (`points`) are filled by the policy from state, not
        by the model;
      * a choice whose prerequisites are unmet, or any LLM error, **falls back to
        the deterministic policy** — so the agent can never be driven into an
        unsafe or nonsensical step by the model.

    This directly addresses OWASP LLM08 (excessive agency): the LLM decides
    ordering among safe tools, not arbitrary actions.
    """

    SYSTEM = (
        "You are the decision policy of a BOUNDED, authorized web-application "
        "security-testing agent. You may ONLY call the provided tools, and only "
        "in a safe order: call `authorize` first; if it rejects, stop; once "
        "authorized, call `recon`; once injection points exist, call "
        "`select_payloads`. When authorization→recon→selection are all done, "
        "reply with a short sentence and NO tool call to stop. Never invent "
        "tools or arguments. Choose exactly one tool per turn."
    )

    def __init__(self, client, registry, fallback: Policy | None = None):
        self.client = client
        self.registry = registry
        self.fallback = fallback or DeterministicPolicy()

    def _state_brief(self, state, eligible: list[str]) -> str:
        done = "authorized={}, injection_points={}, payloads_selected={}".format(
            state.authorized,
            "not yet" if state.points is None else f"{len(state.points)} found",
            "no" if state.selection is None else "yes",
        )
        return (f"Goal (target URL): {state.goal}\n"
                f"Profile: {state.profile or 'unknown'}\n"
                f"Progress so far: {done}\n"
                f"Valid next tool(s) right now: {', '.join(eligible)}.\n"
                "Call exactly one of them to advance the assessment.")

    def decide(self, state) -> Action | None:
        from .llm import to_ollama_tools, LLMError

        eligible = _eligible_tools(state)
        if not eligible:
            return None   # goal reached (or rejected) -> stop

        # offer ONLY the currently-valid tools, so the model can't loop on a
        # finished step or jump the dependency order
        specs = [s for s in self.registry.list_specs() if s["name"] in eligible]
        messages = [
            {"role": "system", "content": self.SYSTEM},
            {"role": "user", "content": self._state_brief(state, eligible)},
        ]
        try:
            msg = self.client.chat(messages, tools=to_ollama_tools(specs))
        except LLMError:
            return self.fallback.decide(state)   # LLM down -> stay functional

        calls = msg.get("tool_calls") or []
        if not calls:
            return self.fallback.decide(state)   # work remains but model didn't act

        fn = calls[0].get("function", {})
        tool = fn.get("name", "")
        if tool not in eligible:
            return self.fallback.decide(state)   # invalid choice -> guardrail

        # The model picks the tool; the policy supplies safe, concrete arguments.
        rationale = f"LLM ({self.client.cfg.model}) chose {tool}"
        if tool == "authorize":
            return Action("authorize", {"target_url": state.goal}, rationale)
        if tool == "recon":
            return Action("recon",
                          {"target_url": state.goal, "profile": state.profile or "dvwa"},
                          rationale)
        return Action("select_payloads", {"points": state.points, "k_per_type": 2}, rationale)
