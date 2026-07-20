"""
Agent orchestration — a LangGraph state machine over the seven layers.

The graph is the orchestrator; the **tools** (src/agent/layer_tools.py) are the
capabilities. Each node invokes ONE registered tool by name — the graph never
inlines domain logic. The graph **branches** on state (a scope rejection or a
recon failure routes straight to the end) and **gates** (governance holds
destructive payloads before execution). Working memory is `RunState`; every node
appends to the tamper-evident audit ledger.

Agency, not a pipeline:
  * tools are first-class (invoked via the registry, with machine-readable specs);
  * the flow branches on what the agent observes;
  * an optional **LLM triage node** (HuggingFace, opt-in) lets the model reason
    over the discovered injection points and re-prioritise them — a real, bounded
    decision (the governance gate still enforces safety regardless).
"""
from __future__ import annotations
import json
from typing import Optional, TypedDict

from langgraph.graph import StateGraph, START, END

from .layer_tools import build_registry


class RunState(TypedDict, total=False):
    target: str
    profile: Optional[str]
    authorized: Optional[bool]
    reason: str
    points: Optional[list]
    selection: Optional[list]
    gate: object
    findings: list
    plan: list          # the LLM triage ordering (when --llm)
    status: str


def _llm_triage(client, points) -> Optional[list]:
    """Ask the local LLM to rank the injection points by exploitation risk."""
    catalog = [{"name": p.name, "method": p.method, "param": p.param,
                "bucket": p.bucket, "classes": p.classes} for p in points]
    prompt = ("You are the PLANNING step of a bounded, authorized web-application security "
              "agent. Given these candidate injection points, return ONLY a JSON array of "
              "their `name` values ordered from highest to lowest exploitation risk (most "
              "promising first). Every name must appear exactly once, no extra text.\n"
              + json.dumps(catalog))
    try:
        out = client.generate(prompt)
        s, e = out.find("["), out.rfind("]")
        if s >= 0 and e > s:
            return [str(n) for n in json.loads(out[s:e + 1])]
    except Exception:
        return None
    return None


def build_agent(audit=None, registry=None, llm_client=None,
                k_per_type: int = 2, max_per_point: int | None = None):
    """Compile the LangGraph agent. `llm_client` (HFClient) enables LLM triage.
    `max_per_point=None` fires every selected payload (no rate cap)."""
    registry = registry or build_registry()

    def log(event, data):
        if audit is not None:
            audit.record(event, data)

    # ---- one node per layer; each invokes a registered TOOL ----
    def authorize_node(state: RunState) -> dict:
        r = registry.invoke("authorize", {"target_url": state["target"]})
        d = r.output
        log("authorize", {"tool": "authorize", "approved": d.approved, "reason": d.reason})
        return {"authorized": d.approved, "reason": d.reason,
                "profile": d.profile or state.get("profile"),
                "status": "authorized" if d.approved else "rejected"}

    def recon_node(state: RunState) -> dict:
        r = registry.invoke("recon", {"target_url": state["target"],
                                       "profile": state.get("profile") or "dvwa"})
        if not r.ok:
            log("recon", {"tool": "recon", "ok": False, "reason": r.error})
            return {"points": None, "status": "recon_failed", "reason": r.error}
        log("recon", {"tool": "recon", "ok": True, "points": len(r.output)})
        return {"points": r.output}

    def triage_node(state: RunState) -> dict:
        # optional LLM decision — reorder points by assessed risk (bounded/advisory).
        if llm_client is None:
            return {}
        pts = state["points"]
        order = _llm_triage(llm_client, pts)
        if not order:
            log("triage", {"tool": "llm_triage", "result": "parse_failed — kept original order"})
            return {}
        by_name = {p.name: p for p in pts}
        reordered = [by_name[n] for n in order if n in by_name]
        reordered += [p for p in pts if p not in reordered]   # never drop a point
        log("triage", {"tool": "llm_triage", "order": [p.name for p in reordered]})
        return {"points": reordered, "plan": [p.name for p in reordered]}

    def select_node(state: RunState) -> dict:
        r = registry.invoke("select_payloads", {"points": state["points"], "k_per_type": k_per_type})
        log("select", {"tool": "select_payloads", "summary": r.summary})
        return {"selection": r.output}

    def govern_node(state: RunState) -> dict:
        r = registry.invoke("govern", {"selection": state["selection"],
                                       "max_per_point": max_per_point})
        gate = r.output
        log("govern", {"tool": "govern", "summary": r.summary,
                       "flagged_destructive": len(gate.flagged)})
        return {"gate": gate}

    def execute_detect_node(state: RunState) -> dict:
        r = registry.invoke("execute_detect",
                            {"target_url": state["target"],
                             "profile": state.get("profile") or "dvwa",
                             "approved": state["gate"].approved})
        confirmed = sum(1 for f in r.output if f["confirmed"] is True)
        log("execute_detect", {"tool": "execute_detect", "fired": len(r.output), "confirmed": confirmed})
        return {"findings": r.output, "status": "done"}

    # ---- routing (the branches that make it an agent, not a pipeline) ----
    def after_authorize(state: RunState) -> str:
        return "recon" if state.get("authorized") else END

    def after_recon(state: RunState) -> str:
        return "triage" if state.get("points") is not None else END

    g = StateGraph(RunState)
    g.add_node("authorize", authorize_node)
    g.add_node("recon", recon_node)
    g.add_node("triage", triage_node)
    g.add_node("select", select_node)
    g.add_node("govern", govern_node)
    g.add_node("execute_detect", execute_detect_node)

    g.add_edge(START, "authorize")
    g.add_conditional_edges("authorize", after_authorize, {"recon": "recon", END: END})
    g.add_conditional_edges("recon", after_recon, {"triage": "triage", END: END})
    g.add_edge("triage", "select")
    g.add_edge("select", "govern")
    g.add_edge("govern", "execute_detect")
    g.add_edge("execute_detect", END)
    return g.compile()
