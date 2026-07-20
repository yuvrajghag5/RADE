"""
Offensive IT-Tester — AGENT driver (all 7 layers, LangGraph-orchestrated).

Builds the LangGraph agent (which orchestrates one tool per layer) and runs it
against a target. It walks authorize → recon → [triage] → select → govern →
execute+detect, branching on a scope rejection or a recon failure, and logs every
step to a tamper-evident ledger. Layer 5 fires the governance-approved payloads
and Layer 6 confirms real exploits with per-technique oracles.

Options:
  --llm     enable the LLM triage node — a local open-source model (HuggingFace)
            reasons over the discovered injection points and re-prioritises them
            (bounded; the governance gate still enforces safety regardless).
  --report  Layer 7 — a local LLM writes the Markdown findings report into reports/.

Usage:
  python main.py http://127.0.0.1:5000                  # deterministic full run
  python main.py http://127.0.0.1:5000 --llm            # + LLM triage decision
  python main.py http://127.0.0.1:5000 --llm --report   # + triage + report
  python main.py http://example.com                     # authorization rejects
"""
from __future__ import annotations
import sys
import time

from config.paths import ROOT
from src.agent import build_agent, AuditLog, HFClient

DEFAULT_TARGET = "http://127.0.0.1:8080"
AUDIT_PATH = ROOT / "audit" / "audit.jsonl"
REPORTS_DIR = ROOT / "reports"
BAR = "=" * 72


def _report(state: dict) -> None:
    print("\n[LAYER 1] AUTHORIZATION")
    if not state.get("authorized"):
        print(f"  ✗ REJECTED — {state.get('reason')}")
        print("\n  Out of scope. Nothing fired. (This is the scope firewall working.)")
        return
    print("  ✓ APPROVED")

    print("\n[LAYER 2] RECONNAISSANCE  (live crawl)")
    if state.get("points") is None:
        print(f"  ✗ RECON FAILED — {state.get('reason')}")
        return
    print(f"  {len(state['points'])} injection points discovered live")

    gate = state.get("gate")
    print("\n[LAYER 3-4] SELECTION → GOVERNANCE GATE  (automated policy — fires autonomously)")
    print(f"  {gate.summary()}")

    print("\n[LAYER 5-6] EXECUTION → DETECTION")
    findings = state.get("findings") or []
    confirmed = [f for f in findings if f["confirmed"] is True]
    print(f"  fired {len(findings)} payloads · {len(confirmed)} CONFIRMED exploit(s):")
    seen = set()
    for f in confirmed:
        key = (f["attack_class"], f["type"], f["point"])
        if key in seen:
            continue
        seen.add(key)
        print(f"    ✓ {f['attack_class']}/{f['type']:14} at {f['point']:10} "
              f"via {f['oracle']:17} [{f['confidence']}] — {f['evidence'][:60]}")
    if not confirmed:
        print("    (none confirmed on this target)")

    print("\n" + BAR)
    by = {}
    for f in confirmed:
        by[f["attack_class"]] = by.get(f["attack_class"], 0) + 1
    print(f"CONFIRMED {len(confirmed)} exploits across {len(state['points'])} injection points — by class: {by}")
    print(BAR)


def run(target_url: str, use_llm: bool = False, make_report: bool = False) -> None:
    print(BAR)
    brain = "LangGraph + LLM triage (HuggingFace)" if use_llm else "LangGraph (deterministic)"
    print(f"OFFENSIVE IT-TESTER (agent)   target = {target_url}   orchestrator = {brain}")
    print(BAR)

    # one HF client shared by the LLM triage node and the Layer-7 report
    llm_client = HFClient() if (use_llm or make_report) else None

    audit = AuditLog(AUDIT_PATH)
    agent = build_agent(audit=audit, llm_client=llm_client if use_llm else None)
    if use_llm:
        print("  (LLM triage enabled — first LLM call loads the local model)")
    state = agent.invoke({"target": target_url})
    _report(state)
    if state.get("plan"):
        print(f"\n[LLM TRIAGE] model-chosen point priority: {', '.join(state['plan'])}")

    ok, msg = AuditLog.verify(AUDIT_PATH)
    print(f"\n[AUDIT] {audit.seq} events logged · chain {('OK — ' + msg) if ok else ('BROKEN — ' + msg)}")
    print(f"        ledger: {AUDIT_PATH}")

    if make_report:
        from src.reporting import generate_report
        print("\n[LAYER 7] REPORT  (LLM-generated, HuggingFace)")
        md = generate_report(state, client=llm_client)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        out = REPORTS_DIR / f"report_{time.strftime('%Y%m%d_%H%M%S')}.md"
        out.write_text(md, encoding="utf-8")
        print(f"  written: {out}")


if __name__ == "__main__":
    args = sys.argv[1:]
    use_llm = "--llm" in args
    make_report = "--report" in args
    positional = [a for a in args if not a.startswith("--")]
    target = positional[0] if positional else DEFAULT_TARGET
    run(target, use_llm=use_llm, make_report=make_report)
