"""
Offensive IT-Tester — AGENT driver (Layers 1-3, + optional LLM).

Builds the tool registry (authorize, recon, select_payloads), gives it to an
Agent, and runs it against a target. The agent decides each step from its own
state and stops on a scope rejection or a recon failure — it is not a fixed
pipeline. Every decision is written to a tamper-evident audit ledger.

The "brain" is swappable:
  * default — DeterministicPolicy (reproducible, safe).
  * --llm   — LLMPolicy: an open-source model (qwen2.5:7b via Ollama) chooses the
              next tool, bounded (scope still enforced; falls back to the
              deterministic policy on any error/invalid choice).
And Layer 7:
  * --report — generate an LLM run report (Markdown) into reports/.

The agent stops after selection (Layers 4-6 — governance, execution, detection —
are not built): no attack payload is fired.

Usage:
  python main.py                         # deterministic, DVWA :8080
  python main.py http://127.0.0.1:5000   # self-owned Flask sandbox
  python main.py http://127.0.0.1:5000 --llm --report   # LLM orchestrator + report
  python main.py http://example.com      # authorization rejects (out of scope)
"""
from __future__ import annotations
import sys
import time
from collections import Counter

from config.paths import ROOT
from src.agent import (Agent, DeterministicPolicy, LLMPolicy, build_registry,
                       AuditLog, OllamaClient)

DEFAULT_TARGET = "http://127.0.0.1:8080"
AUDIT_PATH = ROOT / "audit" / "audit.jsonl"
REPORTS_DIR = ROOT / "reports"
BAR = "=" * 72


def _report(state) -> None:
    """Pretty-print what the agent discovered and selected."""
    # authorization
    print("\n[LAYER 1] AUTHORIZATION")
    if state.authorized is False:
        print(f"  ✗ REJECTED — {state.abort_reason}")
        print("\n  Out of scope. Nothing fired. (This is the scope firewall working.)")
        return
    print("  ✓ APPROVED")

    # reconnaissance
    print("\n[LAYER 2] RECONNAISSANCE  (live crawl)")
    if state.points is None:
        print(f"  ✗ RECON FAILED — {state.abort_reason}")
        print("\n  Live recon could not run. (Start the sandbox and retry.)")
        return
    print(f"  {len(state.points)} injection points discovered live:")
    for pt in state.points:
        print(f"    - {pt.name:14} {pt.short():52} try={','.join(pt.classes)}")

    # selection
    print("\n[LAYER 3] PAYLOAD SELECTION")
    if state.selection is None:
        print("  (not reached)")
        return

    total = 0
    class_counter = Counter()
    techniques_by_class: dict[str, set] = {}
    for pt, payloads in state.selection:
        print(f"\n  ▶ {pt.name}  ({pt.method} {pt.param}, bucket={pt.bucket})"
              f"  → {len(payloads)} payloads")
        for p in payloads:
            total += 1
            class_counter[p["attack_class"]] += 1
            techniques_by_class.setdefault(p["attack_class"], set()).add(p["type"])
            flag = "  ⚠ DESTRUCTIVE" if p["is_destructive"] else ""
            print(f"      [{p['id']:9}] {p['attack_class']:4}/{p['type']:16} "
                  f"{p['severity']:8} oracle={p['oracle']:17} {p['payload'][:42]!r}{flag}")

    print("\n" + BAR)
    print(f"SELECTED {total} payloads across {len(state.points)} injection points")
    print(f"  by class: {dict(class_counter)}")
    print("  technique coverage (stratified by type):")
    for cls in sorted(techniques_by_class):
        print(f"      {cls:5} → {', '.join(sorted(techniques_by_class[cls]))}")
    print("  next layers (not built): governance gate -> fire -> oracle validation")
    print(BAR)


def run(target_url: str, use_llm: bool = False, make_report: bool = False,
        k_per_type: int = 2) -> None:
    print(BAR)
    brain = "LLM (qwen2.5:7b via Ollama)" if use_llm else "deterministic"
    print(f"OFFENSIVE IT-TESTER (agent)   target = {target_url}   brain = {brain}")
    print(BAR)

    registry = build_registry()
    audit = AuditLog(AUDIT_PATH)

    # choose the orchestrator ("brain")
    if use_llm:
        client = OllamaClient()
        if not client.available():
            print("  ⚠ Ollama not reachable — falling back to the deterministic policy.")
            policy = DeterministicPolicy(k_per_type=k_per_type)
        else:
            policy = LLMPolicy(client, registry,
                               fallback=DeterministicPolicy(k_per_type=k_per_type))
    else:
        policy = DeterministicPolicy(k_per_type=k_per_type)

    agent = Agent(registry, policy, audit=audit)
    state = agent.run(target_url)
    _report(state)

    ok, msg = AuditLog.verify(AUDIT_PATH)
    print(f"\n[AUDIT] {agent.audit.seq} events logged · chain {('OK — ' + msg) if ok else ('BROKEN — ' + msg)}")
    print(f"        ledger: {AUDIT_PATH}")

    # Layer 7 — optional LLM report
    if make_report:
        from src.reporting import generate_report
        print("\n[LAYER 7] REPORT  (LLM-generated)")
        md = generate_report(state)
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
