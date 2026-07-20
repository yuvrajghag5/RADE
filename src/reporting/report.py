"""
Layer 7 — reporting (open-source LLM via HuggingFace transformers).

Turns the agent's run state — including the Layer-6 confirmations — into a
readable Markdown findings report. The LLM only *narrates facts we hand it*: the
confirmed/unconfirmed findings come from the oracles, not the model, and a
deterministic facts block is appended verbatim so the ground truth is present
even if the model phrases things loosely.

Two responsible-AI controls are baked in: an EU AI Act Art. 50 transparency label
(the prose is AI-generated) and an honest confidence framing (e.g. reflected-XSS
is a candidate confirmed by reflection, not by observing JS execution).
"""
from __future__ import annotations
import json
from collections import Counter

from src.agent.llm import HFClient, LLMError


def build_run_summary(state: dict) -> dict:
    points = state.get("points") or []
    findings = state.get("findings") or []
    gate = state.get("gate")
    confirmed = [f for f in findings if f.get("confirmed") is True]

    return {
        "target": state.get("target"),
        "profile": state.get("profile"),
        "authorized": state.get("authorized"),
        "status": state.get("status"),
        "n_injection_points": len(points),
        "n_fired": len(findings),
        "n_confirmed": len(confirmed),
        "n_held": len(gate.held) if gate else 0,
        "confirmed_by_class": dict(Counter(f["attack_class"] for f in confirmed)),
        "confirmed_findings": [
            {"attack_class": f["attack_class"], "type": f["type"], "point": f["point"],
             "oracle": f["oracle"], "confidence": f["confidence"], "evidence": f["evidence"]}
            for f in confirmed
        ],
    }


def _facts_block(s: dict) -> str:
    lines = [
        "## Ground-truth facts (deterministic)",
        f"- Target: `{s['target']}`  · profile: `{s['profile']}`  · authorized: {s['authorized']}",
        f"- Injection points: {s['n_injection_points']}  · payloads fired: {s['n_fired']}  "
        f"· held by governance: {s['n_held']}",
        f"- **Confirmed exploits: {s['n_confirmed']}**  · by class: {s['confirmed_by_class']}",
    ]
    for f in s["confirmed_findings"]:
        lines.append(f"    - {f['attack_class']}/{f['type']} at `{f['point']}` "
                     f"via `{f['oracle']}` ({f['confidence']}): {f['evidence']}")
    return "\n".join(lines)


PROMPT = """You are writing a concise web-application security-assessment report for a bounded, \
authorized testing agent. Use ONLY the JSON facts provided — do not invent vulnerabilities, \
CVEs, hosts, or numbers beyond what is listed, and do not contradict the counts. Key facts to \
state correctly: `n_fired` payloads WERE fired at the target; `n_held` payloads were held by \
the governance gate and NOT fired; `n_confirmed` are confirmed by a detection oracle. Keep each \
finding's stated confidence (e.g. a reflected-XSS confirmed by reflection is NOT verified as \
executing in a browser). Write these Markdown sections: 1) Summary (use the exact fired / held / \
confirmed counts), 2) Scope & authorization, 3) Confirmed findings (a table: class, technique, \
oracle, confidence), 4) Governance & caveats. Keep it factual and under ~300 words.

JSON facts:
{facts}
"""

AI_LABEL = ("> **AI-generated (EU AI Act Art. 50).** The prose in this report was written by an "
            "open-source LLM ({model}, run locally via HuggingFace transformers) from the agent's "
            "structured run data. Findings are produced by deterministic detection oracles, not by "
            "the model.\n")


def generate_report(state: dict, client: HFClient | None = None) -> str:
    client = client or HFClient()
    summary = build_run_summary(state)
    try:
        narrative = client.generate(PROMPT.format(facts=json.dumps(summary, indent=2))).strip()
    except LLMError as e:
        narrative = f"*(LLM report unavailable: {e})*"
    label = AI_LABEL.format(model=client.cfg.model)
    return f"{label}\n{narrative}\n\n---\n{_facts_block(summary)}\n"
