"""
Layer 7 — reporting (open-source LLM via Ollama).

Turns the agent's structured run state into a readable Markdown report. The LLM
only *narrates facts we hand it* — it is explicitly told NOT to invent or confirm
vulnerabilities, because execution/detection (Layers 5-6) are not built yet: what
recon found are **candidate** injection points and what selection produced is a
**planned test set**, not confirmed findings.

Two responsible-AI controls are baked in:
  * an EU AI Act Art. 50 transparency label (the report is AI-generated), and
  * a deterministic facts block appended verbatim, so the ground truth is present
    even if the model phrases things loosely.
"""
from __future__ import annotations
from collections import Counter

from src.agent.llm import OllamaClient, LLMError


def build_run_summary(state) -> dict:
    """Compact, factual summary of the run for the model to narrate."""
    points = state.points or []
    selection = state.selection or []

    class_counts: Counter = Counter()
    techniques: dict[str, set] = {}
    total_payloads = 0
    for pt, payloads in selection:
        for p in payloads:
            total_payloads += 1
            class_counts[p["attack_class"]] += 1
            techniques.setdefault(p["attack_class"], set()).add(p["type"])

    return {
        "target": state.goal,
        "profile": state.profile,
        "authorized": state.authorized,
        "status": state.status,
        "abort_reason": state.abort_reason,
        "injection_points": [
            {"name": pt.name, "method": pt.method, "param": pt.param,
             "bucket": pt.bucket, "classes": pt.classes, "url": pt.full_url}
            for pt in points
        ],
        "n_injection_points": len(points),
        "n_payloads_selected": total_payloads,
        "by_class": dict(class_counts),
        "technique_coverage": {k: sorted(v) for k, v in techniques.items()},
        "steps": state.steps,
    }


def _facts_block(summary: dict) -> str:
    lines = [
        "## Ground-truth facts (deterministic)",
        f"- Target: `{summary['target']}`  · profile: `{summary['profile']}`",
        f"- Authorized: {summary['authorized']}  · run status: {summary['status']}",
        f"- Injection points discovered: {summary['n_injection_points']}",
        f"- Payloads selected: {summary['n_payloads_selected']}  · by class: {summary['by_class']}",
        "- Technique coverage:",
    ]
    for cls, techs in sorted(summary["technique_coverage"].items()):
        lines.append(f"    - {cls}: {', '.join(techs)}")
    return "\n".join(lines)


PROMPT = """You are writing a concise security-assessment RUN REPORT for a bounded, \
authorized web-application testing agent. Use ONLY the JSON facts provided — do not \
invent vulnerabilities, CVEs, or results. IMPORTANT: no payload has been fired and no \
exploit has been confirmed (the execution/detection stages are not implemented), so \
describe the injection points as CANDIDATE points and the payloads as a PLANNED test \
set — never as confirmed findings. Write 4 short sections in Markdown: \
1) Summary, 2) Scope & authorization, 3) Candidate injection points (a table), \
4) Planned tests & coverage. Keep it factual and under ~300 words.

JSON facts:
{facts}
"""

AI_LABEL = ("> **AI-generated (EU AI Act Art. 50).** This report was written by an "
            "open-source LLM ({model}, run locally via Ollama) from the agent's "
            "structured run data. No payload was fired; nothing here is a confirmed "
            "vulnerability.\n")


def generate_report(state, client: OllamaClient | None = None) -> str:
    """Produce the Markdown report (LLM narration + deterministic facts + AI label)."""
    client = client or OllamaClient()
    summary = build_run_summary(state)
    import json
    try:
        msg = client.chat([
            {"role": "user", "content": PROMPT.format(facts=json.dumps(summary, indent=2))}
        ])
        narrative = (msg.get("content") or "").strip()
    except LLMError as e:
        narrative = f"*(LLM report unavailable: {e})*"

    label = AI_LABEL.format(model=client.cfg.model)
    return f"{label}\n{narrative}\n\n---\n{_facts_block(summary)}\n"
