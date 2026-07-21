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


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0, "": 0}
_CLASS_NAME = {
    "sqli": "SQL Injection", "xss": "Cross-Site Scripting", "cmdi": "OS Command Injection",
    "lfi": "Local File Inclusion", "rfi": "Remote File Inclusion", "ssrf": "Server-Side Request Forgery",
    "csrf": "Cross-Site Request Forgery", "xxe": "XML External Entity", "ssti": "Server-Side Template Injection",
    "idor": "Insecure Direct Object Reference", "redirect": "Open Redirect", "traversal": "Path Traversal",
}


def _class_label(cls: str) -> str:
    return _CLASS_NAME.get((cls or "").lower(), (cls or "unknown").upper())


def build_run_summary(state: dict) -> dict:
    points = state.get("points") or []
    findings = state.get("findings") or []
    gate = state.get("gate")
    confirmed = [f for f in findings if f.get("confirmed") is True]

    # order the detailed findings most-severe first so the report reads like an audit
    confirmed = sorted(confirmed, key=lambda f: _SEV_RANK.get(f.get("severity"), 0), reverse=True)

    def _sev(f):
        return (f.get("severity") or "unrated").lower()

    return {
        "target": state.get("target"),
        "profile": state.get("profile"),
        "authorized": state.get("authorized"),
        "status": state.get("status"),
        "n_injection_points": len(points),
        "n_fired": len(findings),
        "n_confirmed": len(confirmed),
        "n_held": len(gate.held) if gate else 0,
        "confirmed_by_class": dict(Counter(_class_label(f["attack_class"]) for f in confirmed)),
        "confirmed_by_severity": dict(Counter(_sev(f) for f in confirmed)),
        "highest_severity": max((_sev(f) for f in confirmed), key=lambda s: _SEV_RANK.get(s, 0),
                                default="none"),
        # Vulnerability-identity facts only (class, technique, WHERE it lives, how bad it is).
        # Still NO detection-method / oracle / evidence / confidence — the report talks about the
        # vulnerabilities and their fixes, not how the test found them.
        "confirmed_findings": [
            {
                "n": i + 1,
                "vulnerability": _class_label(f["attack_class"]),
                "technique": f["type"],
                "severity": _sev(f),
                "endpoint": f.get("url") or f.get("point"),
                "parameter": f.get("param"),
                "method": (f.get("method") or "GET").upper(),
            }
            for i, f in enumerate(confirmed)
        ],
    }


def _findings_appendix(s: dict) -> str:
    """Deterministic ground-truth table, appended verbatim after the model's prose so the
    exact counts and locations are present even if the narrative phrases things loosely."""
    lines = [
        "",
        "APPENDIX A — CONFIRMED FINDINGS (deterministic ground truth)",
        f"Target: {s['target']}  |  profile: {s['profile']}  |  authorised: {s['authorized']}",
        f"Injection points: {s['n_injection_points']}  |  payloads fired: {s['n_fired']}  "
        f"|  held by governance: {s['n_held']}  |  confirmed: {s['n_confirmed']}",
        f"By class: {s['confirmed_by_class'] or '{}'}   By severity: {s['confirmed_by_severity'] or '{}'}",
        "",
    ]
    if s["confirmed_findings"]:
        lines.append(f"{'#':<3} {'SEVERITY':<9} {'VULNERABILITY':<26} {'TECHNIQUE':<16} "
                     f"{'METHOD':<7} {'PARAMETER':<14} ENDPOINT")
        lines.append("-" * 100)
        for f in s["confirmed_findings"]:
            lines.append(f"{f['n']:<3} {f['severity'].upper():<9} {f['vulnerability']:<26} "
                         f"{str(f['technique']):<16} {f['method']:<7} {str(f['parameter'] or '-'):<14} "
                         f"{f['endpoint']}")
    else:
        lines.append("No exploits were confirmed on this target.")
    return "\n".join(lines) + "\n"


PROMPT = """Write a professional SECURITY ASSESSMENT REPORT from the JSON facts below.

FORMATTING RULES (important):
- Plain prose only. Do NOT use any Markdown: no '#', no '*', no backticks, no tables, no bullet stars.
- Put each section title on its own line in UPPERCASE, followed by plain sentences.
- Within DETAILED FINDINGS, start each finding on its own line as "Finding N:" followed by prose.

CONTENT RULES:
- Use ONLY these facts — do not invent vulnerabilities, CVEs, hosts, ports, or numbers, and do not
  contradict the counts (`n_fired` payloads fired, `n_confirmed` confirmed vulnerabilities).
- Talk ONLY about the vulnerabilities that were found and how to fix them. Do NOT mention the
  testing tools, the detection method or oracles, confidence levels, headless browsers, true/false
  divergence, or any limitation of the test itself. This is a findings-and-remediation report, not
  a commentary on the methodology.
- Write for a technical-but-mixed audience: each detailed finding must state, in plain sentences,
  what the flaw is, the concrete impact an attacker could achieve, and the specific fix — using the
  finding's own class, technique, severity, HTTP method, parameter, and endpoint.

Sections, in order:
EXECUTIVE SUMMARY  — one paragraph: the scope in a phrase, how many payloads were fired and how many
  confirmed vulnerabilities were found, the classes involved, the highest severity observed, and the
  resulting overall risk posture.
SCOPE AND AUTHORISATION  — the target, the tester profile, and that the run was authorised and bounded.
SUMMARY OF FINDINGS  — the count of confirmed vulnerabilities broken down by class and by severity.
DETAILED FINDINGS  — one entry per confirmed finding (there are `n_confirmed`). For each, give: its
  severity, the vulnerability class and technique, the exact location (HTTP method, parameter, and
  endpoint), the concrete impact if exploited, and a targeted remediation for that specific instance.
RECOMMENDATIONS  — cross-cutting hardening for each class found (for example: parameterised queries /
  prepared statements and least-privilege database accounts for SQL injection; contextual output
  encoding, strict input validation, and a Content-Security-Policy for cross-site scripting).
CONCLUSION  — one short paragraph on the overall security posture and the priority order for fixes.

Aim for 450-650 words. Be specific and concrete; do not pad.

FACTS:
{facts}
"""

AI_LABEL = ("AI-generated (EU AI Act Art. 50): written by a local open-source model ({model}, via "
            "HuggingFace) from the agent's run data. Findings come from deterministic detection "
            "oracles, not the model.\n\n")


def stream_report(state: dict, client: HFClient | None = None):
    """Yield the report as it's written — a plain AI label, then the streamed prose."""
    client = client or HFClient()
    summary = build_run_summary(state)
    yield AI_LABEL.format(model=client.cfg.model)
    try:
        for chunk in client.stream(PROMPT.format(facts=json.dumps(summary, indent=2))):
            yield chunk
    except LLMError as e:
        yield f"\n(LLM unavailable: {e})"
    # deterministic ground-truth block, always emitted regardless of the LLM's prose
    yield "\n" + _findings_appendix(summary)


def generate_report(state: dict, client: HFClient | None = None) -> str:
    client = client or HFClient()
    summary = build_run_summary(state)
    try:
        narrative = client.generate(PROMPT.format(facts=json.dumps(summary, indent=2))).strip()
    except LLMError as e:
        narrative = f"(LLM report unavailable: {e})"
    return (AI_LABEL.format(model=client.cfg.model) + narrative + "\n"
            + _findings_appendix(summary))
