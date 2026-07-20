"""
Layer 6 — detection oracles.

An oracle answers the one question the dataset cannot: *did the payload actually
work on the target?* Each oracle compares the attack response against a benign
baseline (or a planted signal) and returns a Confirmation with a confidence tier.

Demonstrable locally (implemented, real):
  * error_signature  — a DB error appears that the baseline didn't show
  * differential     — a true-vs-false condition makes the response diverge
  * marker_reflection— the injected payload is reflected back unescaped
  * timing           — the response is delayed far beyond baseline (needs a real
                       DB backend, e.g. DVWA/MySQL; SQLite won't sleep)

Not demonstrable on a self-owned local sandbox (honest stubs — return
confirmed=None with the reason / infrastructure they would need):
  * browser_execution— needs a headless browser to see the JS actually run
  * out_of_band      — needs an external collaborator/callback server
  * state_change     — CSRF; semi-manual verification
"""
from __future__ import annotations
from dataclasses import dataclass

from src.execution.execute import fire, FireResult

# substrings that betray a database error surfacing to the response
SQL_ERROR_SIGNS = [
    "sql error", "sqlite", "syntax error", "unrecognized token", "no such column",
    "unterminated", "you have an error in your sql", "warning: mysql",
    "unclosed quotation", "sqlstate", "odbc", "near \"", "incorrect syntax",
]


@dataclass
class Confirmation:
    confirmed: bool | None     # True / False, or None = oracle not demonstrable here
    oracle: str
    confidence: str            # high | medium | low | none
    evidence: str


# ----- individual oracle checks ------------------------------------------------
def _error_signature(baseline: FireResult, attack: FireResult) -> Confirmation:
    b, a = baseline.text.lower(), attack.text.lower()
    for sign in SQL_ERROR_SIGNS:
        if sign in a and sign not in b:
            return Confirmation(True, "error_signature", "high",
                                f"DB error {sign!r} appeared that the baseline did not show")
    return Confirmation(False, "error_signature", "none", "no new DB error in the response")


def _marker_reflection(attack: FireResult) -> Confirmation:
    # the payload itself is the marker: if it comes back verbatim (unescaped), the
    # input reaches the output without sanitisation.
    marker = attack.payload
    if marker and marker in attack.text:
        return Confirmation(True, "marker_reflection", "high",
                            "payload reflected unescaped in the response (injection point confirmed)")
    return Confirmation(False, "marker_reflection", "none", "payload not reflected unescaped")


def _false_variant(payload: str) -> str | None:
    for a, b in (("'1'='1", "'1'='2"), ("1'='1", "1'='2"), ("1=1", "1=2"),
                 ("'a'='a", "'a'='b"), (" OR ", " AND ")):
        if a in payload:
            return payload.replace(a, b)
    return None


def _differential(session, point, attack: FireResult) -> Confirmation:
    fv = _false_variant(attack.payload)
    if fv is None:
        return Confirmation(False, "differential", "none",
                            "no true/false counterpart could be derived")
    false_res = fire(session, point, fv)
    # a real boolean SQLi makes the TRUE response differ from the FALSE one
    if attack.ok and false_res.ok and _diverges(attack.text, false_res.text):
        return Confirmation(True, "differential", "medium",
                            f"true vs false condition diverged ({fv!r} returned differently)")
    return Confirmation(False, "differential", "none", "true and false conditions matched")


def _diverges(a: str, b: str) -> bool:
    # crude but robust: a meaningful difference in returned content length
    return abs(len(a) - len(b)) > 15 or ("no user found" in b.lower()) != ("no user found" in a.lower())


def _timing(baseline: FireResult, attack: FireResult, min_delay: float = 4.0) -> Confirmation:
    delta = attack.elapsed - baseline.elapsed
    if attack.ok and delta >= min_delay:
        return Confirmation(True, "timing", "medium",
                            f"response delayed {attack.elapsed:.1f}s vs {baseline.elapsed:.1f}s baseline")
    return Confirmation(False, "timing", "none",
                        f"no significant delay ({attack.elapsed:.1f}s vs {baseline.elapsed:.1f}s)")


def _browser_execution(attack: FireResult) -> Confirmation:
    # Full XSS proof needs a headless browser to see the JS run. We can still give
    # an honest partial result: if the script payload is reflected UNESCAPED into
    # the HTML, that is a real reflected-XSS signal (it would execute in a browser).
    if attack.payload and attack.payload in attack.text:
        return Confirmation(True, "browser_execution", "medium",
                            "payload reflected unescaped into HTML (reflected-XSS candidate); "
                            "JS execution not verified without a headless browser")
    return Confirmation(None, "browser_execution", "none",
                        "not demonstrable without a headless browser (payload not reflected)")


def _not_demonstrable(oracle: str, needs: str) -> Confirmation:
    return Confirmation(None, oracle, "none", f"not demonstrable on a local sandbox — needs {needs}")


# ----- dispatcher --------------------------------------------------------------
ORACLES = ["error_signature", "differential", "marker_reflection", "timing",
           "browser_execution", "out_of_band", "state_change"]


def detect(session, point, payload_row: dict, baseline: FireResult) -> tuple[Confirmation, FireResult]:
    """Fire the payload and confirm it with the oracle the dataset assigned to it."""
    oracle = payload_row.get("oracle", "")
    attack = fire(session, point, payload_row["payload"])

    if oracle == "error_signature":
        conf = _error_signature(baseline, attack)
    elif oracle == "marker_reflection":
        conf = _marker_reflection(attack)
    elif oracle == "differential":
        conf = _differential(session, point, attack)
    elif oracle == "timing":
        conf = _timing(baseline, attack)
    elif oracle == "browser_execution":
        conf = _browser_execution(attack)
    elif oracle == "out_of_band":
        conf = _not_demonstrable("out_of_band", "an external collaborator/callback server")
    elif oracle == "state_change":
        conf = _not_demonstrable("state_change", "semi-manual cross-origin verification")
    else:
        conf = Confirmation(None, oracle or "unknown", "none", "no oracle for this payload type")
    return conf, attack
