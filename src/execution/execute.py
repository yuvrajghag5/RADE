"""
Layer 5 — execution.

Fires a single value at one injection point and captures the response (body,
status, elapsed time). This is the ONLY layer that sends attack input to the
target, so it is small, explicit, and always runs *after* the Layer-4 governance
gate has approved the payload. It never decides what to send — it just sends what
it is given and reports what came back, for the Layer-6 oracles to judge.
"""
from __future__ import annotations
from dataclasses import dataclass
import time

import requests

BENIGN_VALUE = "test"        # harmless value used to capture a baseline response


@dataclass
class FireResult:
    payload: str
    method: str
    url: str
    param: str
    status: int
    elapsed: float           # seconds
    text: str
    ok: bool = True
    error: str = ""


def fire(session: requests.Session, point, value: str, timeout: int = 10) -> FireResult:
    """Send `value` in `point.param` to `point.full_url` and capture the response.

    The whole form is submitted: the payload goes in `point.param`, and any companion
    fields recon captured (e.g. a Submit button) ride along in `point.extra` — without
    them, targets like DVWA never run the vulnerable code path.
    """
    fields = {**getattr(point, "extra", {}), point.param: value}
    if point.method == "GET":
        kwargs = {"params": fields}
    else:
        kwargs = {"data": fields}
    t0 = time.perf_counter()
    try:
        r = session.request(point.method, point.full_url, timeout=timeout,
                            allow_redirects=True, **kwargs)
        return FireResult(value, point.method, point.full_url, point.param,
                          r.status_code, time.perf_counter() - t0, r.text)
    except requests.RequestException as e:
        return FireResult(value, point.method, point.full_url, point.param,
                          0, time.perf_counter() - t0, "", ok=False, error=str(e))


def baseline(session: requests.Session, point, timeout: int = 10) -> FireResult:
    """Fire a harmless value to establish the 'normal' response for comparison."""
    return fire(session, point, BENIGN_VALUE, timeout)
