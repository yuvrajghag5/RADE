# How the detection oracles work — "verify successful exploitation"

This is the heart of the offensive tester: an **oracle** decides whether a fired
payload *actually worked* on the target. It is what turns "I sent an attack" into
"I proved the attack succeeded."

Code: [`src/detection/oracles.py`](../src/detection/oracles.py) (the oracles) and
[`src/execution/execute.py`](../src/execution/execute.py) (firing + baseline).

---

## The core problem

The payload dataset is only an *arsenal* — it contains attacks, but **no label for
whether any attack will work on a given target**, because success depends entirely
on how *that* site is built. So success cannot be read from data; it must be
**observed on the live target**. Every fired payload is validated by watching how
the target reacts.

## Two flavours of proof

Every oracle uses one of two ideas — and both refuse to *assume* success:

1. **Compare against a baseline** — snapshot the site's *normal* behaviour first,
   then attack, and only claim success if the response changed in a telltale way.
2. **Plant a signal you control** — inject something recognisable (a unique string,
   or a timed delay) and only claim success if that exact signal comes back.

---

## Groundwork: firing a payload and snapshotting "normal"

Both flavours build on two small functions in `execute.py`:

```python
def fire(session, point, value, timeout=10):
    if point.method == "GET":
        kwargs = {"params": {point.param: value}}   # ?param=value
    else:
        kwargs = {"data": {point.param: value}}      # form body
    t0 = time.perf_counter()                          # start a stopwatch
    r = session.request(point.method, point.full_url, **kwargs)
    return FireResult(..., r.status_code, time.perf_counter() - t0, r.text)
```

- Drops `value` into the vulnerable parameter, sends the request, and returns the
  **response text** plus **how long it took** (`elapsed`). That stopwatch matters
  for the timing oracle.

```python
def baseline(session, point):
    return fire(session, point, "test")   # a harmless value
```

- Fires a boring value once to capture what a **normal** response looks like — the
  reference point for "normal".

---

## Flavour 1 — Compare against the baseline

### `error_signature` — the cleanest example

```python
def _error_signature(baseline, attack):
    b, a = baseline.text.lower(), attack.text.lower()
    for sign in SQL_ERROR_SIGNS:
        if sign in a and sign not in b:
            return Confirmation(True, "error_signature", "high",
                                f"DB error {sign!r} appeared that the baseline did not show")
    return Confirmation(False, "error_signature", "none", "no new DB error")
```

1. `b` = the **normal** page text; `a` = the **attack** page text.
2. `SQL_ERROR_SIGNS` is a list of DB-error phrases (`"you have an error in your sql"`,
   `"unrecognized token"`, …).
3. The key line — `if sign in a and sign not in b` — a database error appears in the
   **attack** response *and was absent from the normal one*.
4. That `and sign not in b` is why the baseline matters: it proves **our attack
   caused the error** (not that the phrase is always on the page). Input reaching the
   database raw → injection confirmed.

### `differential` — the one proven end-to-end

Compares two *crafted* responses (true vs false) — same "look for a difference" idea:

```python
def _differential(session, point, attack):
    fv = _false_variant(attack.payload)          # make the "false" twin
    if fv is None:
        return Confirmation(False, ...)          # can't build a pair -> give up honestly
    false_res = fire(session, point, fv)         # fire the false version too
    if _diverges(attack.text, false_res.text):   # did true and false differ?
        return Confirmation(True, "differential", "medium", "...diverged...")
    return Confirmation(False, ...)

def _false_variant(payload):
    for a, b in (("1=1", "1=2"), (" OR ", " AND "), ...):
        if a in payload:
            return payload.replace(a, b)          # ' OR 1=1--  ->  ' OR 1=2--
    return None

def _diverges(a, b):
    return abs(len(a) - len(b)) > 15 or (... "no user found" differs ...)
```

1. Take the attack (`' OR 1=1--`, always **true**) and auto-build its opposite
   (`' OR 1=2--`, always **false**).
2. Fire both.
3. `_diverges` asks: are the two responses **meaningfully different**?
4. If they diverge, the site is genuinely evaluating our true/false logic — a *safe*
   site returns the same for both — so **SQL injection is confirmed**. This is the
   `✓ sqli/tautology via differential` result in a run.

---

## Flavour 2 — Plant a signal

### `marker_reflection` — plant a *text* signal

```python
def _marker_reflection(attack):
    marker = attack.payload                       # the payload IS the signal
    if marker and marker in attack.text:          # did it come back verbatim?
        return Confirmation(True, "marker_reflection", "high",
                            "payload reflected unescaped in the response")
    return Confirmation(False, ...)
```

1. The "signal" is the payload itself — e.g. `<script>alert(1)</script>`, a
   distinctive string that should not appear naturally.
2. `marker in attack.text` — did our **exact injected string survive the round trip
   and come back unchanged**?
3. If yes, the site placed our input into the output **without sanitising it**. On
   real DVWA command injection this is how `| whoami` echoing the actual username
   back is caught — the planted signal came home.

### `timing` — plant a *time* signal

```python
def _timing(baseline, attack, min_delay=4.0):
    delta = attack.elapsed - baseline.elapsed     # how much slower than normal?
    if attack.ok and delta >= min_delay:
        return Confirmation(True, "timing", "medium",
                            f"response delayed {attack.elapsed:.1f}s vs {baseline.elapsed:.1f}s")
    return Confirmation(False, ...)
```

1. The planted signal is not text — it is a **deliberate delay**. The payload says
   `SLEEP(5)`: "database, pause for 5 seconds."
2. `delta = attack.elapsed - baseline.elapsed` — subtract the normal response time
   (from the baseline stopwatch) from the attack's response time.
3. If the attack was **≥ 4 s slower** than normal, the database *obeyed the injected
   pause* → injection confirmed.
4. This works even when the page looks **identical** (a "blind" injection with no
   visible data) — you read the *clock*, not the *content*. It needs a real DB that
   can sleep (DVWA/MySQL, not the SQLite sandbox).

---

## The honest stubs (not faked)

Some confirmations cannot be produced on a self-owned local sandbox, so the oracle
returns `confirmed = None` with the reason — never a fake green tick:

| Oracle | Why it can't be proven locally |
|---|---|
| `browser_execution` (full) | needs a **headless browser** to watch the JS actually run. We give an honest partial result: script reflected unescaped = a reflected-XSS *candidate*, clearly labelled "not verified in a browser". |
| `out_of_band` (SSRF, blind CMDi) | needs an **external callback server** to catch the target phoning home. |
| `state_change` (CSRF) | **semi-manual** cross-origin verification. |

The sandbox is also kept honest: its command-injection and SSRF pages **do not echo
input back**, specifically so no oracle can *falsely* confirm them.

---

## Coverage: built vs. verified

| Oracle | Built (real code)? | Verified end-to-end? | Where / notes |
|---|---|---|---|
| `differential` | ✅ | ✅ **proven** | Flask sandbox — true/false SQLi diverges, no caveats |
| `browser_execution` | ✅ | ✅ **proven (reflection, caveated)** | Flask + DVWA — reflected/stored XSS; full JS-run needs a browser |
| `error_signature` | ✅ | ✅ **proven** | **live DVWA (MySQL)** — real "you have an error in your SQL" on error-based SQLi |
| `timing` | ✅ | ▲ not triggered on DVWA | the arsenal's blind payloads use `--`/`pg_sleep` (wrong comment style / PostgreSQL); MySQL didn't sleep → correctly not confirmed |
| `marker_reflection` | ✅ | ▲ guarded | now suppressed on echo-everything pages to avoid a false positive; a true union/CMDi marker oracle needs data/command-output checking |
| `out_of_band` | ✖ stub | ✖ | needs a callback server |

**3 of 6 oracles are now proven end-to-end** (`differential`, `browser_execution`,
`error_signature`), across the Flask sandbox *and* live DVWA. The rest are implemented but
either need infrastructure a local run can't provide (`out_of_band`) or were correctly *not*
confirmed because the specific arsenal payloads don't match the target's DBMS/context.

### What live DVWA taught us (an honest, important finding)
Firing the full arsenal at real DVWA, only the payloads that genuinely fit **MySQL + a
string-context injection** confirmed (error-based SQLi, reflected/stored XSS). Blind-time
payloads like `' OR SLEEP(5)--` (MySQL needs `-- ` *with a space*) and `' OR pg_sleep(4)#`
(PostgreSQL, not MySQL) **did not** — and that's the tool being **honest**: it fires everything
but confirms only what actually works, never assuming an exploit from the payload alone. This is
exactly why you fire *many* payloads (coverage) and rely on an oracle to tell you which landed.

---

## One-liner

> An oracle fires the attack, compares the site's reaction to its normal behaviour
> (or plants a signal it controls), and declares **"confirmed"** only when the target
> does something it physically could not do unless the vulnerability were real.
