# Risk Assessment — the Agent (Layers 1–7)

**Scope.** The full LangGraph agent (`main.py`): authorize → recon → select → govern →
execute → detect → report. The baseline *model's* risk register is in `models/baseline.ipynb`
§8; this is the system-level view. Framed with **NIST AI RMF (Map → Measure → Manage)**.

**Bounding fact.** The agent now **fires payloads and confirms exploits**, but two controls
cap the blast radius: **Layer 1** only authorises a loopback host on the allowlist (it cannot
touch a third party), and **Layer 4** is an automated governance policy that flags every
destructive payload in the audit (and, with `allow_destructive=False`, holds them by rule).
The target is a self-owned, disposable sandbox — worst case is resetting it.

## MAP — identified risks
| # | Risk | Likelihood | Impact | Evidence / note |
|---|---|---|---|---|
| P1 | **Scope escape** — scanning a host that isn't ours | Low | **Critical** (StGB §202a) | mitigated by `require_loopback` + allowlist + reject-by-default |
| P2 | **Recon blind spots** — a crawl misses real injection points | ~~High~~ **Reduced** | Medium | recon is now a **live crawler** (logs in, parses forms + URL params on the running target), not a static profile. Residual: it only visits seed + menu-linked pages, so an unlinked endpoint is still a blind spot |
| P3 | **Selection coverage gap** — techniques never fired → false "not vulnerable" | ~~High~~ **Reduced** | High | **mitigated:** selection now **stratifies by `type`**, so SQLi technique coverage went 3/6 → 5/6 (`union`/`error-based` now fired). Residual: `stacked-queries` unreachable — reclassified as a recon gap (P2), not selection bias (fairness §1) |
| P4 | **Destructive payload is fired** | Medium | **High** (bounded) | execution is live; the gate fires destructive payloads on the sandbox but **flags** them in the audit. Bounded to a disposable loopback target; `allow_destructive=False` holds them by rule for a real engagement |
| P5 | **Over-trust** — treating "fired" as "vulnerable" | Medium | Medium | firing ≠ confirmation; only a Layer-6 oracle marks a finding confirmed, with a confidence tier; unconfirmed ≠ safe |

## MEASURE — how each is checked
- **P1:** authorization tested on out-of-scope inputs — `http://example.com` → rejected
  (not loopback); `127.0.0.1:9999` → rejected (not on allowlist). Reject-by-default verified.
- **P3:** coverage = unique-selected / available per class; techniques-selected vs available.
  After the stratify-by-`type` fix: **5 of 6 SQLi techniques** selected (was 3), the last one
  unreachable from the current injection points.
- **P4:** the gate reports approved-vs-flagged counts each run (`GateResult.summary()`), and
  every fired destructive payload is recorded in the audit ledger. `allow_destructive=False`
  verified to hold them by rule.
- **P5:** oracle coverage is honest — 2 of 6 oracles are proven end-to-end on the sandbox
  (`differential`, `browser_execution`), the rest need DVWA/infra (see `docs/oracles_explained.md`).

## MANAGE — mitigations
- **P1** `require_loopback: true` hard guard + allowlist stored as reviewable data
  (`config/target_allowlist.yaml`) + reject-by-default. The scope firewall is the central
  lawfulness control.
- **P2** **done** — live crawler (requests + BeautifulSoup) is now the primary recon: it logs
  in, sets the security level, and parses forms + URL params on the running target. It
  hard-fails if the target is down (no silent profile fallback). Residual work: follow links
  beyond the seed/menu set to catch unlinked endpoints.
- **P3** **done** — selection stratifies by `type` (`k_per_type=2`), so every *reachable*
  technique gets a slot (fairness §3); coverage is now printed per scan by `main.py`. Residual
  `stacked-queries` gap rolls up into **P2** (recon must expose a `form_field` SQLi point).
- **P4** **automated governance gate (Layer 4), no human in the loop** — the agent fires
  autonomously, so the gate decides *by rule* (a person can't review a large, variable payload
  count). On the authorized disposable sandbox it fires all payloads but **flags every
  `is_destructive` one in the audit** for transparency; `allow_destructive=False` re-imposes a
  rule-based hold for a real engagement. Firing is bounded to the loopback sandbox by Layer 1.
- **P5** carry the `oracle` + confidence tier through to reporting; never label a target
  vulnerable without an oracle confirmation.

## Residual risk (accepted, documented)
Execution is now enabled, so the live risk is **firing destructive payloads at the target**
(P4) — accepted because the target is a self-owned, disposable, loopback sandbox (worst case:
reset it), destructive payloads are flagged in the audit, and `allow_destructive=False` is a
one-flag switch for non-sandbox use. The other standing concern is **P3 (coverage)** — a clean
result may just be an untested one.
