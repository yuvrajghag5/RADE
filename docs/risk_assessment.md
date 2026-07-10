# Risk Assessment — Scanner Pipeline (Layers 1–3)

**Scope.** The authorization → recon → selection pipeline (`main.py`). The baseline
*model's* risk register is in `models/baseline.ipynb` §8; this is the system-level view.
Framed with **NIST AI RMF (Map → Measure → Manage)**.

**Bounding fact.** Layers 1–3 **never fire a payload** — they stop at selection. That caps
the blast radius: the only actions taken are reading config and reading the dataset. The
serious risks below are about *what happens when execution is added* and about *scope*.

## MAP — identified risks
| # | Risk | Likelihood | Impact | Evidence / note |
|---|---|---|---|---|
| P1 | **Scope escape** — scanning a host that isn't ours | Low | **Critical** (StGB §202a) | mitigated by `require_loopback` + allowlist + reject-by-default |
| P2 | **Recon blind spots** — profile-based recon misses real injection points | High | Medium | current recon reads a declared DVWA profile; a missed point = untested surface |
| P3 | **Selection coverage gap** — most of the arsenal is never fired | High | High | only 22/455 (~5%) selected; **union / error-based / stacked-queries SQLi never chosen** (see fairness §2) → false "not vulnerable" |
| P4 | **Destructive payload reaches execution** | Medium | **High** | selection does **not** exclude destructive payloads — 0 were selected here only *incidentally* (bucket mismatch), not by design |
| P5 | **Over-trust** — treating "selected" as "vulnerable" | Medium | Medium | selection ≠ confirmation; only the Layer-6 oracle proves a hit |

## MEASURE — how each is checked
- **P1:** authorization tested on out-of-scope inputs — `http://example.com` → rejected
  (not loopback); `127.0.0.1:9999` → rejected (not on allowlist). Reject-by-default verified.
- **P3:** coverage = unique-selected / available per class (3.4–6.9%); techniques-selected
  vs available (3 of 6 SQLi techniques = 0).
- **P4:** count of `is_destructive` payloads that pass selection (currently 0, but **not
  guaranteed** — must be enforced downstream).

## MANAGE — mitigations
- **P1** `require_loopback: true` hard guard + allowlist stored as reviewable data
  (`config/target_allowlist.yaml`) + reject-by-default. The scope firewall is the central
  lawfulness control.
- **P2** wire the live crawler (requests + BeautifulSoup) as the primary recon, keeping the
  profile only as a fallback; log every discovered vs profiled point.
- **P3** stratify selection by `type` and raise `k_per_class` so every technique gets a slot
  (see fairness §3) — turn coverage into a reported metric per scan.
- **P4** **do not enable execution before Layer 4 (governance gate)** — the gate must hold
  every `is_destructive`/critical payload for human review *before* firing. Until then the
  pipeline is intentionally selection-only.
- **P5** carry the `oracle` + confidence tier through to reporting; never label a target
  vulnerable without an oracle confirmation.

## Residual risk (accepted, documented)
Because nothing is fired, present risk is low and dominated by **P3 (coverage)** — a real
responsibility concern that a clean result may be an untested one. The gating rule going
forward: **execution stays disabled until the governance gate (L4) and sandbox isolation
are both in place.**
