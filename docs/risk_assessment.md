# Risk Assessment — Baseline Model

Structured with **NIST AI RMF (Map → Measure → Manage)**. Scope: the baseline
classifier (attack-vs-benign detector + attack_class router), not the whole scanner.

## MAP — identified risks
| # | Risk | Likelihood | Impact | Evidence |
|---|---|---|---|---|
| R1 | **Label leakage** inflating scores (id prefix == class; bucket ≈ label) | Low (guarded) | High | features are payload-text only; `id`/`bucket`/`severity` excluded; exact-dup payloads removed before split |
| R2 | **Over-optimistic performance / OOD & evasion** — 0.98–0.99 F1 on clean, separable, in-distribution data | **High** | High | a hex-encoded payload already evades (fairness FN table); obfuscation/mutation not represented in training |
| R3 | **False negatives (missed attacks)** — attacks classified benign | Medium | **High** | 5/114 hold-out attacks missed (4.4%), concentrated in SSRF/CMDi exotic schemes & short commands |
| R4 | **Class imbalance** (1 : 4.4) making raw accuracy misleading | High | Medium | 92% "accuracy" is close to the 81% benign base-rate; only macro/per-class metrics are honest |
| R5 | **Benign distribution shift** — CSIC is clean Spanish e-commerce traffic | High | Medium | real target inputs differ in language, charset, structure → precision will drop |
| R6 | **Excessive agency / mis-routing** (OWASP LLM08) — a wrong class routes a payload to the wrong `confirm()` (possibly firing a destructive validator) | Low | High | 1 ssrf→cmdi confusion observed; oracle routing depends on class |

## MEASURE — how each is quantified
- **Reference beat:** DummyClassifier macro-F1 0.449 (binary) / 0.072 (5-way) vs model
  0.986 / 0.991 → the model learns real signal.
- **Per-class recall + confusion matrix** (see fairness doc) — the honest performance view.
- **False-negative rate** = 4.4% (R3), tracked as the primary security metric.
- **Leakage probe** (R1): retrain on `id`-derived features → if F1 → 1.0, leakage exists;
  current payload-only features avoid it.

## MANAGE — mitigations
- **R1:** payload-text-only features; exact-dup removal; documented — keep as a test.
- **R2:** treat reported F1 as an **upper bound**; add an adversarial/obfuscated eval set
  (URL-encode, case-swap, comment-insert) before trusting the model in the loop; the
  notebook's §10.1 evasion demo stays as the standing reminder.
- **R3:** the classifier is a **routing aid, not an authorizer** — a "benign" verdict never
  suppresses a payload that the dataset already labels as an attack; the live loop routes
  by the dataset `type`, so a model FN cannot silently drop a real payload.
- **R4:** `class_weight="balanced"`, macro-averaged reporting, no raw-accuracy claims.
- **R5:** flag low-confidence predictions for manual review; re-evaluate on target-native
  inputs once DVWA runs exist.
- **R6:** oracle **fallback chains** (a mis-routed CMDi still gets a timing/OOB check);
  the **governance gate** holds any `is_destructive`/critical payload for human review
  regardless of the model — so a misroute cannot autonomously fire a destructive test.

## Residual risk (accepted, documented)
The model is accurate **because the current data is easy**. Its real-world value is
**unproven against adversarial inputs**, and it is deliberately kept **non-authoritative**
(advisory routing only). This is the honest limitation to carry into the model card.
