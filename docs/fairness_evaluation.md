# Fairness Evaluation — Scanner Pipeline (Layers 1–3)

**Scope.** This document assesses the **payload-selection pipeline** (`main.py`:
authorization → recon → selection). The *baseline classifier's* fairness (per-class
precision/recall) lives in `models/baseline.ipynb` §7 — this is the complementary,
system-level view.

**What "fairness" means here.** Equal **test coverage** — across attack classes *and*
across techniques within a class. A class or technique that is selected less often is
**tested less**, so a "no vulnerability found" result there may just be an untested blind
spot, not a secure target. That is the core responsibility risk of an autonomous scanner.

Measured on the DVWA sandbox profile with the default `k_per_class = 3`.

## 1. Class-level coverage
| class | payloads available | unique selected | coverage | injection points |
|---|---|---|---|---|
| sqli | 87 | 6 | 6.9% | 2 |
| csrf | 95 | 6 | 6.3% | 2 |
| xss | 100 | 4 | 4.0% | 2 |
| ssrf | 85 | 3 | 3.5% | 1 |
| cmdi | 88 | 3 | 3.4% | 1 |

Two asymmetries:
- **CMDi and SSRF are exposed at only one injection point each**, so they get fewer shots
  than SQLi/XSS/CSRF. This reflects the *target profile*, not the arsenal — but it means
  those classes are systematically under-tested on this target.
- **Overall coverage is ~5%** — only **22 of 455 payloads** are ever fired. Most of the
  arsenal is never used (a function of small `k_per_class` + few injection points).

## 2. Within-class technique bias (the sharp finding)
For SQLi the selector fires only a subset of techniques:

| SQLi technique | available | selected |
|---|---|---|
| blind-time | 33 | 4 |
| boolean-blind | 13 | 1 |
| tautology | 17 | 1 |
| **union** | 9 | **0** |
| **error-based** | 4 | **0** |
| **stacked-queries** | 11 | **0** |

**Three whole SQLi techniques are never selected.** Cause: selection ranks by
`severity → payload length` and filters by `context_bucket`, so short high-severity
blind-time payloads always win the top-`k` slots. A target vulnerable *only* to
union-based SQLi would be reported clean — a coverage blind spot.

## 3. Root causes & mitigations
| cause | effect | mitigation |
|---|---|---|
| small `k_per_class` (=3) | ~5% of arsenal fired | raise `k`; or budget by injection point |
| rank by severity + length | short techniques dominate | **stratify by `type`**, not just `attack_class` |
| bucket-match filter | narrows the candidate pool | round-robin across techniques within a class |
| target profile (1 pt for cmdi/ssrf) | class exposure asymmetry | richer recon / more injection points |

## 4. What is fair today
- **Every class is represented** — no class is dropped entirely (0% coverage nowhere).
- Selection is **transparent and deterministic** — the rule is documented and auditable,
  so a blind spot is *explainable*, not hidden.

Next step to close the gap: change §3's ranking to **stratify by technique** so `union`,
`error-based`, and `stacked-queries` each get a slot.
