# Fairness Evaluation — Scanner Pipeline (Layers 1–3)

**Scope.** This document assesses the **payload-selection pipeline** (`main.py`:
authorization → recon → selection). The *baseline classifier's* fairness (per-class
precision/recall) lives in `models/baseline.ipynb` §7 — this is the complementary,
system-level view.

**What "fairness" means here.** Equal **test coverage** — across attack classes *and*
across techniques within a class. A class or technique that is selected less often is
**tested less**, so a "no vulnerability found" result there may just be an untested blind
spot, not a secure target. That is the core responsibility risk of an autonomous scanner.

Measured on the DVWA sandbox profile. **Update:** selection was changed from "rank the
whole class by severity+length, take the top-`k`" to **stratify by `type`** — take the
`k_per_type` (=2) best of *every* technique. §1–2 show the before/after; §3 is the fix.

## 1. Within-class technique bias (the sharp finding) — FIXED
The old rule ranked each class by `severity → payload length` and took the top-`k`, so
short high-severity **blind-time** payloads won every SQLi slot and whole techniques were
never selected. Stratifying by technique gives each technique its own slots:

| SQLi technique | available | selected (old, `k_per_class=3`) | selected (new, stratified `k_per_type=2`) |
|---|---|---|---|
| blind-time | 33 | 4 | ✓ |
| boolean-blind | 13 | 1 | ✓ |
| tautology | 17 | 1 | ✓ |
| **union** | 9 | **0** | **✓ now covered** |
| **error-based** | 4 | **0** | **✓ now covered** |
| **stacked-queries** | 11 | **0** | **0 — recon gap (see below)** |

**SQLi technique coverage went from 3/6 → 5/6.** `union` and `error-based` are now fired.
A target vulnerable *only* to union-based SQLi is no longer reported clean.

**Why `stacked-queries` is still 0 — and why that's now a *different* problem.** Every
stacked-queries payload sits in the `form_field` context bucket, but **neither SQLi
injection point in the DVWA profile exposes `form_field`** (`sqli_id` = `url_param`,
`xss_reflected` = `search_field`). So the miss is no longer a *selection* bias — the
selector fires every technique it can reach — it is a **recon coverage gap**: the target
profile has no form-field SQLi point. That is tracked as risk **P2** (recon blind spots),
fixed by richer recon / more injection points, not by the selector.

## 2. Class-level coverage (before → after)
| class | payloads available | unique selected (old) | unique selected (new) | injection points |
|---|---|---|---|---|
| sqli | 87 | 6 | **11** | 2 |
| csrf | 95 | 6 | 4 | 2 |
| xss | 100 | 4 | 5 | 2 |
| ssrf | 85 | 3 | 2 | 1 |
| cmdi | 88 | 3 | 2 | 1 |
| **total** | 455 | **22 (4.8%)** | **24 (5.3%)** | 6 |

Total volume is about the same (24 vs 22) but it is now **spread across techniques**
instead of concentrated in blind-time SQLi — the fairness win is in *composition*, not
count. The remaining asymmetry is structural: **CMDi and SSRF are exposed at only one
injection point each** and their `type` field has no sub-techniques, so stratification
can't add breadth there — again a *target-profile* limit, not a selection bias.

## 3. The fix (what changed in `select.py`)
| cause (old) | effect | mitigation (now shipped) |
|---|---|---|
| rank whole class by severity + length | short blind-time techniques dominate | **group by `type`, take `k_per_type` of each** — round-robin across techniques |
| single `k_per_class` budget | depth in one technique, none in others | per-technique budget (`k_per_type=2`) — breadth first, then depth |
| bucket-match filter | narrows the candidate pool | *kept* — bucket relevance still matters; residual misses are attributed to recon |
| target profile (1 pt for cmdi/ssrf; no form_field) | class/technique exposure asymmetry | richer recon / more injection points (risk P2) |

## 4. What is fair now
- **Every class is represented, and every *reachable* technique gets a slot** — SQLi
  coverage 3/6 → 5/6; the only miss is unreachable from the current injection points.
- The one residual technique gap (`stacked-queries`) is **correctly re-attributed** from
  selection bias to a recon/target-profile gap — an honest, more precise diagnosis.
- Selection stays **transparent and deterministic** — the rule is documented and auditable,
  so any remaining blind spot is *explainable*, not hidden.
