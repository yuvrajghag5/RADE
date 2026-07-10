# Project Updates

Summary of the data + modelling work added in this iteration. The original design and
architecture remain in [`README.md`](README.md); this file records **what changed and why**.

---

## 1. What changed at a glance
1. **Fixed a broken pipeline** — `config/paths.py` had been renamed (`RAW_DIR`→`RAW`),
   which crashed `preprocess/preprocess.py` on import. Re-aliased; the pipeline runs again.
2. **Added a real benign/negative corpus** — sourced from **HTTP DATASET CSIC 2010**
   (not synthetic), so the system can decide *"is this an attack?"*, not just *"which attack?"*.
3. **Re-scored severity** — the raw severity labels were internally inconsistent; they are
   now recomputed from a documented policy with a full audit trail.
4. **Built the final execution-ready dataset** — attack + benign unified into one schema
   with injection-point buckets, oracle routing, and governance flags.
5. **Trained a baseline model** — attack-vs-benign detector + attack_class router, with
   leakage guards; delivered as both a script and an executed notebook.
6. **Wrote fairness & risk analyses** grounded in the model's actual errors.

---

## 2. New / changed files
| Path | Status | Purpose |
|---|---|---|
| `config/paths.py` | fixed | removed duplicate import, added `RAW_DIR` alias |
| `data/raw/csic_2010_benign.csv` | **new** | 20,104 benign values extracted from CSIC 2010 (GPL-3.0) |
| `preprocess/benign_corpus.py` | **new** | loads + maps + samples benign inputs from CSIC 2010 |
| `preprocess/build_dataset.py` | **new** | master builder: repair → clean → bucket → **severity** → oracle → merge |
| `data/cleaned/dataset_final.jsonl` (+`.csv`) | **new** | the execution-ready dataset (also in `data/processed/`) |
| `data/processed/DATA_CARD.md` | **new** | provenance, schema, severity policy, limitations |
| `models/baseline.py` | **new** | baseline training script (Tasks A & B) |
| `models/baseline.ipynb` | **new** | executed, presentation-ready notebook version |
| `models/clf_binary.pkl`, `models/clf_attack_class.pkl` | **new** | trained baseline models |
| `docs/fairness_evaluation.md` | **new** | per-class metrics + false-negative analysis |
| `docs/risk_assessment.md` | **new** | NIST Map → Measure → Manage risk register |

---

## 3. Dataset: `dataset_final.jsonl` (2,455 rows)
| Half | Rows | Source |
|---|---|---|
| attack | 455 | Kaggle `WEB_APPLICATION_PAYLOADS` (repaired, deduped) |
| benign | 2,000 | HTTP DATASET CSIC 2010 (normal traffic, sampled seed 42) |

**15-field schema:** `id · label · attack_class · type · payload · context ·
context_bucket · severity · severity_original · severity_reason · is_destructive ·
destructive_flags · oracle · description · example`

**Severity was recomputed** (raw labels were inconsistent — reflected == stored XSS,
all blind SQLi == medium, CMDi split medium/high/critical). **283 / 455 labels changed;**
`severity_original` + `severity_reason` keep it auditable.

**`oracle`** tags each attack with the `confirm()` validator that proves it:
`timing · error_signature · marker_reflection · differential · browser_execution ·
out_of_band · state_change`.

---

## 4. Baseline model results
Char n-gram TF-IDF + Logistic Regression, `class_weight="balanced"`, payload-text-only
features, exact-dup removal, 25% stratified hold-out.

| Task | Macro-F1 | Dummy ref |
|---|---|---|
| A — attack vs benign | **0.986** | 0.449 |
| B — attack_class (router) | **0.991** | 0.072 |

**Honest read:** scores are high because the data is easy (clean benign vs loud payloads).
The value is in the **5 false negatives** — SSRF/CMDi payloads with exotic schemes
(`tel:`, `magnet:`), short Windows commands, and encoded payloads — i.e. the model breaks
exactly where an attacker would push. The model is kept **advisory only**.

---

## 5. Reproduce
```bash
python -m preprocess.build_dataset      # rebuild dataset_final (cleaned + processed)
python -m models.baseline               # train + evaluate both baseline models
# notebook: open models/baseline.ipynb  (run with the .venv kernel)
```

---

## 6. Known limitations / next steps
- **Imbalanced 1 : 4.4** (attack : benign) — use macro metrics, not raw accuracy.
- **Benign is clean, Spanish e-commerce traffic** — under-represents payload-shaped-but-
  benign inputs (`O'Brien`, `1=1`); real precision will be lower.
- **No adversarial eval yet** — add URL-encoded / case-swapped / comment-injected variants
  to *measure* the evasion risk instead of only naming it.
- **No target responses yet** — success validation (the `oracle` layer) needs live DVWA
  runs; that is the next build after the safety gates.
