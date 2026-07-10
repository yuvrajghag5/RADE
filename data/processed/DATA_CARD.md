# Data Card — `dataset_final.jsonl`

Execution-ready dataset for the Offensive IT-Tester. One row per input string,
either an **attack** payload (from the Kaggle set) or a **benign** input
(synthetic negative corpus). Built by `preprocess/build_dataset.py` (reproducible).

## Provenance
| Source | Rows | Notes |
|---|---|---|
| `data/raw/WEB_APPLICATION_PAYLOADS.jsonl` (Kaggle) | 500 → **455** | repaired (nbsp/comma/escape), deduped (−44), 1 empty payload dropped |
| **HTTP DATASET CSIC 2010** (benign, `Class=Valid`) | **2000** | sampled (seed 42) from 20,104 distinct benign param values; mapped to injection-point buckets |
| **Total** | **2455** | attack:benign ≈ 1:4.4 (imbalanced — see limitations) |

**Benign source detail.** CSIC 2010 is the standard academic web-attack benchmark
(Spanish Research Council). We use only the 36,000 normal requests and extract the
parameter values real users sent to an e-commerce app (usernames, names, emails,
addresses, prices, national-ID/card fields). Obtained via
`github.com/msudol/Web-Application-Attack-Datasets` (`CSVData/csic_final.csv`, **GPL-3.0**);
the compact extract lives at `data/raw/csic_2010_benign.csv` (408 KB, 20,104 rows).
CSIC traffic is **auto-generated**, so DNI/card values are fabricated — **no real PII**
(consistent with the project's GDPR data-minimisation stance).

## Schema (15 fields)
| field | meaning |
|---|---|
| `id` | `sqli-001…` / `benign-000…` |
| `label` | `attack` \| `benign` — the input-side classifier target |
| `attack_class` | `sqli/xss/csrf/ssrf/cmdi` \| `benign` |
| `type` | technique (`union`, `blind-time`, `stored`, …) or benign category |
| `payload` | the raw string to send |
| `context` | free-text injection point (original) |
| `context_bucket` | normalised injection-point bucket (15 values) |
| `severity` | **recomputed** severity (see below) |
| `severity_original` | label as shipped in the raw data (null for benign) |
| `severity_reason` | audit trail: every rule that set `severity` |
| `is_destructive` | payload destroys/alters data (governance-gate hold) |
| `destructive_flags` | which destructive pattern(s) matched |
| `oracle` | which `confirm()` validator proves this technique |
| `description` | human description |
| `example` | example query/usage (null for benign / when absent) |

## Severity was RECOMPUTED, not trusted
The raw labels were internally inconsistent (reflected == stored XSS == `high`;
all blind SQLi == `medium`; CMDi split medium/high/critical; SSRF had `low`).
**283 of 455 (62%) severities changed.** New severity = a documented base per
`(class, technique)` + payload-content overrides (cloud-metadata → critical,
read-only recon → high, high-impact CSRF → high, destructive → critical).
`severity_original` + `severity_reason` are kept on every row so the change is
auditable. Note: no attack payload is rated `low` — `medium` is the floor.
This is an **opinionated policy** — review `BASE_SEVERITY` against your threat model.

## `oracle` routing (how success is validated)
`timing`, `error_signature`, `marker_reflection`, `differential`,
`browser_execution`, `out_of_band`, `state_change` (CSRF; semi-manual).

## Known limitations (for the risk deliverable)
- **Class imbalance:** 455 attack vs 2000 benign (≈1:4.4). Realistic direction (most
  traffic is benign) but train with `class_weight="balanced"` / stratified splits and
  report per-class metrics, not raw accuracy. Adjust `BENIGN_N` in `build_dataset.py`.
- **Benign is clean real traffic**, not adversarial hard negatives — CSIC inputs rarely
  contain payload-like characters, so the two classes may be *more* separable than in
  production (a payload-shaped-but-benign string like `O'Brien` is under-represented).
- Benign values are **Spanish-language** e-commerce inputs (domain/language shift).
- `severity` is now near-deterministic in `type` (carries little independent signal).
- `context_bucket` still has an `other` residual (long-tail SSRF protocols).
- No target responses / success labels here — those come from live DVWA runs.
