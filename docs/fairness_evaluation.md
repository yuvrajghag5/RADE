# Fairness Evaluation — Baseline Model

**What "fairness" means here.** Not demographic fairness — this system has no people
as subjects. Fairness = **equal detection quality across attack classes** (and across
the attack/benign labels). A class the model detects worse is a class whose attacks are
systematically **under-tested** and more likely to slip through — a real coverage harm.

Model: char n-gram TF-IDF + Logistic Regression (`class_weight="balanced"`), evaluated
on a 25% stratified hold-out of `dataset_final.jsonl` (exact-duplicate payloads removed).
Reference: `DummyClassifier` macro-F1 = 0.449 (binary) / 0.072 (5-way) — the model
clearly learns signal, not the majority class.

## Task A — attack vs benign
| class | precision | recall | F1 | support |
|---|---|---|---|---|
| attack | 1.000 | **0.956** | 0.978 | 114 |
| benign | 0.990 | 1.000 | 0.995 | 500 |

**Asymmetry (the key finding):** the model makes **0 false positives** (never flags a
benign input) but **5 false negatives** (4.4% of attacks pass as benign). For a security
tool the error costs are unequal: a **missed attack (FN) is worse** than a false alarm.
The model is tuned toward the *user-friendly* direction (don't annoy) at the expense of
the *security* direction (don't miss) — a bias worth stating explicitly.

**The 5 missed attacks** (concentrated in specific classes):
| class/type | payload | why it evades |
|---|---|---|
| ssrf/SSRF | `tel:+1234567890` | looks identical to a benign phone number |
| ssrf/SSRF | `magnet:?xt=urn:btih:…` | exotic URI scheme, rare in training |
| cmdi/Command Injection | `&& ipconfig` | short, no classic shell metacharacters |
| cmdi/Command Injection | `& reg query HKLM\Software` | Windows registry, unlike Unix-flavoured training |
| csrf/CSRF | `<script>eval(unescape('%66%6f…'))` | hex-encoded to hide the payload |

## Task B — attack_class (5-way router)
| class | F1 | support |
|---|---|---|
| csrf / sqli / xss | 1.000 | 24 / 22 / 25 |
| cmdi | 0.978 | 22 |
| ssrf | 0.976 | 21 |

Only one confusion: 1 `ssrf` → `cmdi`. **SSRF and CMDi are the weakest classes in *both*
tasks** → these two families are the fairness/coverage gap: their attacks are the ones
most likely to be mis-routed or missed.

## Honest caveats
- **Metrics are optimistic.** Benign (CSIC 2010) is clean real traffic with few
  payload-like characters, so the classes are highly separable. Production benign
  (a user literally typing `O'Brien` or `1=1`) would push precision down.
- **Small-support classes can't be fairly judged.** `error-based` SQLi has only 4 rows
  total; any per-technique metric on it is noise. Reported at class level, not technique.
- The evasion cases above are the honest edge: **the model degrades exactly where
  attackers would push** (encoding, exotic schemes, OS variety).
