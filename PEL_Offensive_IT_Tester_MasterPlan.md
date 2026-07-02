# Responsible AI & Data Ethics — Project Master Plan
## Topic: Offensive IT-Tester (Web-Application Payload Agent)

**Team size:** 2 · **Final code delivery:** 20 Jul 2026 · **Presentation:** 24 Jul 2026
**Strategy:** finish the substance in 3 weeks, keep Week 4 as a buffer for debugging, tests, and the pitch.

---

## 0. The one idea that wins this project

You are **not** being graded on how good a hacking tool you can build. You are being graded on
**Programming, Performance, Responsibility, and Presentation** — and in a course called *Responsible
AI & Data Ethics*, "Responsibility" is where the marks (and the "best model wins" competition) are
actually decided. Every rival group can throw payloads at a target. Few will build the *governance
shell* around it.

So the whole project is framed as: **"An offensive testing agent that is safe by construction."**

Two consequences that drive every decision below:

1. **The agent only ever attacks a target you own** — a deliberately-vulnerable app running on
   `localhost` (DVWA, bWAPP, or a tiny custom Flask app). It has a hard-coded **scope allowlist** and
   physically refuses any other host. This is simultaneously your responsible-AI story *and* your legal
   requirement (see §4). Say this in every status meeting.
2. **The "intelligence" is a real ML model, not just a for-loop.** The dataset is a bag of labelled
   payloads; the machine-learning contribution is a **payload classifier** that (a) categorises attack
   type and (b) predicts which payloads are worth firing in a given context. That gives you something
   concrete to explain with XAI, test for fairness, and write a model card about — which is exactly
   what the "Must-Haves" slide demands.

---

## 1. WEEK 1 — GOAL 1: Data Analysis

### 1.1 What the dataset actually is (verify on load, but expect this)

The Kaggle set (`cyberprince/web-application-payloads-dataset`) is a **small, curated** collection —
roughly **300–400 rows** in a `.jsonl` file, not a big corpus. Each row is one payload with rich
metadata. Expected fields:

| Field | Meaning | Use in project |
|-------|---------|----------------|
| `id` | unique payload id | audit logging / traceability |
| `payload` | the raw attack string | model input (text) |
| `type` | SQLi / XSS / SSRF / CMDi | **target label** (multi-class) |
| `context` | where it applies (URL param, header, form field…) | drives agent's payload *selection* |
| `severity` | risk rating | risk analysis + agent prioritisation |
| `description` / `example` | human note + usage | documentation, model card |

Composition is roughly balanced: **~100 payloads each** for SQLi, XSS, SSRF, and CMDi.

### 1.2 The four findings that shape the entire project

Write these up — they *are* Goal 2 ("derive a plan from your analysis"):

1. **The data is tiny.** ~300 rows will overfit any heavy model instantly. → Use **character-level
   TF-IDF + a classical model** (Logistic Regression / Linear SVM / XGBoost) as the baseline, not a
   deep net. Deep nets here are a red flag, not a flex. Optionally augment via label-preserving
   mutations (case-swapping, comment insertion `/**/`, URL/hex encoding) — which *also* becomes your
   robustness test later.
2. **There is no "benign" class.** Every row is an attack. A pure detector needs negatives, so either
   (a) frame the model as a **multi-class attack-type classifier** (clean, honest, matches the data),
   or (b) add a benign class from a public source (normal SQL queries, HTTP CSIC 2010) and build a
   **malicious-vs-benign + type** model. Recommendation: do (a) first as baseline, add (b) if time
   allows. State this choice explicitly.
3. **The assignment says SQLi/XSS/CMDi but the data also contains SSRF.** Decide your scope: keep all
   4 classes (richer) or drop SSRF to match the brief. Document the decision — noticing this mismatch
   is exactly the "profound data analysis" the rubric rewards.
4. **Rich `context`/`severity` metadata is a gift.** It lets the agent be *selective* ("this is a URL
   parameter → prefer reflected-XSS and error-based-SQLi payloads") instead of blindly spraying all
   300. That selectivity is both smarter engineering and more responsible (minimises noise/traffic).

### 1.3 The EDA to actually run (drop into your notebook)

```python
import json, pandas as pd, matplotlib.pyplot as plt

# 1. Load & inspect schema (confirm the fields above!)
rows = [json.loads(l) for l in open("WEB_APPLICATION_PAYLOADS.jsonl")]
df = pd.DataFrame(rows)
print(df.shape); print(df.columns.tolist()); df.head()

# 2. Class balance  ->  bar chart
df["type"].value_counts().plot.bar(title="Payloads per attack type")

# 3. Duplicates & leakage (critical for honest metrics)
print("exact dupes:", df["payload"].duplicated().sum())

# 4. Payload length distribution per class (a strong, cheap feature)
df["len"] = df["payload"].str.len()
df.groupby("type")["len"].describe()

# 5. Character / token profile: which symbols separate classes?
for c in ["<", ">", "'", "--", "|", ";", "$(", "http", "UNION", "SELECT"]:
    df[f"has_{c}"] = df["payload"].str.contains(re.escape(c), case=False)
# crosstab has_* vs type -> this is your first "why the model works" evidence

# 6. Severity & context distributions -> feed the agent's selection logic
df["severity"].value_counts(); df["context"].value_counts()
```

**Deliverable for Goal 1:** a notebook section with the class-balance chart, duplicate check,
length-by-class table, a character-signature crosstab, and the 4 written findings above.

---

## 2. WEEK 1 — GOAL 2: The Plan (derived from the analysis)

Because the data is small, labelled by type, and attack-only, the plan is:

**Build a two-part system.**

- **Part A — Payload Classifier (the ML core).** Input = payload string. Output = attack type +
  confidence. Char-level TF-IDF → Logistic Regression / Linear SVM baseline, then XGBoost. This is
  what you explain (XAI), test (fairness/robustness), and model-card.
- **Part B — Offensive Agent (the orchestration).** Given a *target context* from **your own
  sandboxed app**, the agent: reads the context → uses the classifier + `context`/`severity` metadata
  to **select** a small ranked set of payloads → sends them to the local target → inspects the
  response to **verify** exploitation (e.g. SQL error string echoed, `<script>` reflected unescaped,
  command output present) → logs everything → produces a report.

Wrapped around both: a **governance layer** (scope allowlist, human confirmation, rate limit, kill
switch, immutable audit log). This layer is the differentiator.

Success criteria to state: classifier macro-F1 ≥ ~0.90 on a deduplicated held-out split; agent
correctly confirms ≥ N known-vulnerable endpoints on the sandbox with zero out-of-scope requests.

---

## 3. WEEK 1 — GOAL 3: Possible Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │                  GOVERNANCE / GUARDRAILS               │
                    │  scope allowlist · human-in-loop confirm · rate-limit  │
                    │  kill-switch · immutable audit log · config as code    │
                    └──────────────────────────────────────────────────────┘
                                            │ (wraps everything)
  ┌────────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────────┐
  │  DATA LAYER│ -> │ MODEL LAYER   │ -> │ AGENT LAYER  │ -> │  SANDBOXED TARGET │
  │ payloads   │    │ TF-IDF +      │    │ select →     │    │  DVWA / bWAPP /   │
  │ clean/dedup│    │ classifier    │    │ deploy →     │    │  local Flask app  │
  │ features   │    │ (+confidence) │    │ verify → log │    │  (localhost ONLY) │
  └────────────┘    └───────────────┘    └──────────────┘    └──────────────────┘
                            │                    │
                            └──── XAI (SHAP) ────┘ ──► REPORTING LAYER
                                                        results + explanations
                                                        + Pseudo-Model-Card
```

**Layer notes**

- **Data layer:** load, dedup, feature-extract; keep raw payloads out of logs where possible.
- **Model layer:** classifier + calibrated confidence; SHAP/feature-weights hook for explainability.
- **Agent layer:** a simple, auditable state machine (`select → deploy → verify → log`). Keep it
  deterministic and inspectable; if you use an LLM anywhere, it *suggests*, a rule checks, a human
  confirms — never autonomous fire.
- **Sandboxed target:** ships **with** the repo (docker-compose for DVWA, or a 50-line vulnerable
  Flask app you write). Reproducibility requirement + the reason the whole thing is legal.
- **Governance layer (grade-critical):**
  - **Scope allowlist:** hard-coded `ALLOWED_HOSTS = {"127.0.0.1", "localhost"}`; every request is
    checked and refused otherwise, with the refusal logged.
  - **Human-in-the-loop:** agent prints its planned actions and waits for explicit confirmation before
    any "attack" run (dry-run mode by default).
  - **Rate limiting + kill switch:** bounded requests/sec; single flag halts everything.
  - **Audit log:** append-only JSON of every decision (payload id, target, verdict, timestamp) →
    traceability, and your evidence of transparency.

**Recommended stack:** Python, `scikit-learn` + `xgboost`, `requests`, `pytest` + `coverage` (for the
80% requirement), `shap`, plain `dataclasses`/`pydantic` for config. Repo layout:

```
repo/
  data/            notebooks/01_eda.ipynb ... 04_agent_demo.ipynb
  src/  models.py  agent.py  guardrails.py  target/(flask app)
  tests/           test_model.py test_guardrails.py test_agent.py
  MODEL_CARD.md    README.md   docker-compose.yml
```

---

## 4. WEEK 1 — GOAL 4: Regulatory Analysis

This is a security-*offensive* tool, so your regulatory analysis is richer than the other groups' —
lean into it. Four bodies of rules apply.

### 4.1 EU AI Act (Reg. 2024/1689)
- **Status (as of mid-2026):** in force since 1 Aug 2024, phased. Prohibited-practice and AI-literacy
  rules apply since Feb 2025; GPAI-model obligations since Aug 2025. The **May 2026 "Digital Omnibus"**
  political agreement **pushed the Annex III high-risk obligations to 2 Dec 2027** (and embedded-product
  high-risk to Aug 2028). Cite this — it shows current awareness.
- **Your classification:** an offensive security testing tool is **not** in the Annex III high-risk
  list (which covers biometrics, credit scoring, employment, law enforcement, etc.), so it is most
  likely **limited/minimal-risk**. But note the tension: an *autonomous* agent that acts on systems is
  a governance concern, and **cybersecurity/robustness is an explicit AI-Act theme**. Argue that you
  voluntarily apply high-risk-style controls (risk management, logging, human oversight, transparency)
  even though not strictly required — that is the responsible posture.
- **If you use an LLM** for payload generation/agent reasoning: you become a **deployer of a GPAI
  model** and inherit transparency duties (users must know AI is involved; AI-generated content
  considerations). Prefer the classical classifier to keep this simple; if you add an LLM, disclose it.

### 4.2 GDPR
- Payloads and HTTP logs can incidentally contain **personal data** (usernames, session tokens, IPs).
  → minimise, pseudonymise, don't persist real PII; your sandbox uses only synthetic data. State a
  one-line **data-minimisation + purpose-limitation** justification.

### 4.3 German criminal law — the decisive constraint
German **StGB §202a/§202b** (unlawful access to / interception of data) and **§202c** (the
"Hackerparagraph" — producing or distributing tools *intended* to commit those offences), plus
**§303a/§303b** (data alteration / computer sabotage), are the real boundary. The settled position:
**penetration testing is legal only with the authorisation/consent of the target's owner**, and tools
used strictly within that agreed scope — and **not distributed beyond it** — are not punishable.
Acting "on your own initiative" against systems you don't own is where liability starts.

→ Your mitigations map *directly* onto these statutes and you should say so explicitly:
- attacks **only against a target you own** (the bundled sandbox) = authorisation is inherent;
- **scope allowlist** enforces this in code = no unlawful access (§202a/b);
- **read-only verification / no destructive payloads by default** = no data alteration (§303a/b);
- tool stays in the repo for grading, **not published as a weaponised scanner** = mindful of §202c.

### 4.4 Standards, norms & course frameworks (ties back to lectures)
- **ISO/IEC 42001** (AI management system) and **NIST AI RMF** — cite as the governance frameworks you
  loosely follow.
- **OWASP** (Top 10, WSTG) — the domain standard for what SQLi/XSS/CMDi *are* and how to test them.
- **Value-Based Engineering (Spiekermann)** from your slides — apply Principle 6 (respect for regional
  laws), 8 (transparency of the value mission), and 10 (risk-analysis-driven requirements) directly.
- **IBM's five pillars** (Explainability, Fairness, Robustness, Transparency, Privacy) — use them as
  the section headings of your final responsibility write-up so it maps 1:1 to the course.

---

## 5. The 3-Week Compressed Master Plan

Course goals are 4 weeks; you compress into 3 and keep **Week 4 as pure buffer** (debug, coverage,
pitch). Each week lists what to build **and** your status-meeting script (meetings are individually
graded — missing one = fail, so prep them).

### WEEK 1 (now → ~08 Jul): Analyse, Plan, Architect, Regulate
Course goals 1–4, all delivered this week (this document is your draft).
- [ ] Load data, run the EDA in §1.3, write the 4 findings.
- [ ] Lock the plan (§2) and architecture diagram (§3).
- [ ] Write the regulatory analysis (§4) into the notebook.
- [ ] Stand up the repo skeleton + the sandboxed target app (do this early — everything depends on it).
- **Status-meeting script:** "We analysed the ~300-payload set; key findings are small size, no benign
  class, and an SSRF/brief mismatch, which pushed us to a char-TF-IDF multi-class classifier plus a
  scope-locked agent against a local DVWA sandbox. Architecture and a full EU-AI-Act/GDPR/§202c
  regulatory analysis are done. Challenge: dataset size. Next: baseline model + risk analysis."

### WEEK 2 (~09 → ~15 Jul): Baseline model, Risk analysis, Fairness
Course Week-2 goals.
- [ ] Train baseline classifier (LogReg/SVM → XGBoost), report deduplicated macro-F1 / confusion matrix.
- [ ] Wire the agent's select→deploy→verify loop against the sandbox (dry-run first).
- [ ] **Risk analysis:** misuse, dual-use, adversarial evasion (WAF-bypass/obfuscation), false
  positives/negatives, out-of-scope firing, log leakage — and a treatment for each.
- [ ] **Fairness — reframed for this domain** (there's no protected attribute): measure **per-class
  performance parity** (is SSRF recall as good as SQLi?), **robustness parity** across encodings/
  obfuscations, and the **false-positive burden** per class. This is the clever move most groups miss.
- **Status-meeting script:** "Baseline hits X macro-F1; agent confirms N sandbox vulns with zero
  out-of-scope requests. Risk register covers evasion + misuse with mitigations. Fairness measured as
  cross-class parity. Challenge: <e.g. XSS recall>. Next: XAI + automated tests + coverage."

### WEEK 3 (~16 → ~19 Jul): XAI, Tests, 80% coverage, Model card — then FREEZE for 20 Jul delivery
Course Week-3 goals. **Code delivery is 20 Jul**, so finish here.
- [ ] **XAI:** SHAP (or LinearSVC coefficients) to show which characters/tokens drive each prediction
      (e.g. `<script`, `UNION SELECT`, `;$(`). One clear figure per class.
- [ ] **Tests + coverage:** `pytest` covering model, **guardrails (most important)**, and agent;
      hit **≥80%** with `coverage`. Include a test that proves an out-of-scope host is *refused*.
- [ ] **Pseudo-Model-Card** (`MODEL_CARD.md`): intended use, data, metrics, limitations, biases,
      attack surface, out-of-scope uses. Required by the Must-Haves slide.
- [ ] Clean code pass + README; **freeze and submit on 20 Jul.**
- **Status-meeting script:** "SHAP confirms the model keys on the expected attack signatures; test
  suite at 8X% coverage including a guardrail test that blocks non-localhost targets; model card done.
  Delivering on the 20th. Next week is polish + pitch."

### WEEK 4 (20 → 24 Jul): BUFFER — debug, harden, pitch
Course Week-4 goals + your safety margin.
- [ ] Fix anything the freeze exposed; raise coverage; tighten docs.
- [ ] **Top-management sales pitch** (per the rubric): lead with *"safe-by-construction offensive
      testing"* — the responsibility layer is the selling point, not the exploit count.
- [ ] Rehearse the **15 min talk + 5 min deep-questions**. Pre-write answers to likely questions:
      *"Isn't this just a hacking tool?"* → scope allowlist + §202c + sandbox; *"where's the ML?"* →
      classifier + XAI; *"how do you know it's fair/robust?"* → cross-class parity + mutation tests.

---

## 6. Must-Haves compliance checklist (from the course slide)

- [x] Profound data analysis of provided data — §1
- [x] Use additional info if found — benign corpus (CSIC 2010) option, §1.2
- [x] Risk assessment with example treatments — Week 2
- [x] An XAI method to understand the model — SHAP, Week 3
- [x] Pseudo-Model-Card at the end of the notebook — Week 3
- [x] Limitations, biases, attacks, restrictions — model card + risk register
- [x] Clean code & documentation — repo layout + README, ongoing
- [x] Everything runnable in a Jupyter notebook — notebooks 01–04 orchestrate `src/`

---

## 7. Immediate next actions (this week, in order)

1. Download the `.jsonl`, run §1.3, confirm the real schema, screenshot the class-balance chart.
2. `git init` the repo skeleton (§3) and get the **sandboxed Flask/DVWA target running on localhost**.
3. Paste §4 into your notebook as the regulatory section (adjust once you confirm any LLM use).
4. Bring the §5 Week-1 status script to your first meeting.

> Reminder on accuracy: EU AI Act dates and the §202c interpretation above are current as of mid-2026;
> re-verify the AI Act timeline near your presentation, since the Digital Omnibus was still completing
> formal adoption.
