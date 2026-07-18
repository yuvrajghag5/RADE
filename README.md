# Offensive IT-Tester

An AI-assisted, **autonomous-but-bounded web-application vulnerability-testing agent** built
for the *Responsible AI & Data Ethics* course. Given an **authorized target URL**, the agent
orchestrates a set of tools — authorize, live-recon, payload-selection — to find injection
points (SQLi, XSS, CMDi, SSRF, CSRF), choose the payloads that would test them, and write an
LLM run report — logging every decision to a tamper-evident ledger. An optional open-source
LLM can drive the orchestration. (Firing + verification are the planned Layers 4-6.)

The offensive capability is the smaller part — the graded emphasis is on making it
**responsible**: authorization at the front, safety limits during, transparency throughout,
and accountability around the whole thing.

> **Scope & safety.** The agent only runs against targets on an explicit allowlist — in
> practice a deliberately vulnerable app we host ourselves (a self-owned Flask sandbox, or
> DVWA in a local Docker container) on a **loopback** address. It *cannot* be pointed at an
> arbitrary third-party site. This keeps the project within German law (§202a/b/c StGB),
> GDPR, and the EU AI Act.

---

## Project status

| Stage | State |
|---|---|
| Data engineering (repair → clean → benign corpus → final dataset) | ✅ **done** |
| Exploratory analysis (`preprocess/analysis.ipynb`) | ✅ **done** |
| Baseline model + fairness + risk (`models/baseline.ipynb`) | ✅ **done** |
| **Agent** — tool registry + decision policy + audit ledger (`src/agent/`) | ✅ **done** |
| **Layers 1–3: authorization → LIVE recon → payload selection** (`main.py`) | ✅ **done** |
| Live sandbox target (`sandbox/target_app.py`) + live crawler | ✅ **done** |
| **LLM orchestrator + Layer 7 report** — open-source `qwen2.5:7b` via Ollama | ✅ **done** (opt-in) |
| Layer 4–6: governance gate, execution, detection oracles | ◻ **planned** (design below) |

This README documents both what exists today and the target design it plugs into.

---

## 1. Conceptual architecture (seven layers)

Data flows down; results come back up. The two **safety gates** (authorization and
governance) are the responsible-AI control points.

```mermaid
flowchart TD
    URL([Target URL - authorized only])

    subgraph L1 [Layer 1 - Input and authorization]
        AUTH{{Authorization gate<br/>scope + consent check}}
    end
    subgraph L2 [Layer 2 - Reconnaissance]
        RECON[Find injection points<br/>forms, params, headers]
    end
    subgraph L3 [Layer 3 - Intelligence]
        SELECT[Payload selection<br/>from labelled dataset, stratified by technique]
    end
    subgraph L4 [Layer 4 - Governance and safety]
        GOV{{Governance gate<br/>severity + destructive + rate limits}}
    end
    subgraph L5 [Layer 5 - Execution]
        EXEC[Human review +<br/>fire payload<br/>capture response]
    end
    subgraph L6 [Layer 6 - Detection]
        DETECT[Oracle validation<br/>did the exploit succeed? + confidence]
    end
    subgraph L7 [Layer 7 - Reporting and audit]
        REPORT[/Report + audit log<br/>findings, redacted/]
    end

    URL --> AUTH
    AUTH -->|rejected| STOP([Out of scope - stop])
    AUTH -->|approved| RECON
    RECON --> SELECT
    SELECT --> GOV
    GOV -->|approved| EXEC
    EXEC --> DETECT
    DETECT -->|loops per payload| SELECT
    DETECT --> REPORT

    classDef gate fill:#FAEEDA,stroke:#BA7517,color:#633806;
    classDef stopnode fill:#FCEBEB,stroke:#A32D2D,color:#791F1F;
    class AUTH,GOV gate;
    class STOP stopnode;
```

**In plain language.** You hand the tool an authorized URL. The **authorization gate** asks
"am I allowed to touch this?" — if not, everything stops. **Reconnaissance** finds the doors
(input fields, parameters). The **intelligence layer** picks known payloads for each door
from the dataset (it never invents payloads). Before firing, the **governance gate** asks
"is it safe to send *this* one now?" — destructive payloads are held/escalated and the rate
is throttled. Approved payloads are **fired**, the response is read, and the **detection
layer** decides whether a real vulnerability triggered. That select → gate → fire → verify
cycle **loops** across every injection point. Finally the **report** stage collects confirmed
findings, strips real personal data, and writes a report plus a tamper-evident audit log.

---

## 2. How exploitation is verified (the detection oracles)

The dataset is only an *arsenal*; it contains no target responses, so **success cannot be
read from it** — it must be observed on the target. Every fired payload is validated against
a **benign baseline** by one of six **oracle** strategies, keyed on the payload's `type`.
Where possible we **plant a signal we control** (a nonce, a delay, an out-of-band token) so
detection is uniform and near-deterministic.

| Oracle | Proves success by | Used for |
|---|---|---|
| `timing` | response time ≫ baseline (planted delay) | blind-time, stacked-queries SQLi |
| `error_signature` | DB error the baseline didn't show | error-based SQLi |
| `marker_reflection` | a planted nonce is returned by the backend | union SQLi, CMDi echo |
| `differential` | true-vs-false condition responses diverge | tautology, boolean-blind SQLi |
| `browser_execution` | injected JS actually *runs* (headless browser) | reflected/stored XSS |
| `out_of_band` | your collaborator server receives a callback | SSRF, blind CMDi |
| `state_change`\* | forged cross-origin request changes state w/o token | CSRF (semi-manual) |

Each payload already carries its `oracle` label in the dataset. Findings are reported with a
**confidence tier** (high = planted signal returned; medium = timing/differential, confirmed
by repetition; low = unconfirmed → flagged for manual review, never auto-claimed).

---

## 3. Project architecture (folders & files)

```
RADE/
├── README.md                      # this file
├── requirements.txt
├── LICENSE
│
├── main.py                        # ✅ AGENT driver: builds the tool registry, runs the decide-act loop
│
├── sandbox/                       # ✅ self-owned LIVE target (loopback-only Flask app)
│   └── target_app.py              #    vulnerable-by-design; the thing recon crawls
│
├── config/                        # ✅ paths + safety rules as DATA
│   ├── paths.py                   #    canonical project paths (ROOT/DATA/RAW_DIR/CLEAN/PROCESSED)
│   ├── target_allowlist.yaml      #    the scope firewall — which hosts may be scanned (sandbox only)
│   ├── targets/dvwa.yaml          #    DVWA crawl config (login, seed paths) + offline profile
│   └── targets/pyapp.yaml         #    self-owned Flask sandbox crawl profile (no auth)
│
├── data/
│   ├── raw/                       # ✅ untouched sources
│   │   ├── WEB_APPLICATION_PAYLOADS.jsonl   # Kaggle attack payloads (needs repair)
│   │   └── csic_2010_benign.csv             # benign extract from HTTP DATASET CSIC 2010 (GPL-3.0)
│   ├── cleaned/                   # ✅ cleaned + execution-ready outputs
│   │   ├── payloads_clean.jsonl / .csv      # 455 repaired, deduped attack payloads
│   │   └── dataset_final.jsonl / .csv       # 2,455-row attack+benign dataset (the deliverable)
│   └── processed/                 # ✅ analysis artifacts
│       ├── payloads_bucketed.jsonl          # attack payloads + context_bucket (from analysis.ipynb)
│       ├── dataset_final.jsonl / .csv       # mirror of the final dataset
│       └── DATA_CARD.md                     # provenance, schema, severity policy, limitations
│
├── preprocess/                    # ✅ the data pipeline
│   ├── preprocess.py              #    STAGE 1-2: raw-text repair + pandas cleaning
│   ├── benign_corpus.py           #    loads/maps/samples benign inputs from CSIC 2010
│   ├── build_dataset.py           #    MASTER: repair → clean → bucket → severity → oracle → merge
│   └── analysis.ipynb             #    EDA: class/severity/context, bucketing, destructive scan
│
├── models/                        # ✅ baseline model
│   ├── baseline.ipynb             #    trains + evaluates + saves; ends with fairness & risk
│   ├── clf_binary.pkl             #    attack-vs-benign detector
│   └── clf_attack_class.pkl       #    5-way attack_class router
│
└── src/                           # the scanner (maps onto layers 1-7)
    ├── agent/                     # ✅ the AGENT — orchestrates the tools (not a fixed pipeline)
    │   ├── tools.py               #    Tool base + ToolRegistry (Anthropic-style specs, LLM-ready)
    │   ├── layer_tools.py         #    L1-3 wrapped as tools: authorize / recon / select_payloads
    │   ├── policy.py              #    the swappable "brain": DeterministicPolicy + LLMPolicy
    │   ├── llm.py                 #    open-source LLM client (qwen2.5:7b via Ollama)
    │   ├── agent.py               #    perceive → decide → act loop + working memory (AgentState)
    │   └── audit.py               #    hash-chained, tamper-evident run ledger
    ├── authorization/authorize.py # ✅ L1 — allowlist / scope firewall
    ├── recon/recon.py             # ✅ L2 — LIVE injection-point discovery (crawls the target)
    ├── intelligence/select.py     # ✅ L3 — payload selection from the arsenal
    ├── reporting/report.py        # ✅ L7 — LLM-generated run report (Art. 50 labelled)
    ├── governance/                # ◻ L4 — severity / destructive holds, rate limits
    ├── execution/                 # ◻ L5 — fire payloads, capture responses
    └── detection/                 # ◻ L6 — the six confirm() oracles
```

**Why an agent, not a pipeline.** `main.py` does not call the layers in a fixed order — it
builds a **tool registry** (`authorize`, `recon`, `select_payloads`) and hands it to an
**Agent** that runs a *perceive → decide → act* loop: a **policy** chooses each next tool from
the agent's observed **state**, and branches — a scope rejection or a recon failure ends the
run. The policy is a swappable interface with **two implementations**: `DeterministicPolicy`
(default — reproducible, safe) and `LLMPolicy` (opt-in `--llm`), where an **open-source model
(`qwen2.5:7b` via Ollama)** is given the tool specs + state and chooses the next tool by
tool-calling. The LLM is **bounded**: it is only ever offered the currently-valid tools, scope
is still enforced by the `authorize` tool, structured args are supplied by the policy, and any
error/invalid choice **falls back to the deterministic policy** — so the model can never drive
the agent into an unsafe step (a direct answer to OWASP LLM08, excessive agency). Every decision
+ result is appended to a **tamper-evident audit ledger** (`audit/audit.jsonl`, hash-chained;
`AuditLog.verify()` detects any edit).

**Two deliberate choices carried from the design:** `config/` holds safety rules as readable
*data* (allowlist, crawl scope) so an examiner can see the scope firewall at a glance; and
`audit/` is separate from `reporting/` because reports are for the user while audit logs are
the tamper-evident record of what the agent actually did.

---

## 4. The dataset

`data/cleaned/dataset_final.jsonl` — **2,455 rows**, one input string per row.

| Half | Rows | Source |
|---|---|---|
| attack | 455 | Kaggle `WEB_APPLICATION_PAYLOADS` (repaired, deduped from 500) |
| benign | 2,000 | **HTTP DATASET CSIC 2010** normal traffic (sampled, seed 42) |

**15-field schema:**

| field | meaning |
|---|---|
| `id` · `label` · `attack_class` · `type` | identity + the two model targets (attack/benign, 5-way) |
| `payload` | the raw string to send (the **only** model feature) |
| `context` · `context_bucket` | injection point (free-text + normalised to 14 buckets) |
| `severity` · `severity_original` · `severity_reason` | **recomputed** severity + audit trail |
| `is_destructive` · `destructive_flags` | governance-gate hold signals |
| `oracle` | which detection oracle validates this payload |
| `description` · `example` | human context |

### Data quality work (why the pipeline exists)
The raw Kaggle file was **not valid JSON**: 45 non-breaking spaces (some breaking parsing),
a missing comma, a bad escape, 1 empty payload, and 44 duplicate payloads. `preprocess.py`
repairs and de-dupes it. Severity labels were **internally inconsistent** (reflected == stored
XSS, all blind SQLi == medium, CMDi split across three levels), so `build_dataset.py`
**recomputes severity** from a documented `(class, technique)` policy plus payload-content
overrides — **283 / 455 labels changed**, with `severity_original` + `severity_reason` kept
for auditability. Full details in [`data/processed/DATA_CARD.md`](data/processed/DATA_CARD.md).

---

## 5. Baseline model

`models/baseline.ipynb` — **char n-gram TF-IDF + Logistic Regression**, two tasks, with
leakage guards (payload-text-only features, exact-duplicate removal, stratified hold-out,
`class_weight="balanced"`, `DummyClassifier` reference).

| Task | What it does | Macro-F1 | Dummy ref |
|---|---|---|---|
| A — attack vs benign | input-side "is this an attack?" detector | **0.986** | 0.449 |
| B — attack_class (5-way) | router → picks the detection oracle | **0.991** | 0.072 |

**Honest read:** scores are high because the data is easy (clean benign vs syntactically loud
payloads) — treat them as an upper bound. The value is in the **5 false negatives** (SSRF/CMDi
with exotic schemes like `tel:`/`magnet:`, short Windows commands, and encoded payloads) — the
model breaks exactly where an attacker would push. It is kept **advisory, not authoritative**:
the live loop routes by the dataset `type`, so a model error can never silently drop a real
payload. The notebook ends with the model's own **fairness evaluation** and **risk
assessment** (NIST Map → Measure → Manage).

---

## 6. The agent (Layers 1–3)

`main.py` builds a **tool registry** (`authorize`, `recon`, `select_payloads`) and runs an
**agent** over it — a *perceive → decide → act* loop whose policy picks each next tool from the
agent's state and **branches** on the result (a scope rejection or a recon failure ends the
run). It **stops before firing a payload** — recon makes ordinary read requests (log in, load
pages) to crawl the target, but no *attack* payload is ever sent. It prints the payloads the
agent *would* fire, and appends every decision to a tamper-evident ledger (`audit/audit.jsonl`).
See §3 ("Why an agent, not a pipeline") for the architecture.

```bash
# 1. start the self-owned live sandbox (loopback only, no Docker needed)
python sandbox/target_app.py                 # serves http://127.0.0.1:5000

# 2. in another terminal, run the agent against it
python main.py http://127.0.0.1:5000              # deterministic brain
python main.py http://127.0.0.1:5000 --llm        # LLM orchestrator (qwen2.5:7b via Ollama)
python main.py http://127.0.0.1:5000 --llm --report   # + Layer-7 LLM report into reports/
python main.py http://example.com                 # authorization gate REJECTS (out of scope)
python main.py http://127.0.0.1:8080              # DVWA (needs DVWA running in Docker)
```

The `--llm` / `--report` paths need Ollama running with `qwen2.5:7b` pulled
(`ollama pull qwen2.5:7b`); model + endpoint are set in `config/llm.yaml`. If Ollama is
unreachable, `--llm` falls back to the deterministic policy.

**What each layer does**
1. **Authorization** — approves the URL only if it's an allowlisted **loopback** sandbox
   host; `example.com` and wrong ports are rejected with a reason (the scope firewall).
2. **Recon (live)** — actually connects to the target, crawls its pages, and parses every
   `<form>` field and URL parameter with BeautifulSoup to **discover** injection points. For
   DVWA it logs in (`admin`/`password`) and sets security to `low` first; for the Flask
   sandbox it crawls unauthenticated. It **hard-fails** if the target is unreachable — no
   silent fallback. (Crawl settings live in `config/targets/*.yaml` as data.)
3. **Selection** — picks payloads from `dataset_final` per injection point (by attack class
   + context bucket), **stratified by technique**: it groups candidates by `type` and takes
   the best `k_per_type` (=2) of *every* technique, so no technique is skipped. Each is tagged
   with the `oracle` that will verify it.

**Sample output** (trimmed, Flask sandbox):
```
[LAYER 3] PAYLOAD SELECTION
  ▶ sqli  (GET id, bucket=url_param)  → 4 payloads
      [sqli-016 ] sqli/blind-time    high  oracle=timing          "' OR SLEEP(5)--"
      [sqli-004 ] sqli/error-based   high  oracle=error_signature "' AND 1=CONVERT(int,@@version)--"
SELECTED 25 payloads across 6 injection points  by class {sqli:11, xss:6, csrf:4, cmdi:2, ssrf:2}
  technique coverage (stratified by type):
      sqli  → blind-time, boolean-blind, error-based, tautology, union

[AUDIT] 12 events logged · chain OK — chain intact
        ledger: audit/audit.jsonl
```
(Against live DVWA the crawl finds 15 injection points and coverage reaches the full 6/6 — see below.)

**Responsibility analysis of this pipeline** — selection now **stratifies by technique**, so
SQLi technique coverage rose **3/6 → 5/6** on the offline profile (`union` & `error-based` now
fired). The last gap, `stacked-queries`, needed a `form_field` injection point that the
hand-written profile lacked — a *recon* blind spot, not a selection bias. **Live recon proves
this out:** crawling real DVWA discovers 15 injection points (vs 6 profiled), including
`form_field` endpoints, which lifts coverage to the **full 6/6** — better recon closed the gap
that better selection alone could not. Documented with before/after numbers in
[`docs/fairness_evaluation.md`](docs/fairness_evaluation.md) and
[`docs/risk_assessment.md`](docs/risk_assessment.md). (The baseline *model's* fairness/risk
is separate, inside `models/baseline.ipynb`.)

---

## 7. Reproduce

```bash
# 1. rebuild the final dataset (writes to data/cleaned and data/processed)
python -m preprocess.build_dataset

# 2. train + evaluate + save the baseline models, then read fairness & risk
#    open models/baseline.ipynb and run all cells (use the .venv kernel)

# 3. run the AGENT (Layers 1-3) against a live target
python sandbox/target_app.py                # terminal A: start the self-owned sandbox (:5000)
python main.py http://127.0.0.1:5000        # terminal B: agent live-crawls + selects payloads
python main.py http://example.com           # authorization gate rejects (out of scope)

#    optional DVWA target instead of the Flask sandbox (needs Docker):
#    docker run --rm -it -p 8080:80 vulnerables/web-dvwa
python main.py http://127.0.0.1:8080

# 4. verify the tamper-evident audit ledger
python -c "from src.agent import AuditLog; from config.paths import ROOT; print(AuditLog.verify(ROOT/'audit'/'audit.jsonl'))"
```

The notebook adds the project root to `sys.path` automatically, so it runs whether the kernel
starts in `models/` or the repo root.

**Core dependencies:** `pandas`, `scikit-learn`, `matplotlib`, `joblib`, `jupyter` (data +
model); `requests`, `beautifulsoup4`, `PyYAML` (live recon + config); `flask` (the self-owned
sandbox). See `requirements.txt`. The optional `--llm` / `--report` features need **Ollama**
(external, running `qwen2.5:7b`) — no extra Python packages, since it's called over HTTP.

---

## 8. Regulatory & ethics frameworks

| Framework | Relevance |
|---|---|
| **EU AI Act** (Reg. 2024/1689) | Not a prohibited practice (Art. 5) and not high-risk (Art. 6/Annex III) — a sandboxed academic scanner matches no Annex III category. One live duty: Art. 50 transparency — **✅ implemented**: the Layer-7 LLM report carries an "AI-generated" label. |
| **GDPR** (Reg. 2016/679) | Art. 5(1)(c) data minimisation — training data is payload strings + benign inputs only; **CSIC 2010 is auto-generated, so no real PII**. Purpose (Art. 5(1)(b)) and storage limitation (Art. 5(1)(e)) documented. |
| **StGB** §202a/b/c, §303a/b | Data espionage / interception / hacking-tools / data alteration / sabotage — all neutralised by the **self-owned sandbox + enforced target-scoping + non-destructive default mode + documented authorization** (the central lawfulness argument). |
| **OWASP Top 10** (A03 Injection) + **LLM Top 10** (LLM01/LLM08) | Grounds *what* is tested (injection classes) and the agent-safety concerns (prompt injection, excessive agency → bounded agency, validated inputs). |
| **ISO/IEC 42001** · **NIST AI RMF** | Borrowed structure for the governance layer, risk log, and model card (Govern / Map / Measure / Manage). |

---

## 9. Roadmap
1. **Fairer selection** — ✅ **done**: selection stratifies by `type` (`k_per_type=2`) so
   `union` / `error-based` SQLi are no longer skipped (3/6 → 5/6); live recon then closes the
   last gap (`stacked-queries`) to the **full 6/6** on DVWA.
2. **Live recon** — ✅ **done**: `requests` + BeautifulSoup crawler logs into DVWA (or crawls
   the Flask sandbox unauthenticated) and discovers injection points live; **hard-fails** if
   the target is down (no silent profile fallback).
3. **The agent + LLM** — ✅ **done**: tool registry + deterministic policy + audit ledger, plus
   an opt-in **`LLMPolicy`** (open-source `qwen2.5:7b` via Ollama) that orchestrates the tools
   by tool-calling, bounded and with deterministic fallback.
4. **Reporting (Layer 7)** — ✅ **done**: LLM-generated run report (`--report`), framed as
   candidate/planned (not confirmed) with an EU AI Act Art. 50 label + a deterministic facts block.
5. **Governance gate (Layer 4)** — hold `is_destructive`/critical payloads for review and
   throttle rate, as YAML rules; **required before execution is enabled**.
6. **Execution + detection (Layers 5–6)** — fire payloads at the sandbox and implement the six
   `confirm()` oracles; add an adversarial eval set to measure evasion.
