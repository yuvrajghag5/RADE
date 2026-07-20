# Run Guide — Offensive IT-Tester

How to set up and run the agent on **macOS** and **Windows**. The agent walks all seven layers
against a self-owned sandbox — **authorize → recon → select → governance gate → fire → confirm
exploits → report** — logging every decision to a tamper-evident ledger, and (optionally) uses
a local open-source LLM to prioritise targets and to write the report.

> You run two things in two terminals: **(1)** a sandbox target app, and **(2)** the agent
> pointed at it.

---

## 0. Prerequisites

| Needed | For | Notes |
|---|---|---|
| **Python 3.11+** | everything | `python --version` (Windows) / `python3 --version` (macOS) |
| **Docker Desktop** | *optional* — the DVWA sandbox | only if you use Option B in step 2 |
| **HuggingFace model** | *optional* — the `--report` feature | auto-downloads on first use (step 4); no account/key |

The built-in Flask sandbox (Option A) needs **none** of the optional items.

---

## 1. One-time setup (create a virtual environment + install dependencies)

Run these once, from the project root (the `RADE/` folder).

### Windows (PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
> If `Activate.ps1` is blocked ("running scripts is disabled"), run this once and retry:
> `Set-ExecutionPolicy -Scope Process RemoteSigned`

### macOS (Terminal)
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Once activated, your prompt shows `(.venv)` and you can just type `python`.
**Re-activate the venv in every new terminal** (the `Activate.ps1` / `source` line above).

---

## 2. Start a sandbox target — pick ONE

The agent will only ever touch a **loopback** address on its allowlist, so you must run a
target locally first. Leave the chosen target **running in its own terminal**.

### Option A — Built-in Flask sandbox (easiest, no Docker) ✅ recommended to start

Works identically on macOS and Windows:
```bash
python sandbox/target_app.py
```
Serves **http://127.0.0.1:5000**. It's a small, deliberately vulnerable, loopback-only app.
Leave it running; open a **second** terminal for the agent (step 3).

### Option B — DVWA in Docker (more realistic target)

1. Install **Docker Desktop** (macOS or Windows) and make sure it's running.
2. Start DVWA (this image bundles its own database):
   ```bash
   docker run --rm -it -p 8080:80 vulnerables/web-dvwa
   ```
   Serves **http://localhost:8080**. Leave this terminal open.
3. Open **http://localhost:8080** in a browser once → if you see a setup page, scroll down and
   click **"Create / Reset Database"**. Login is `admin` / `password` — **the agent logs in
   automatically**, you don't need to.

> **Windows + Docker note:** Docker Desktop needs WSL2. If `wsl --install` fails with
> `403 Forbidden`, run `wsl --install --no-distribution` instead, reboot, then install Docker
> Desktop (it brings its own Linux distro).

---

## 3. Run the agent

Open a **second terminal**, re-activate the venv (step 1), then run one of these.

> **Windows only — do this first so the ✓ / ▶ symbols print correctly:**
> ```powershell
> $env:PYTHONIOENCODING="utf-8"
> ```

### Against the Flask sandbox (Option A)
```bash
python main.py http://127.0.0.1:5000
```

### Against DVWA (Option B)
```bash
python main.py http://127.0.0.1:8080
```

### See the scope firewall reject an out-of-scope target
```bash
python main.py http://example.com
```

You'll see all layers run (authorization → live recon → selection → governance gate →
execution → detection), the **confirmed exploits**, and a final `[AUDIT]` line confirming the
ledger chain is intact.

---

## 4. (Optional) Use the local open-source LLM

Two features use a **local open-source model via HuggingFace transformers** (no API key,
nothing leaves your machine):
- **`--llm`** — an LLM **triage** decision node: the model re-prioritises the discovered
  injection points by risk (bounded — the governance gate still enforces safety).
- **`--report`** — Layer 7: the model writes a Markdown findings report into `reports/`.

### 4a. Nothing to install separately
`transformers` + `torch` were installed by `pip install -r requirements.txt` in step 1. The
**model weights download automatically on first use** from the HuggingFace Hub (~3 GB, cached
afterwards). The model is set in `config/llm.yaml` (default `Qwen/Qwen2.5-1.5B-Instruct`).

> **Speed:** if `pip` installed CPU-only `torch`, the model runs on CPU (a minute or two). It
> uses the GPU automatically if you have a CUDA build of `torch`. For a faster model, set e.g.
> `Qwen/Qwen2.5-0.5B-Instruct` in `config/llm.yaml`.

### 4b. Run with the LLM
```bash
python main.py http://127.0.0.1:5000 --llm            # LLM triage decision
python main.py http://127.0.0.1:5000 --llm --report   # triage + findings report
```
The report is labelled AI-generated (EU AI Act Art. 50) with a deterministic facts block. The
first run is slow (model download + load); later runs are faster.

---

## 5. Check the tamper-evident audit ledger

Every run appends to `audit/audit.jsonl`. Verify the hash chain any time:
```bash
python -c "from src.agent import AuditLog; from config.paths import ROOT; print(AuditLog.verify(ROOT/'audit'/'audit.jsonl'))"
```
Prints `(True, 'chain intact')` if nothing was edited.

---

## 6. (Optional) Rebuild the dataset and baseline model

Not needed to run the agent — only if you want to regenerate the data/model artifacts.
```bash
# rebuild the final dataset
python -m preprocess.build_dataset

# then open models/baseline.ipynb and "Run All" (use the .venv kernel)
```

---

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `RECON FAILED … connection refused` | The sandbox isn't running. Start it (step 2) in its own terminal, then retry. |
| `REJECTED — not loopback / not on allowlist` | You pointed it at a non-sandbox host/port. Use `127.0.0.1:5000` (Flask) or `127.0.0.1:8080` (DVWA). |
| `UnicodeEncodeError` / garbled ✓ ▶ on Windows | Run `$env:PYTHONIOENCODING="utf-8"` in that terminal first (step 3). |
| `Activate.ps1 … running scripts is disabled` (Windows) | `Set-ExecutionPolicy -Scope Process RemoteSigned`, then re-activate. |
| DVWA shows a MySQL/database error | Use the `vulnerables/web-dvwa` image (step 2B) — it includes the database. |
| `port is already allocated` (Docker) | Something else uses 8080. Stop it, or run DVWA on another allowlisted port (80 or 3000) and target that. |
| `--report` is very slow / seems stuck | First run downloads (~3 GB) + loads the model, and runs on CPU. Wait a couple of minutes, or set a smaller model (`Qwen/Qwen2.5-0.5B-Instruct`) in `config/llm.yaml`. |
| `stale server` / old results after editing the sandbox | A previous `python sandbox/target_app.py` is still holding the port. Stop it (close its terminal / `taskkill /F /IM python.exe` on Windows) and restart. |
| `python: command not found` (macOS) | Use `python3` (and `python3 -m venv`). |

---

## Quick reference (Flask sandbox, the fastest path)

```bash
# terminal 1 — target
python sandbox/target_app.py

# terminal 2 — agent   (Windows: $env:PYTHONIOENCODING="utf-8" first)
python main.py http://127.0.0.1:5000                  # full run: fire + confirm exploits
python main.py http://127.0.0.1:5000 --llm --report   # + LLM triage decision + report
```
