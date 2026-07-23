"""
Web UI for the Offensive IT-Tester — a live "attack console".

Enter an (allowlisted, loopback) target URL and watch the agent work in real time:
each tool fires (authorize -> recon -> select -> govern -> execute+detect), confirmed
exploits pop up as they're found, and the Layer-7 report streams in token-by-token.

    python webui.py            # serves http://127.0.0.1:7000

Safety: the scope firewall (Layer 1) still applies — the UI can only attack a
loopback host on the allowlist (the Flask sandbox on :5000 or DVWA on :8080). It
cannot be pointed at a third-party site.
"""
from __future__ import annotations
import json
import time

from flask import Flask, request, Response

from config.paths import ROOT
from src.agent import build_registry, AuditLog, HFClient
from src.recon.recon import build_session
from src.execution import baseline
from src.detection import detect
from src.agent.layer_tools import finding_dict

app = Flask(__name__)
AUDIT = ROOT / "audit" / "audit.jsonl"
PACE = 0.6   # deliberate pause between layers so the pipeline animates (not a blur)
_LLM = HFClient()   # one shared client: the model loads once, then every attack reuses it


def run_agent_stream(target: str):
    """Generator of event dicts as the agent runs the seven layers."""
    reg = build_registry()
    audit = AuditLog(AUDIT)

    llm = _LLM   # already loaded once at server startup (see __main__) — always ready

    yield {"type": "start", "target": target}

    # L1 — authorization
    yield {"type": "step", "name": "authorize", "label": "Layer 1 · Authorization — checking scope"}
    time.sleep(PACE)
    d = reg.invoke("authorize", {"target_url": target}).output
    audit.record("authorize", {"approved": d.approved, "reason": d.reason})
    if not d.approved:
        yield {"type": "stepdone", "name": "authorize", "ok": False, "detail": d.reason}
        yield {"type": "halt", "reason": "Out of scope — " + d.reason}
        return
    yield {"type": "stepdone", "name": "authorize", "ok": True, "detail": "approved: " + d.reason}

    # L2 — recon
    yield {"type": "step", "name": "recon", "label": "Layer 2 · Recon — crawling the live target"}
    time.sleep(PACE)
    r = reg.invoke("recon", {"target_url": target, "profile": d.profile or "dvwa"})
    if not r.ok:
        yield {"type": "stepdone", "name": "recon", "ok": False, "detail": r.error}
        yield {"type": "halt", "reason": "Recon failed — is the target running?"}
        return
    points = r.output
    yield {"type": "stepdone", "name": "recon", "ok": True, "detail": f"{len(points)} injection points discovered"}
    yield {"type": "points", "points": [
        {"name": p.name, "method": p.method, "param": p.param, "classes": ",".join(p.classes)} for p in points]}

    # L3 — selection
    yield {"type": "step", "name": "select", "label": "Layer 3 · Selection — choosing payloads (stratified)"}
    time.sleep(PACE)
    selection = reg.invoke("select_payloads", {"points": points, "k_per_type": 2}).output
    total = sum(len(pl) for _, pl in selection)
    yield {"type": "stepdone", "name": "select", "ok": True, "detail": f"{total} payloads selected"}

    # L4 — governance
    yield {"type": "step", "name": "govern", "label": "Layer 4 · Governance — automated safety policy"}
    time.sleep(PACE)
    gate = reg.invoke("govern", {"selection": selection}).output
    yield {"type": "stepdone", "name": "govern", "ok": True, "detail": gate.summary()}
    time.sleep(PACE)

    # L5+6 — execution + detection (per-payload, live)
    yield {"type": "step", "name": "execute", "label": "Layers 5-6 · Execution + Detection — firing & verifying"}
    session = build_session(target, d.profile or "dvwa")
    base_cache, findings, confirmed = {}, [], 0
    approved = gate.approved
    for i, (point, payload) in enumerate(approved, 1):
        if point.full_url not in base_cache:
            base_cache[point.full_url] = baseline(session, point)
        conf, _ = detect(session, point, payload, base_cache[point.full_url])
        findings.append(finding_dict(point, payload, conf))
        if conf.confirmed is True:
            confirmed += 1
            # record every confirmed exploit IN THE AUDIT LEDGER (not a separate banner)
            audit.record("finding", {"attack_class": payload["attack_class"], "type": payload["type"],
                                     "point": point.name, "oracle": conf.oracle,
                                     "confidence": conf.confidence})
            yield {"type": "finding", "attack_class": payload["attack_class"], "ptype": payload["type"],
                   "point": point.name, "oracle": conf.oracle, "confidence": conf.confidence}
        yield {"type": "progress", "i": i, "n": len(approved), "confirmed": confirmed}
        time.sleep(0.03)   # smooth the progress bar so firing is visible, not a blur
    audit.record("execute_detect", {"fired": len(findings), "confirmed": confirmed})
    yield {"type": "stepdone", "name": "execute", "ok": True,
           "detail": f"{confirmed} confirmed of {len(findings)} fired"}
    time.sleep(PACE)

    # L7 — report (streamed token-by-token; model was loaded once at startup)
    yield {"type": "step", "name": "report", "label": "Layer 7 · Report — the local LLM is writing it"}
    from src.reporting.report import stream_report
    state = {"target": target, "profile": d.profile, "authorized": True, "status": "done",
             "points": points, "findings": findings, "gate": gate}
    for chunk in stream_report(state, client=llm):
        yield {"type": "report", "text": chunk}
    yield {"type": "stepdone", "name": "report", "ok": True, "detail": "report complete"}

    ok, msg = AuditLog.verify(AUDIT)
    yield {"type": "complete", "confirmed": confirmed, "fired": len(findings),
           "events": audit.seq, "chain_ok": ok, "chain_msg": msg}


@app.route("/attack")
def attack():
    target = request.args.get("target", "").strip()

    def gen():
        try:
            for ev in run_agent_stream(target):
                yield f"data: {json.dumps(ev)}\n\n"
        except Exception as e:  # never leave the client hanging
            yield f"data: {json.dumps({'type': 'halt', 'reason': f'{type(e).__name__}: {e}'})}\n\n"

    return Response(gen(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RADE — Autonomous Penetration Testing Console</title>
<style>
  @keyframes rade-spin { to { transform: rotate(360deg); } }
  @keyframes rade-pulse { 0%,100% { opacity:1; } 50% { opacity:.35; } }
  @keyframes rade-blink { 0%,49% { opacity:1; } 50%,100% { opacity:0; } }
  :root{
    --bg:#f6f7f9; --bg-elevated:#ffffff; --bg-sunken:#eef0f3;
    --border:#e3e6ea; --border-strong:#d3d7dd;
    --text:#1a1d22; --text-secondary:#5c6370; --text-tertiary:#8a919c;
    --accent:oklch(0.52 0.16 258); --accent-soft:oklch(0.94 0.03 258); --accent-contrast:#ffffff;
    --safe:oklch(0.55 0.13 165); --safe-soft:oklch(0.95 0.04 165);
    --danger:oklch(0.58 0.19 25); --danger-soft:oklch(0.95 0.04 25);
    --warn:oklch(0.75 0.15 75); --warn-soft:oklch(0.95 0.05 75);
    --neutral:oklch(0.62 0.01 260); --neutral-soft:oklch(0.93 0.005 260);
    --shadow:0 1px 2px rgba(20,24,32,.04), 0 4px 16px rgba(20,24,32,.06);
    --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }
  @media (prefers-color-scheme: dark){
    :root{
      --bg:#0f1115; --bg-elevated:#171a20; --bg-sunken:#0b0d10;
      --border:#262b33; --border-strong:#333a45;
      --text:#eef0f3; --text-secondary:#a3aab5; --text-tertiary:#6d7480;
      --accent:oklch(0.72 0.14 258); --accent-soft:oklch(0.28 0.06 258); --accent-contrast:#0f1115;
      --safe:oklch(0.72 0.11 165); --safe-soft:oklch(0.26 0.05 165);
      --danger:oklch(0.68 0.17 25); --danger-soft:oklch(0.28 0.07 25);
      --warn:oklch(0.78 0.13 75); --warn-soft:oklch(0.3 0.06 75);
      --neutral:oklch(0.65 0.01 260); --neutral-soft:oklch(0.24 0.005 260);
      --shadow:0 1px 2px rgba(0,0,0,.3), 0 4px 20px rgba(0,0,0,.35);
    }
  }
  [data-theme="light"]{
    --bg:#f6f7f9; --bg-elevated:#ffffff; --bg-sunken:#eef0f3;
    --border:#e3e6ea; --border-strong:#d3d7dd;
    --text:#1a1d22; --text-secondary:#5c6370; --text-tertiary:#8a919c;
    --accent:oklch(0.52 0.16 258); --accent-soft:oklch(0.94 0.03 258); --accent-contrast:#ffffff;
    --safe:oklch(0.55 0.13 165); --safe-soft:oklch(0.95 0.04 165);
    --danger:oklch(0.58 0.19 25); --danger-soft:oklch(0.95 0.04 25);
    --warn:oklch(0.75 0.15 75); --warn-soft:oklch(0.95 0.05 75);
    --neutral:oklch(0.62 0.01 260); --neutral-soft:oklch(0.93 0.005 260);
    --shadow:0 1px 2px rgba(20,24,32,.04), 0 4px 16px rgba(20,24,32,.06);
  }
  [data-theme="dark"]{
    --bg:#0f1115; --bg-elevated:#171a20; --bg-sunken:#0b0d10;
    --border:#262b33; --border-strong:#333a45;
    --text:#eef0f3; --text-secondary:#a3aab5; --text-tertiary:#6d7480;
    --accent:oklch(0.72 0.14 258); --accent-soft:oklch(0.28 0.06 258); --accent-contrast:#0f1115;
    --safe:oklch(0.72 0.11 165); --safe-soft:oklch(0.26 0.05 165);
    --danger:oklch(0.68 0.17 25); --danger-soft:oklch(0.28 0.07 25);
    --warn:oklch(0.78 0.13 75); --warn-soft:oklch(0.3 0.06 75);
    --neutral:oklch(0.65 0.01 260); --neutral-soft:oklch(0.24 0.005 260);
    --shadow:0 1px 2px rgba(0,0,0,.3), 0 4px 20px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  body{ margin:0; background:var(--bg); font-family:var(--sans); }
  ::selection{ background:var(--accent-soft); }
  .appbar{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 32px;background:var(--bg-elevated);border-bottom:1px solid var(--border);flex-wrap:wrap}
  .banner{margin:20px 32px 0;padding:16px 20px;border-radius:12px;display:none;gap:14px;align-items:flex-start}
  .controlbar{padding:20px 32px;display:flex;flex-wrap:wrap;gap:12px;align-items:center}
  .kpis{padding:0 32px 24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}
  .block{padding:0 32px 28px}
  .card{background:var(--bg-elevated);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow)}
  .steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-top:12px}
  h2.blocktitle{font:750 15px var(--sans);color:var(--text);margin:0}
  .blocksub{font:400 12.5px var(--sans);color:var(--text-tertiary);margin:4px 0 12px}
  .spin{width:11px;height:11px;border-radius:50%;border:2px solid var(--border-strong);border-top-color:var(--accent);animation:rade-spin .7s linear infinite;display:inline-block;flex:none}
</style></head>
<body>
<div id="app" data-theme="" style="min-height:100vh;background:var(--bg);color:var(--text);font-family:var(--sans);transition:background .2s,color .2s">

  <!-- HEADER -->
  <header class="appbar">
    <div style="display:flex;align-items:center;gap:12px">
      <svg width="30" height="30" viewBox="0 0 30 30" style="flex:none">
        <circle cx="15" cy="15" r="13" style="fill:none;stroke:var(--accent);stroke-width:2"></circle>
        <circle cx="15" cy="15" r="6.5" style="fill:var(--accent)"></circle>
      </svg>
      <div>
        <div style="font:800 19px/1.1 var(--sans);letter-spacing:-0.01em;color:var(--text)">RADE</div>
        <div style="font:400 12.5px/1.3 var(--sans);color:var(--text-secondary);margin-top:2px">Autonomous penetration testing you can prove and defend</div>
      </div>
    </div>
    <div style="display:flex;align-items:center;gap:12px">
      <div style="display:flex;align-items:center;gap:7px;padding:6px 12px;border-radius:20px;background:var(--safe-soft);border:1px solid var(--safe)">
        <span style="width:7px;height:7px;border-radius:50%;background:var(--safe);animation:rade-pulse 2s ease-in-out infinite"></span>
        <span style="font:600 12px var(--sans);color:var(--safe)">Live &amp; secure</span>
      </div>
      <button id="theme" style="display:flex;align-items:center;gap:6px;padding:7px 12px;border-radius:8px;border:1px solid var(--border-strong);background:var(--bg);color:var(--text-secondary);font:600 12px var(--sans);cursor:pointer">Auto</button>
    </div>
  </header>

  <!-- HALT BANNER -->
  <div id="halt-banner" class="banner" style="background:var(--accent-soft);border:1px solid var(--accent)">
    <svg width="20" height="20" viewBox="0 0 20 20" style="flex:none;margin-top:2px">
      <circle cx="10" cy="10" r="8.5" style="fill:none;stroke:var(--accent);stroke-width:1.6"></circle>
      <circle cx="10" cy="10" r="3" style="fill:var(--accent)"></circle>
    </svg>
    <div>
      <div style="font:700 14px var(--sans);color:var(--text)">Request blocked by scope firewall — the guardrail is working</div>
      <div id="halt-reason" style="font:400 13px/1.5 var(--sans);color:var(--text-secondary);margin-top:4px"></div>
    </div>
  </div>

  <!-- COMPLETE BANNER -->
  <div id="complete-banner" class="banner" style="background:var(--safe-soft);border:1px solid var(--safe)">
    <svg width="20" height="20" viewBox="0 0 20 20" style="flex:none;margin-top:2px">
      <circle cx="10" cy="10" r="8.5" style="fill:none;stroke:var(--safe);stroke-width:1.6"></circle>
      <path d="M6 10.2l2.6 2.6 5-5.4" style="fill:none;stroke:var(--safe);stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round"></path>
    </svg>
    <div>
      <div id="complete-summary" style="font:700 14px var(--sans);color:var(--text)"></div>
      <div style="font:400 13px/1.5 var(--sans);color:var(--text-secondary);margin-top:4px">What this means: every action taken was inside the authorized target and is recorded in a tamper-evident ledger.</div>
    </div>
  </div>

  <!-- CONTROL BAR -->
  <section class="controlbar">
    <input id="url" value="http://127.0.0.1:5000" placeholder="http://127.0.0.1:5000" style="flex:1;min-width:260px;padding:12px 14px;border-radius:10px;border:1px solid var(--border-strong);background:var(--bg-elevated);color:var(--text);font:500 13.5px var(--mono);outline:none" />
    <button id="run" style="padding:12px 22px;border-radius:10px;border:none;background:var(--accent);color:var(--accent-contrast);font:700 13.5px var(--sans);cursor:pointer;white-space:nowrap;box-shadow:var(--shadow)">Run Assessment</button>
    <div style="display:flex;align-items:center;gap:8px;padding:9px 14px;border-radius:20px;background:var(--accent-soft);border:1px solid var(--accent)">
      <svg width="15" height="15" viewBox="0 0 15 15" style="flex:none">
        <circle cx="7.5" cy="7.5" r="6.4" style="fill:none;stroke:var(--accent);stroke-width:1.4"></circle>
        <circle cx="7.5" cy="7.5" r="2.6" style="fill:var(--accent)"></circle>
      </svg>
      <span style="font:600 12px var(--sans);color:var(--accent)">Protected scope · 127.0.0.1:5000 &amp; :8080 only</span>
    </div>
  </section>

  <!-- KPI ROW -->
  <section id="kpis" class="kpis"></section>

  <!-- PIPELINE -->
  <section class="block">
    <div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:4px">
      <h2 class="blocktitle">Assessment pipeline</h2>
      <span style="font:400 12px var(--sans);color:var(--text-tertiary)">Shielded steps are automated safety gates</span>
    </div>
    <div id="steps" class="steps-grid"></div>
  </section>

  <!-- FINDINGS -->
  <section class="block">
    <h2 class="blocktitle">Confirmed vulnerabilities</h2>
    <div class="blocksub">Only exploits that were actually proven to fire are listed here — everything else stays "unconfirmed".</div>
    <div id="findings"></div>
  </section>

  <!-- AUDIT LEDGER -->
  <section class="block">
    <h2 class="blocktitle">Audit ledger</h2>
    <div class="blocksub">What this means: every action is written to a hash-chained record and verified at the end — nothing can be silently altered.</div>
    <div id="ledger"></div>
  </section>

  <!-- REPORT -->
  <section class="block">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
      <h2 class="blocktitle">AI-generated assessment report</h2>
      <span style="font:700 10px var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--text-tertiary);background:var(--bg-sunken);border:1px solid var(--border);padding:3px 8px;border-radius:6px">EU AI Act Art. 50 · AI-generated</span>
    </div>
    <div id="report-scroll" class="card" style="padding:22px 26px;max-height:340px;overflow-y:auto">
      <div id="report-empty" style="font:400 13px var(--sans);color:var(--text-tertiary)">The report streams here once the agent completes execution and detection.</div>
      <div id="report-content" style="display:none;font:400 14.5px/1.7 var(--sans);color:var(--text);white-space:pre-wrap"><span id="report-text"></span><span id="report-cursor" style="display:none;width:2px;height:16px;background:var(--accent);vertical-align:-3px;animation:rade-blink 1s step-end infinite"></span></div>
    </div>
  </section>

  <!-- TRUST / COMPLIANCE STRIP -->
  <section class="block" style="padding-bottom:36px">
    <div style="font:600 11.5px var(--sans);color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.04em;margin-bottom:10px">Designed for compliance with</div>
    <div id="compliance" style="display:flex;flex-wrap:wrap;gap:9px"></div>
  </section>

</div>

<script>
const $=s=>document.getElementById(s);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

const STEP_DEFS=[
  {name:"authorize", tag:"L1",   label:"Authorization",         gate:true},
  {name:"recon",     tag:"L2",   label:"Recon",                 gate:false},
  {name:"select",    tag:"L3",   label:"Selection",             gate:false},
  {name:"govern",    tag:"L4",   label:"Governance",            gate:true},
  {name:"execute",   tag:"L5–6", label:"Execution + Detection", gate:false},
  {name:"report",    tag:"L7",   label:"Report",                gate:false},
];
const COMPLIANCE=["EU AI Act","GDPR","StGB §202","OWASP Top 10","ISO/IEC 42001","NIST AI RMF"];

function freshSteps(){ const s={}; STEP_DEFS.forEach(d=>s[d.name]={status:"pending",detail:""}); return s; }

const state={
  theme:"auto", target:"http://127.0.0.1:5000", running:false,
  steps:freshSteps(), points:[], progress:{i:0,n:0,confirmed:0},
  findings:[], reportText:"", halted:null, complete:null,
};
let es=null;

/* ---------- theme ---------- */
function applyTheme(){
  $("app").dataset.theme = state.theme==="auto" ? "" : state.theme;
  $("theme").textContent = state.theme==="auto" ? "Auto" : (state.theme==="light"?"Light":"Dark");
}
function cycleTheme(){ state.theme = state.theme==="auto"?"light":(state.theme==="light"?"dark":"auto"); applyTheme(); }

/* ---------- renderers ---------- */
function renderControls(){
  const b=$("run");
  b.disabled=state.running;
  b.textContent=state.running?"Running…":"Run Assessment";
  b.style.background=state.running?"var(--neutral)":"var(--accent)";
  b.style.cursor=state.running?"not-allowed":"pointer";
}

function renderBanners(){
  const h=$("halt-banner"), c=$("complete-banner");
  h.style.display = state.halted ? "flex" : "none";
  if(state.halted) $("halt-reason").textContent=state.halted;
  c.style.display = state.complete ? "flex" : "none";
  if(state.complete){
    const d=state.complete;
    $("complete-summary").textContent =
      "Assessment complete — "+d.confirmed+" confirmed of "+d.fired+" tested, audit chain "+(d.chain_ok?"intact":"broken")+".";
  }
}

function renderKpis(){
  const s=state, dash="—";
  const hasStarted = s.running || !!s.complete || !!s.halted || s.points.length>0;
  const pointsVal = hasStarted ? String(s.points.length) : dash;
  let firedVal=dash;
  if(s.complete) firedVal=String(s.complete.fired);
  else if(s.progress.n) firedVal=s.progress.i+"/"+s.progress.n;
  else if(hasStarted) firedVal="0";
  const confirmedVal = s.complete ? String(s.complete.confirmed) : (hasStarted ? String(s.findings.length) : dash);
  const eventsVal = s.complete ? String(s.complete.events) : dash;
  const chainVal = s.complete ? (s.complete.chain_ok?"Intact":"Broken") : dash;
  const chainColor = s.complete ? (s.complete.chain_ok?"var(--safe)":"var(--danger)") : "var(--text)";
  const kpis=[
    {label:"Injection points found", value:pointsVal,     color:"var(--text)"},
    {label:"Payloads fired",         value:firedVal,      color:"var(--text)"},
    {label:"Exploits confirmed",     value:confirmedVal,  color:(hasStarted&&s.findings.length>0)?"var(--danger)":"var(--text)"},
    {label:"Audit events",           value:eventsVal,     color:"var(--text)"},
    {label:"Chain integrity",        value:chainVal,      color:chainColor},
  ];
  $("kpis").innerHTML = kpis.map(k=>
    '<div class="card" style="padding:16px 18px">'+
      '<div style="font:600 11.5px var(--sans);color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.04em">'+esc(k.label)+'</div>'+
      '<div style="font:750 26px var(--sans);color:'+k.color+';margin-top:6px;letter-spacing:-0.01em">'+esc(k.value)+'</div>'+
    '</div>').join("");
}

const STATUS_META={
  pending:{label:"Pending",                     color:"var(--text-tertiary)"},
  running:{label:"Running",                     color:"var(--accent)"},
  passed: {label:"Passed",                      color:"var(--safe)"},
  blocked:{label:"Blocked — guardrail active",  color:"var(--accent)"},
};

function renderSteps(){
  $("steps").innerHTML = STEP_DEFS.map(d=>{
    const st=state.steps[d.name]||{status:"pending",detail:""};
    const meta=STATUS_META[st.status];
    const detail = st.detail || (st.status==="pending" ? "Waiting for this step to begin." : "");
    const border = st.status==="blocked" ? "var(--accent)" : (d.gate ? "var(--border-strong)" : "var(--border)");
    const badgeBg = st.status==="passed" ? "var(--safe-soft)" : ((st.status==="blocked"||st.status==="running") ? "var(--accent-soft)" : "var(--bg-sunken)");
    const badgeCol= st.status==="passed" ? "var(--safe)" : ((st.status==="blocked"||st.status==="running") ? "var(--accent)" : "var(--text-tertiary)");
    return '<div class="card" style="padding:16px;display:flex;flex-direction:column;gap:10px;border-color:'+border+'">'+
      (d.gate ? '<div style="align-self:flex-start;font:700 9.5px var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--accent);background:var(--accent-soft);padding:3px 7px;border-radius:6px;white-space:nowrap">Safety gate</div>' : '')+
      '<div style="display:flex;align-items:center;gap:10px">'+
        '<div style="width:34px;height:34px;border-radius:50%;background:'+badgeBg+';color:'+badgeCol+';display:flex;align-items:center;justify-content:center;font:750 11px var(--mono);flex:none">'+esc(d.tag)+'</div>'+
        '<div style="min-width:0">'+
          '<div style="font:700 13.5px var(--sans);color:var(--text);overflow-wrap:break-word">'+esc(d.label)+'</div>'+
          '<div style="display:flex;align-items:center;gap:5px;margin-top:2px">'+
            (st.status==="running" ? '<span class="spin"></span>' : '')+
            '<span style="font:600 11.5px var(--sans);color:'+meta.color+'">'+esc(meta.label)+'</span>'+
          '</div>'+
        '</div>'+
      '</div>'+
      '<div style="font:400 12px/1.5 var(--sans);color:var(--text-secondary);min-height:18px">'+esc(detail)+'</div>'+
    '</div>';
  }).join("");
}

const SEV_META={
  high:  {label:"High",   bg:"var(--danger-soft)",  color:"var(--danger)"},
  medium:{label:"Medium", bg:"var(--warn-soft)",    color:"var(--warn)"},
  low:   {label:"Low",    bg:"var(--neutral-soft)", color:"var(--neutral)"},
  none:  {label:"Low",    bg:"var(--neutral-soft)", color:"var(--neutral)"},
};

function renderFindings(){
  const f=state.findings;
  let inner;
  if(f.length){
    const head='<div style="display:grid;grid-template-columns:100px 1fr 1fr 1.4fr;gap:10px;padding:10px 18px;background:var(--bg-sunken);font:700 10.5px var(--sans);letter-spacing:.04em;text-transform:uppercase;color:var(--text-tertiary)">'+
      '<div>Severity</div><div>Attack class</div><div>Location</div><div>Verified by</div></div>';
    const rows=f.map(x=>{
      const m=SEV_META[x.confidence]||SEV_META.low;
      return '<div style="display:grid;grid-template-columns:100px 1fr 1fr 1.4fr;gap:10px;padding:12px 18px;border-top:1px solid var(--border);align-items:center">'+
        '<div><span style="font:700 11px var(--sans);padding:4px 9px;border-radius:20px;background:'+m.bg+';color:'+m.color+'">'+m.label+'</span></div>'+
        '<div style="font:600 13px var(--mono);color:var(--text)">'+esc(x.attack_class)+'</div>'+
        '<div style="font:400 12.5px var(--mono);color:var(--text-secondary)">'+esc(x.point)+'</div>'+
        '<div style="font:400 12.5px var(--sans);color:var(--text-secondary)">Verified by: '+esc(x.oracle)+'</div>'+
      '</div>';
    }).join("");
    inner=head+rows;
  } else {
    inner='<div style="padding:28px 18px;text-align:center;font:500 13px var(--sans);color:var(--text-tertiary)">No confirmed exploits yet</div>';
  }
  $("findings").innerHTML='<div class="card" style="overflow:hidden">'+inner+'</div>';
}

function renderLedger(){
  const f=state.findings;
  let lines;
  if(f.length){
    lines=f.map(x=>
      '<div style="display:flex;align-items:center;gap:10px;padding:11px 18px;border-bottom:1px solid var(--border);font:400 12.5px var(--mono);color:var(--text-secondary)">'+
        '<span style="width:6px;height:6px;border-radius:50%;background:var(--safe);flex:none"></span>'+
        '<span style="color:var(--text)">'+esc(x.attack_class)+'</span><span>·</span>'+
        '<span>'+esc(x.point)+'</span><span>·</span>'+
        '<span>confidence: '+esc(x.confidence)+'</span>'+
      '</div>').join("");
  } else {
    lines='<div style="padding:20px 18px;font:400 12.5px var(--mono);color:var(--text-tertiary)">No ledger entries recorded yet</div>';
  }
  const c=state.complete;
  const chainCol = c ? (c.chain_ok?"var(--safe)":"var(--danger)") : "var(--text)";
  const chainLine = c ? c.chain_msg : "Audit chain will be verified once the assessment completes.";
  const footer='<div style="padding:13px 18px;background:var(--bg-sunken);display:flex;align-items:center;gap:9px">'+
    '<svg width="14" height="14" viewBox="0 0 14 14" style="flex:none">'+
      '<circle cx="7" cy="7" r="6" style="fill:none;stroke:'+chainCol+';stroke-width:1.4"></circle>'+
      '<path d="M4.2 7.2l1.8 1.8 3.6-3.9" style="fill:none;stroke:'+chainCol+';stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round"></path>'+
    '</svg>'+
    '<span style="font:600 12.5px var(--sans);color:'+chainCol+'">'+esc(chainLine)+'</span></div>';
  $("ledger").innerHTML='<div class="card" style="overflow:hidden">'+lines+footer+'</div>';
}

function renderAll(){ renderControls(); renderBanners(); renderKpis(); renderSteps(); renderFindings(); renderLedger(); }

/* ---------- report (incremental) ---------- */
function stripMarkdown(t){ return String(t).replace(/[#*\x60]/g,""); }
function clearReport(){
  state.reportText="";
  $("report-text").textContent="";
  $("report-content").style.display="none";
  $("report-empty").style.display="block";
  $("report-cursor").style.display="none";
}
function appendReport(t){
  const clean=stripMarkdown(t);
  state.reportText+=clean;
  $("report-empty").style.display="none";
  $("report-content").style.display="block";
  $("report-text").textContent+=clean;
  if(state.running) $("report-cursor").style.display="inline-block";
  const sc=$("report-scroll"); sc.scrollTop=sc.scrollHeight;
}

/* ---------- event stream ---------- */
function closeES(){ if(es){ es.close(); es=null; } }

function resetRun(target){
  state.steps=freshSteps(); state.points=[]; state.progress={i:0,n:0,confirmed:0};
  state.findings=[]; state.reportText=""; state.halted=null; state.complete=null;
  if(target){ state.target=target; $("url").value=target; }
  clearReport(); renderAll();
}

function handleEvent(d){
  switch(d.type){
    case "start": resetRun(d.target); break;
    case "step":
      state.steps[d.name]={status:"running", detail:(state.steps[d.name]&&state.steps[d.name].detail)||""};
      renderAll(); break;
    case "stepdone":
      state.steps[d.name]={status:d.ok?"passed":"blocked", detail:d.detail||""};
      renderAll(); break;
    case "points": state.points=d.points||[]; renderAll(); break;
    case "progress": state.progress={i:d.i,n:d.n,confirmed:d.confirmed}; renderAll(); break;
    case "finding":
      state.findings.push({attack_class:d.attack_class, ptype:d.ptype, point:d.point, oracle:d.oracle, confidence:d.confidence});
      renderAll(); break;
    case "report": appendReport(d.text||""); break;
    case "halt":
      state.halted=d.reason; state.running=false; closeES();
      $("report-cursor").style.display="none"; renderAll(); break;
    case "complete":
      state.complete=d; state.running=false; closeES();
      $("report-cursor").style.display="none"; renderAll(); break;
  }
}

function run(){
  if(state.running) return;
  const url=$("url").value.trim(); if(!url) return;
  closeES();
  state.steps=freshSteps(); state.points=[]; state.progress={i:0,n:0,confirmed:0};
  state.findings=[]; state.halted=null; state.complete=null; state.running=true;
  clearReport(); renderAll();
  try{
    es=new EventSource("/attack?target="+encodeURIComponent(url));
    es.onmessage=e=>{ try{ handleEvent(JSON.parse(e.data)); }catch(err){} };
    es.onerror=()=>{ state.running=false; closeES(); renderAll(); };
  }catch(err){ state.running=false; renderAll(); }
}

/* ---------- init ---------- */
$("theme").onclick=cycleTheme;
$("run").onclick=run;
$("url").addEventListener("input", e=>{ state.target=e.target.value; });
$("url").addEventListener("keydown", e=>{ if(e.key==="Enter") run(); });
$("compliance").innerHTML = COMPLIANCE.map(b=>
  '<span style="font:600 12px var(--sans);color:var(--text-secondary);background:var(--bg-elevated);border:1px solid var(--border);padding:7px 13px;border-radius:20px">'+esc(b)+'</span>').join("");
applyTheme();
clearReport();
renderAll();
</script>
</body></html>"""


if __name__ == "__main__":
    # Option C: load the model ONCE at startup, so every attack streams instantly.
    print(f"Loading LLM ({_LLM.cfg.model}) — the first ever run downloads it (~6 GB)…")
    try:
        _LLM._ensure()
        print("LLM ready · reports will stream instantly.")
    except Exception as e:
        print(f"WARNING: LLM failed to load ({e}) — the agent still runs, the report is skipped.")
    print("Attack console:  http://127.0.0.1:7000")
    app.run(host="127.0.0.1", port=7000, threaded=True, debug=False)
