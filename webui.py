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
<title>Offensive IT-Tester — Attack Console</title>
<style>
  :root{ --bg:#0b0e14; --panel:#121722; --line:#232b3a; --fg:#c8d3e6; --dim:#7b879c;
         --green:#3ddc84; --red:#ff5c6c; --amber:#ffb454; --accent:#5ac8fa; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{padding:18px 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
  header h1{font-size:16px;margin:0;letter-spacing:.5px}
  header .dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green)}
  header .sub{color:var(--dim);font-size:12px;margin-left:auto}
  .bar{padding:16px 24px;display:flex;gap:10px;align-items:center;border-bottom:1px solid var(--line)}
  .bar input{flex:1;background:#0e131d;border:1px solid var(--line);color:var(--fg);padding:10px 12px;border-radius:8px;font:inherit}
  .bar button{background:var(--green);color:#04180d;border:0;padding:10px 20px;border-radius:8px;font:inherit;font-weight:700;cursor:pointer}
  .bar button:disabled{opacity:.5;cursor:not-allowed}
  .hint{color:var(--dim);font-size:12px;padding:0 24px 12px}
  .wrap{display:grid;grid-template-columns:minmax(320px,1fr) minmax(360px,1.2fr);gap:16px;padding:16px 24px}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .panel h2{margin:0;padding:12px 16px;font-size:12px;letter-spacing:1px;color:var(--dim);border-bottom:1px solid var(--line);text-transform:uppercase}
  .panel .body{padding:12px 16px;max-height:60vh;overflow:auto}
  .step{display:flex;gap:10px;padding:8px 0;border-bottom:1px dashed var(--line)}
  .step:last-child{border-bottom:0}
  .ic{width:18px;text-align:center}
  .spin{display:inline-block;animation:sp 1s linear infinite}@keyframes sp{to{transform:rotate(360deg)}}
  .step .lbl{font-weight:600}.step .det{color:var(--dim);font-size:12.5px}
  .ok{color:var(--green)}.bad{color:var(--red)}.run{color:var(--accent)}
  .prog{height:6px;background:#0e131d;border-radius:4px;margin-top:8px;overflow:hidden}
  .prog > i{display:block;height:100%;width:0;background:var(--accent);transition:width .2s}
  .audithead{color:var(--dim);font-size:11px;letter-spacing:1px;text-transform:uppercase;margin:2px 0 6px}
  .aline{font-size:12.5px;padding:4px 0;border-bottom:1px dashed var(--line)}
  .aline .ok{color:var(--green);font-weight:700;margin-right:6px}
  .aline .dim{color:var(--dim)}
  .auditsum{margin-top:10px;color:var(--green);font-size:12.5px}
  #report{white-space:pre-wrap;font-size:13px;color:#dbe6f5}
  #report .cur{display:inline-block;width:8px;background:var(--green);animation:bl 1s steps(1) infinite}@keyframes bl{50%{opacity:0}}
  .banner{padding:10px 16px;border-radius:8px;margin:0 24px 16px;display:none}
  .banner.good{background:rgba(61,220,132,.12);border:1px solid var(--green);color:var(--green)}
  .banner.err{background:rgba(255,92,108,.12);border:1px solid var(--red);color:var(--red)}
  .points{color:var(--dim);font-size:12px}
</style></head>
<body>
  <header>
    <span class="dot"></span><h1>OFFENSIVE IT-TESTER · ATTACK CONSOLE</h1>
    <span class="sub">LangGraph agent · 7 layers · local LLM</span>
  </header>
  <div class="bar">
    <input id="url" value="http://127.0.0.1:5000" placeholder="target URL (loopback / allowlisted only)">
    <button id="go">▶ ATTACK</button>
  </div>
  <div class="hint">Allowed targets only: the Flask sandbox <code>http://127.0.0.1:5000</code> or DVWA <code>http://127.0.0.1:8080</code>. The scope firewall rejects anything else.</div>
  <div id="banner" class="banner"></div>
  <div class="wrap">
    <div class="panel">
      <h2>Pipeline · tools called</h2>
      <div class="body" id="steps"></div>
    </div>
    <div class="panel">
      <h2>Audit &amp; report</h2>
      <div class="body">
        <div id="auditlog"></div>
        <div id="reportwrap" style="display:none">
          <div style="color:var(--dim);font-size:12px;margin:12px 0 6px">— Layer 7 report (streaming) —</div>
          <div id="report"></div>
        </div>
      </div>
    </div>
  </div>
<script>
const $=s=>document.querySelector(s);
const steps=$("#steps"), auditlog=$("#auditlog"), report=$("#report"), banner=$("#banner");
let es=null, cursor=null;

function ensureAuditHead(){ if(!document.getElementById("ahead")){
  const h=document.createElement("div"); h.id="ahead"; h.className="audithead";
  h.textContent="audit ledger — confirmed exploits"; auditlog.appendChild(h); } }

function stepEl(name){ let e=document.getElementById("st-"+name);
  if(!e){ e=document.createElement("div"); e.className="step"; e.id="st-"+name;
    e.innerHTML='<span class="ic"><span class="spin run">◍</span></span><div><div class="lbl"></div><div class="det"></div></div>';
    steps.appendChild(e);} return e; }

function handle(d){
  if(d.type==="start"){ steps.innerHTML=""; auditlog.innerHTML=""; report.textContent="";
    $("#reportwrap").style.display="none"; banner.style.display="none"; }
  else if(d.type==="step"){ const e=stepEl(d.name); e.querySelector(".lbl").textContent=d.label;
    e.querySelector(".ic").innerHTML='<span class="spin run">◍</span>'; }
  else if(d.type==="stepdone"){ const e=stepEl(d.name);
    e.querySelector(".ic").innerHTML = d.ok?'<span class="ok">✓</span>':'<span class="bad">✗</span>';
    e.querySelector(".det").textContent=d.detail||""; }
  else if(d.type==="points"){ const e=stepEl("recon"); const p=document.createElement("div");
    p.className="points"; p.textContent=d.points.map(x=>x.name+" ("+x.method+" "+x.param+")").join("  ·  ");
    e.appendChild(p); }
  else if(d.type==="progress"){ let e=stepEl("execute"); let bar=e.querySelector(".prog");
    if(!bar){ bar=document.createElement("div"); bar.className="prog"; bar.innerHTML="<i></i>"; e.appendChild(bar);}
    bar.querySelector("i").style.width=(100*d.i/d.n)+"%";
    e.querySelector(".det").textContent="firing "+d.i+"/"+d.n+" · "+d.confirmed+" confirmed"; }
  else if(d.type==="finding"){ ensureAuditHead();
    const l=document.createElement("div"); l.className="aline";
    l.innerHTML='<span class="ok">CONFIRMED</span>'+d.attack_class+'/'+d.ptype+
      '<span class="dim"> — at '+d.point+' · '+d.oracle+' · '+d.confidence+'</span>';
    auditlog.appendChild(l); }
  else if(d.type==="report"){ $("#reportwrap").style.display="block";
    if(cursor) cursor.remove(); report.append(d.text.replace(/[#*\x60]/g,""));  // strip markdown chars
    cursor=document.createElement("span"); cursor.className="cur"; cursor.textContent=" ";
    report.appendChild(cursor); report.parentElement.parentElement.scrollTop=1e9; }
  else if(d.type==="halt"){ banner.className="banner err"; banner.style.display="block";
    banner.textContent="⛔ "+d.reason; done(); }
  else if(d.type==="complete"){ if(cursor) cursor.remove();
    const s=document.createElement("div"); s.className="auditsum";
    s.textContent="✓ audit ledger: "+d.events+" events · "+(d.chain_ok?"chain intact":"chain BROKEN");
    auditlog.appendChild(s);
    banner.className="banner good"; banner.style.display="block";
    banner.textContent="✔ Done — "+d.confirmed+" exploit(s) confirmed of "+d.fired+" fired (recorded in the audit)."; done(); }
}
function done(){ if(es){es.close();es=null;} $("#go").disabled=false; $("#go").textContent="▶ ATTACK"; }
$("#go").onclick=()=>{ const url=$("#url").value.trim(); if(!url) return;
  $("#go").disabled=true; $("#go").textContent="… running";
  es=new EventSource("/attack?target="+encodeURIComponent(url));
  es.onmessage=e=>handle(JSON.parse(e.data));
  es.onerror=()=>{ if(es){done();} };
};
$("#url").addEventListener("keydown",e=>{ if(e.key==="Enter") $("#go").click(); });
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
