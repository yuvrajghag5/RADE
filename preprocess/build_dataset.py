"""
Master builder for the FINAL execution-ready dataset.

Pipeline:
  raw payloads --(repair + clean)--> attack rows
              --(bucket context)--> injection-point bucket
              --(RECOMPUTE severity)--> trustworthy severity + audit trail
              --(oracle routing)--> which confirm() validator proves each payload
  + benign corpus (negative class)
  => data/processed/dataset_final.jsonl (+ .csv)  with ONE unified schema.

Run:  python -m preprocess.build_dataset
"""
from __future__ import annotations
import json
import re
from collections import Counter

import pandas as pd

from config.paths import RAW_DIR, PROCESSED, CLEAN
from preprocess.preprocess import load_repaired, clean
from preprocess.benign_corpus import load_benign

RAW_FILE = RAW_DIR / "WEB_APPLICATION_PAYLOADS.jsonl"
BENIGN_N = 2000   # negative corpus size (CSIC 2010); user target 1000-3000

# --------------------------------------------------------------------------
# 1. Context -> injection-point bucket  (same rules as analysis notebook §3.1)
# --------------------------------------------------------------------------
BUCKET_RULES = [
    ("login_form",     r"login|sign[\s-]?in|username|password|\bauth"),
    ("search_field",   r"search"),
    ("ssrf_target",    r"internal|metadata|localhost service|network device|redis|"
                       r"memcached|\bftp\b|\bsmb\b|mysql|smtp|snmp|\bec2|\baws|gcp|"
                       r"azure|cloud|instance|gopher|ldap|\bnfs\b|imap|pop3|mqtt|"
                       r"websocket|protocol|scheme|magnet|bitcoin|traversal|smuggling"),
    ("command_exec",   r"command|shell|whoami|curl|netcat|\bnc\b|shadow|environment|"
                       r"director|process|reverse|exfiltrat|substitution|\bread |"
                       r"write to|print |\bexec|passwd"),
    ("script_context", r"script|\beval|innerhtml|\bsvg|\bdom\b|element creation|"
                       r"concatenat|obfuscat|encoded|base64|\bhex|\bimg|onerror|"
                       r"iframe|\bcss|animation|expression"),
    ("attacker_page",  r"malicious (web)?page|attacker|forged|external site|"
                       r"interaction triggered"),
    ("account_settings", r"setting|management|subscription|account|transfer|banking|"
                       r"payment|admin|notification|webhook|ssh key|firewall|\bdns\b|"
                       r"forwarding|iot"),
    ("comment_field",  r"comment|feedback|message|review|\bpost|forum|\bbio|guestbook"),
    ("url_param",      r"\burl\b|parameter|query string|\bid\b|get param|querystring|"
                       r"redirect|method test"),
    ("http_header",    r"header|user-?agent|referer|x-forwarded|host header"),
    ("cookie",         r"cookie|session"),
    ("file_upload",    r"upload|file ?name|attachment"),
    ("api_json",       r"\bapi\b|json|rest|graphql|xml|soap|endpoint|fetch"),
    ("profile_form",   r"profile|registration|contact|newsletter|calendar|"
                       r"email service|social media|mailing"),
    ("form_field",     r"form|input|field|text ?area|checkout"),
]


def bucket_context(text: str) -> str:
    t = str(text).lower()
    for name, pattern in BUCKET_RULES:
        if re.search(pattern, t):
            return name
    return "other"


# --------------------------------------------------------------------------
# 2. Severity — RECOMPUTED, not trusted.
#    The raw labels are internally inconsistent (README §4.2 / crosstab):
#      * XSS reflected == stored == "high"  (no distinction)
#      * all blind SQLi == "medium"         (under-rated data exfiltration)
#      * CMDi split medium/high/critical    (RCE is never "medium")
#      * SSRF has "low" rows                (internal access is not low)
#    Base severity is derived from (class, technique) impact, then adjusted by
#    payload content. We KEEP the original label + record every reason so the
#    change is auditable ("report, don't hide").
# --------------------------------------------------------------------------
BASE_SEVERITY = {
    ("sqli", "tautology"):       "high",       # authentication bypass
    ("sqli", "union"):           "high",       # direct data exfiltration
    ("sqli", "error-based"):     "high",       # data exfiltration via errors
    ("sqli", "boolean-blind"):   "high",       # data exfiltration (inferential)
    ("sqli", "blind-time"):      "high",       # data exfiltration (time-inferential)
    ("sqli", "stacked-queries"): "critical",   # arbitrary statement execution
    ("xss",  "reflected"):       "medium",     # needs per-request victim luring
    ("xss",  "stored"):          "high",       # persistent, hits every viewer
    ("csrf", "CSRF"):            "medium",     # bounded by victim privilege
    ("ssrf", "SSRF"):            "high",       # internal-resource access
    ("cmdi", "Command Injection"): "critical", # remote code execution
}

# Patterns that actually DESTROY / WRITE data -> force critical.
# NOTE: plain localhost/127.0.0.1 SSRF probes are deliberately NOT here
# (README §4.5 caveat: "reaches internal host" != "destroys data").
DESTRUCTIVE_PATTERNS = {
    # data alteration / destruction (StGB §303a): drop, wipe, or rewrite rows
    "sql_write":         r"\b(DROP|TRUNCATE|ALTER)\s+(TABLE|DATABASE)\b|"
                         r"\bDELETE\s+FROM\b|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b",
    "shell_destructive": r"rm\s+-rf|\brm\s+/|mkfs|:\(\)\{|\bshutdown\b|\breboot\b|>\s*/dev/sd",
    "file_write":        r"dd\s+if=|chmod\s+777|>\s*/\w",   # redirect-write to an absolute path
}
CLOUD_METADATA = r"169\.254\.169\.254|metadata\.google|metadata\.aws|/latest/meta-data"
READONLY_RECON = r"^\W*(whoami|id|hostname|uname|pwd|ls)\b"
HIGH_IMPACT_CSRF = (r"password|change email|admin|payment|transfer|fund|ssh|"
                    r"firewall|delete account|api key|webhook")


def flag_destructive(payload: str) -> list[str]:
    p = str(payload)
    return [name for name, pat in DESTRUCTIVE_PATTERNS.items()
            if re.search(pat, p, re.IGNORECASE)]


def recompute_severity(attack_class: str, typ: str, payload: str,
                       description: str, flags: list[str]) -> tuple[str, str]:
    p = str(payload)
    sev = BASE_SEVERITY.get((attack_class, typ), "medium")
    reasons = [f"base {attack_class}/{typ}={sev}"]

    # cloud metadata SSRF -> credential theft
    if re.search(CLOUD_METADATA, p, re.IGNORECASE):
        sev = "critical"
        reasons.append("cloud-metadata endpoint -> critical")

    # read-only recon command injection is serious but not destructive
    if attack_class == "cmdi" and re.search(READONLY_RECON, p.strip(), re.IGNORECASE) and not flags:
        sev = "high"
        reasons.append("read-only recon command -> high")

    # a CSRF that flips a high-impact setting
    if attack_class == "csrf" and sev == "medium" and \
            re.search(HIGH_IMPACT_CSRF, f"{p} {description}", re.IGNORECASE):
        sev = "high"
        reasons.append("high-impact CSRF action -> high")

    # destructive payloads always win -> critical
    if flags:
        sev = "critical"
        reasons.append(f"destructive {flags} -> critical")

    return sev, "; ".join(reasons)


# --------------------------------------------------------------------------
# 3. Oracle routing — which confirm() strategy proves each technique.
#    (Primary validator; the execution layer may hold a fallback chain.)
# --------------------------------------------------------------------------
ORACLE_BY_TYPE = {
    "blind-time":        "timing",
    "boolean-blind":     "differential",
    "tautology":         "differential",
    "union":             "marker_reflection",
    "error-based":       "error_signature",
    "stacked-queries":   "timing",
    "reflected":         "browser_execution",
    "stored":            "browser_execution",
    "Command Injection": "marker_reflection",
    "SSRF":              "out_of_band",
    "CSRF":              "state_change",
}

FINAL_COLUMNS = [
    "id", "label", "attack_class", "type", "payload",
    "context", "context_bucket",
    "severity", "severity_original", "severity_reason",
    "is_destructive", "destructive_flags", "oracle",
    "description", "example",
]


def build_attack_records() -> list[dict]:
    df = clean(load_repaired(RAW_FILE))
    records = df.to_dict(orient="records")
    out = []
    for r in records:
        payload = r["payload"]
        typ = r["type"]
        cls = r["attack_class"]
        desc = r.get("description") or ""
        flags = flag_destructive(payload)
        new_sev, reason = recompute_severity(cls, typ, payload, desc, flags)
        out.append({
            "id": r["id"],
            "label": "attack",
            "attack_class": cls,
            "type": typ,
            "payload": payload,
            "context": r.get("context"),
            "context_bucket": bucket_context(r.get("context")),
            "severity": new_sev,
            "severity_original": str(r["severity"]) if r.get("severity") is not None else None,
            "severity_reason": reason,
            "is_destructive": bool(flags),
            "destructive_flags": flags,
            "oracle": ORACLE_BY_TYPE.get(typ, "differential"),
            "description": r.get("description"),
            "example": r.get("example"),
        })
    return out


def _to_clean(v):
    """pandas NA / NaN -> None so JSON is clean."""
    if v is None:
        return None
    if isinstance(v, float) and pd.isna(v):
        return None
    try:
        if pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    return v


def main() -> None:
    attack = build_attack_records()
    benign = load_benign(n=BENIGN_N, seed=42)       # real negatives from CSIC 2010
    rows = attack + benign

    # normalise every value + enforce column order
    df = pd.DataFrame(rows)
    for c in FINAL_COLUMNS:
        if c not in df:
            df[c] = None
    df = df[FINAL_COLUMNS]
    df = df.map(_to_clean)

    # safety: no payload string may appear in BOTH classes (would poison the split)
    overlap = set(df[df.label == "attack"].payload) & set(df[df.label == "benign"].payload)
    if overlap:
        raise SystemExit(f"attack/benign payload overlap: {overlap}")

    records = df.to_dict(orient="records")
    # write the same execution-ready dataset to both data/cleaned and data/processed
    for out_dir in (CLEAN, PROCESSED):
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "dataset_final.jsonl").open("w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        df.to_csv(out_dir / "dataset_final.csv", index=False)
    out_jsonl = CLEAN / "dataset_final.jsonl"
    out_csv = PROCESSED / "dataset_final.csv"

    # ---- report ----
    print(f"final rows          : {len(df)}")
    print(f"  attack / benign   : {(df.label=='attack').sum()} / {(df.label=='benign').sum()}")
    print(f"attack classes      : {dict(Counter(df[df.label=='attack'].attack_class).most_common())}")
    print(f"severity (attack)   : {dict(Counter(df[df.label=='attack'].severity).most_common())}")
    print("severity CHANGED    :",
          int((df[df.label=='attack'].severity != df[df.label=='attack'].severity_original).sum()),
          "of", int((df.label=='attack').sum()))
    print(f"destructive payloads: {int(df.is_destructive.sum())}")
    print(f"oracle routing      : {dict(Counter(df[df.label=='attack'].oracle).most_common())}")
    print(f"context buckets     : {len(df.context_bucket.unique())}")
    print(f"\nwrote: {out_jsonl}\n       {out_csv}")


if __name__ == "__main__":
    main()
