
import json, re
import pandas as pd
from pathlib import Path
from config.paths import RAW_DIR, CLEAN

# project root = parent of this script's folder (…/RADE/preprocess/ -> …/RADE)

RAW = RAW_DIR / "WEB_APPLICATION_PAYLOADS.jsonl"
OUT_DIR = CLEAN
 
# ---------- STAGE 1: raw-text repair (pandas cannot do this) ----------
def load_repaired(path: Path) -> list[dict]:
    text = path.read_bytes().decode("utf-8")
    text = text.replace("\u00a0", " ")                          # nbsp -> space
    text = re.sub(r"}(\s*\n\s*){", r"},\1{", text)              # missing commas
    text = re.sub(r'(?<!\\)\\(?![\\"/bfnrtu])', r"\\\\", text)  # bad escapes
    return json.loads(text)
 
# ---------- STAGE 2: pandas cleaning ----------
def clean(records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(records)
 
    # derive attack class from the id prefix
    df["attack_class"] = (df["id"].str.extract(r"^([a-zA-Z]+)")[0]
                          .str.lower()
                          .replace({"cmdinj": "cmdi"}))
 
    # unify the two names for the same concept into one column (guarded)
    eq = df["example_query"] if "example_query" in df else pd.Series(pd.NA, index=df.index)
    eu = df["example_usage"] if "example_usage" in df else pd.Series(pd.NA, index=df.index)
    df["example"] = eq.combine_first(eu)
    df = df.drop(columns=[c for c in ["example_query", "example_usage"] if c in df])
 
    # strip whitespace on every text column (pandas 2/3 safe)
    for c in df.columns:
        if df[c].dtype == "object" or str(df[c].dtype) == "string":
            df[c] = df[c].astype("string").str.strip()
 
    # drop rows with no payload
    before = len(df)
    df = df[df["payload"].notna() & (df["payload"] != "")]
    dropped_empty = before - len(df)
 
    # detect duplicate payloads with CONFLICTING labels (report, don't hide)
    conflicts = (df.groupby("payload")["attack_class"].nunique()
                 .loc[lambda s: s > 1].index.tolist())
 
    # drop exact duplicate payloads, keep first
    before = len(df)
    df = df.drop_duplicates(subset="payload", keep="first")
    dropped_dupes = before - len(df)
 
    # ordered severity for correct sorting / plots
    df["severity"] = pd.Categorical(df["severity"],
                                    categories=["low", "medium", "high", "critical"],
                                    ordered=True)
 
    cols = ["id", "attack_class", "payload", "type", "severity",
            "context", "description", "example"]
    df = df[cols].reset_index(drop=True)
 
    print(f"dropped empty payloads : {dropped_empty}")
    print(f"dropped duplicate rows : {dropped_dupes}")
    print(f"label-conflicting dupes: {len(conflicts)} {conflicts[:3]}")
    return df
 
if __name__ == "__main__":
    df = clean(load_repaired(RAW))
    print("final shape:", df.shape)
    print("class balance:\n", df["attack_class"].value_counts())
 
    OUT_DIR.mkdir(parents=True, exist_ok=True)          # create output dir if missing
    df.to_csv(OUT_DIR / "payloads_clean.csv", index=False)
    df.to_json(OUT_DIR / "payloads_clean.jsonl", orient="records", lines=True)
    print("written to:", OUT_DIR)
 