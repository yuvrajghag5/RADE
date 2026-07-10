"""
Benign / negative corpus — sourced from a real open-source dataset.

SOURCE: HTTP DATASET CSIC 2010 (Spanish Research Council, CSIC), the standard
academic benchmark for web-attack detection. We use only the 36,000 *normal*
(Class="Valid") requests and extract the parameter VALUES a real user sent to an
e-commerce app (usernames, names, emails, addresses, prices, card numbers, …).

  Dataset : HTTP DATASET CSIC 2010
  Via     : github.com/msudol/Web-Application-Attack-Datasets  (CSVData/csic_final.csv, GPL-3.0)
  Extract : data/raw/csic_2010_benign.csv  (20,104 distinct benign key/value pairs)

The parameter KEY is used to map each value to the same injection-point buckets
the attack payloads target, so the classifier learns "attack vs benign", not
"topic A vs topic B". Every row uses the SAME schema as an attack row.
"""
from __future__ import annotations
import csv
import random

from config.paths import RAW_DIR

BENIGN_CSV = RAW_DIR / "csic_2010_benign.csv"

# CSIC param key -> (context label, injection-point bucket, benign category)
KEY_MAP = {
    "login":     ("Login username",        "login_form",    "username"),
    "pwd":       ("Login password",         "login_form",    "password"),
    "password":  ("Registration password",  "login_form",    "password"),
    "remember":  ("Login form option",       "login_form",    "form_option"),
    "modo":      ("Action mode parameter",   "url_param",     "mode_param"),
    "nombre":    ("Name field",              "form_field",    "name"),
    "apellidos": ("Surname field",           "form_field",    "surname"),
    "email":     ("Email field",             "profile_form",  "email"),
    "id":        ("ID parameter",            "url_param",     "numeric_id"),
    "precio":    ("Price parameter",         "url_param",     "price"),
    "cantidad":  ("Quantity parameter",      "url_param",     "quantity"),
    "dni":       ("National ID field",       "profile_form",  "national_id"),
    "ntc":       ("Credit card field",       "profile_form",  "card_number"),
    "direccion": ("Address field",           "profile_form",  "address"),
    "ciudad":    ("City field",              "profile_form",  "city"),
    "provincia": ("Province field",          "profile_form",  "province"),
    "cp":        ("Postal code field",       "profile_form",  "postal_code"),
    "errorMsg":  ("Status message",          "comment_field", "status_message"),
    "B1":        ("Form button",             "form_field",    "button"),
    "B2":        ("Form button",             "form_field",    "button"),
}


def load_benign(n: int = 2000, seed: int = 42) -> list[dict]:
    """Load, map and sample `n` benign inputs from the CSIC 2010 extract."""
    if not BENIGN_CSV.exists():
        raise FileNotFoundError(
            f"{BENIGN_CSV} not found. It is the benign extract from HTTP DATASET "
            "CSIC 2010 (CSVData/csic_final.csv, Class=Valid). See DATA_CARD.md."
        )

    pool: list[tuple[str, str]] = []
    with BENIGN_CSV.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            key, val = row["param_key"], row["value"].strip()
            if key in KEY_MAP and val:
                pool.append((key, val))

    rng = random.Random(seed)
    rng.shuffle(pool)
    picked = pool[:n]

    rows = []
    for i, (key, val) in enumerate(picked):
        context, bucket, category = KEY_MAP[key]
        rows.append({
            "id": f"benign-{i:04d}",
            "label": "benign",
            "attack_class": "benign",
            "type": category,
            "payload": val,
            "context": context,
            "context_bucket": bucket,
            "severity": "none",
            "severity_original": None,
            "severity_reason": "benign_input (CSIC 2010)",
            "is_destructive": False,
            "destructive_flags": [],
            "oracle": None,
            "description": f"Benign user input (CSIC 2010, param '{key}')",
            "example": None,
        })
    return rows


if __name__ == "__main__":
    from collections import Counter
    b = load_benign()
    print("benign rows:", len(b))
    print("by category:", dict(Counter(r["type"] for r in b).most_common()))
    print("by bucket:  ", dict(Counter(r["context_bucket"] for r in b).most_common()))
    for r in b[:6]:
        print(" ", r["id"], r["type"], "->", repr(r["payload"][:55]))
