"""
Baseline model — char n-gram TF-IDF + Logistic Regression.

Two tasks on data/cleaned/dataset_final.jsonl:
  A. binary      label        (attack vs benign)   -> input-side detector
  B. multiclass  attack_class (sqli/xss/csrf/ssrf/cmdi) -> oracle router

Design choices (all defensible for a Responsible-AI baseline):
  * FEATURE = payload text ONLY. `id`, `context_bucket`, `severity` are NEVER
    fed in -- they would leak the label (id prefix == class; bucket correlates
    with label). This is the single most important guard.
  * char n-grams (2-5): payloads are code-like; syntax fragments ('  UNION, <script,
    ;, ../) are the signal, not English words.
  * class_weight="balanced": the data is 1:4.4 attack:benign.
  * DummyClassifier(most_frequent) as the reference every real model must beat.
  * exact-duplicate payloads dropped before the split so a test row can't be an
    identical copy of a training row.
  * stratified split -> per-class precision/recall/F1 + confusion matrix (fairness).

Run:  python -m models.baseline
"""
from __future__ import annotations
import json

import numpy as np
import joblib
from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from config.paths import CLEAN, ROOT

DATA = CLEAN / "dataset_final.jsonl"
OUT = ROOT / "models"
SEED = 42


def load():
    rows = [json.loads(l) for l in DATA.open(encoding="utf-8")]
    # drop exact-duplicate payloads (guard against train/test leakage)
    seen, uniq = set(), []
    for r in rows:
        if r["payload"] in seen:
            continue
        seen.add(r["payload"])
        uniq.append(r)
    return uniq


def make_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                  min_df=2, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
    ])


def evaluate(name, X, y, save_as=None):
    print("\n" + "=" * 68)
    print(f"TASK: {name}   (n={len(X)}, classes={sorted(set(y))})")
    print("=" * 68)
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y)

    # reference baseline
    dummy = DummyClassifier(strategy="most_frequent").fit(Xtr, ytr)
    dummy_f1 = f1_score(yte, dummy.predict(Xte), average="macro")

    # real model
    pipe = make_pipeline().fit(Xtr, ytr)
    pred = pipe.predict(Xte)
    model_f1 = f1_score(yte, pred, average="macro")

    print(f"\nDummyClassifier macro-F1 : {dummy_f1:.3f}   (reference to beat)")
    print(f"Baseline model macro-F1  : {model_f1:.3f}")
    print("\nPer-class report (this table IS the fairness view):")
    print(classification_report(yte, pred, digits=3, zero_division=0))

    labels = sorted(set(y))
    cm = confusion_matrix(yte, pred, labels=labels)
    print("Confusion matrix (rows=true, cols=pred):")
    print("        " + "  ".join(f"{l[:6]:>6}" for l in labels))
    for l, row in zip(labels, cm):
        print(f"{l[:7]:>7} " + "  ".join(f"{v:>6}" for v in row))

    if save_as:
        OUT.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipe, OUT / save_as)
        print(f"\nsaved -> models/{save_as}")
    return model_f1, dummy_f1


def main():
    rows = load()
    print(f"rows after exact-dup removal: {len(rows)}")

    # TASK A: binary attack vs benign (all rows)
    Xa = [r["payload"] for r in rows]
    ya = [r["label"] for r in rows]
    evaluate("A. attack vs benign", Xa, ya, save_as="clf_binary.pkl")

    # TASK B: 5-way attack_class (attack rows only)
    atk = [r for r in rows if r["label"] == "attack"]
    Xb = [r["payload"] for r in atk]
    yb = [r["attack_class"] for r in atk]
    evaluate("B. attack_class (5-way router)", Xb, yb, save_as="clf_attack_class.pkl")


if __name__ == "__main__":
    main()
