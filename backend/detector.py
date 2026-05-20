"""
detector.py — Trains and serves the multi-class HTTP threat classifier.

Training data: HttpParamsDataset (Morzeux/HttpParamsDataset, MIT licence)
  ~1,900 real + synthetic examples across 6 classes.
Model: TF-IDF (char trigrams) + Logistic Regression with balanced class weights.
Persistence: model saved to model.pkl / vectorizer.pkl via joblib.
             Delete these files to force a retrain.
"""

import os
import urllib.parse
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import dataset

# ── Label constants ────────────────────────────────────────────────────────
SAFE       = "safe"
SQLI       = "sqli"
XSS        = "xss"
PATH_TRAV  = "path_traversal"
CMD_INJECT = "cmd_injection"
SSRF       = "ssrf"

ALL_LABELS = [SAFE, SQLI, XSS, PATH_TRAV, CMD_INJECT, SSRF]

# ── Persistence paths ──────────────────────────────────────────────────────
_DIR      = os.path.dirname(__file__)
_MODEL_PATH = os.path.join(_DIR, "model.pkl")
_VEC_PATH   = os.path.join(_DIR, "vectorizer.pkl")


def _train_and_save() -> tuple:
    print("Training classifier …", flush=True)
    log_lines, labels = dataset.load()
    print(f"  {len(log_lines)} examples, {len(set(labels))} classes", flush=True)

    vec = TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", min_df=1)
    X   = vec.fit_transform(log_lines)
    clf = LogisticRegression(class_weight="balanced", max_iter=1000, C=5.0)
    clf.fit(X, labels)

    joblib.dump(clf, _MODEL_PATH)
    joblib.dump(vec, _VEC_PATH)
    print("  Model saved.", flush=True)
    return clf, vec


def _load_or_train() -> tuple:
    if os.path.exists(_MODEL_PATH) and os.path.exists(_VEC_PATH):
        return joblib.load(_MODEL_PATH), joblib.load(_VEC_PATH)
    return _train_and_save()


classifier, vectorizer = _load_or_train()


# ── Public API ─────────────────────────────────────────────────────────────

def analyze_payload(log_string: str) -> tuple[str, float]:
    """Return (label, confidence). Label is one of the ALL_LABELS constants."""
    decoded    = urllib.parse.unquote(log_string)
    vec        = vectorizer.transform([decoded])
    label      = classifier.predict(vec)[0]
    proba      = classifier.predict_proba(vec)[0]
    confidence = proba[list(classifier.classes_).index(label)]
    return str(label), float(confidence)


def retrain() -> None:
    """Force a full retrain (call after updating dataset.py)."""
    global classifier, vectorizer
    for path in (_MODEL_PATH, _VEC_PATH):
        if os.path.exists(path):
            os.remove(path)
    classifier, vectorizer = _train_and_save()


# ── Smoke-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        ("GET /profile.php?user=' OR 1=1-- HTTP/1.1",                       SQLI),
        ("GET /download.php?file=../../../etc/passwd HTTP/1.1",              PATH_TRAV),
        ("GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1",          CMD_INJECT),
        ("GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1", SSRF),
        ("POST /comment.php HTTP/1.1 text=<script>alert(1)</script>",        XSS),
        ("GET /index.html HTTP/1.1",                                         SAFE),
    ]
    ok = total = 0
    for log, expected in tests:
        label, conf = analyze_payload(log)
        match = label == expected
        ok += match; total += 1
        print(f"{'✓' if match else '✗'} {label:20s} {conf:.0%}  {log[:60]}")
    print(f"\n{ok}/{total} correct")
