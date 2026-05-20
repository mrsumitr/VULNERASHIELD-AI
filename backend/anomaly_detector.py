"""
anomaly_detector.py — Unsupervised zero-day detector using Isolation Forest.

Trained exclusively on SAFE log lines. Flags requests that are statistically
anomalous even if the supervised classifier says "safe" — catching attack
patterns the model has never seen before.
"""

import os
import joblib
import urllib.parse

from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer

_DIR            = os.path.dirname(__file__)
_MODEL_PATH     = os.path.join(_DIR, "anomaly_model.pkl")
_VEC_PATH       = os.path.join(_DIR, "anomaly_vectorizer.pkl")

# contamination = expected fraction of anomalies in training data.
# Safe logs should be clean, but we allow 1% noise.
_CONTAMINATION  = 0.01


def _train_and_save(safe_logs: list[str]) -> tuple:
    print("Training anomaly detector (Isolation Forest)…", flush=True)
    vec = TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", min_df=1)
    X   = vec.fit_transform(safe_logs)
    clf = IsolationForest(contamination=_CONTAMINATION, n_estimators=100, random_state=42)
    clf.fit(X)
    joblib.dump(clf, _MODEL_PATH)
    joblib.dump(vec, _VEC_PATH)
    print(f"  Anomaly detector trained on {len(safe_logs)} safe examples.", flush=True)
    return clf, vec


def load_or_train(safe_logs: list[str]) -> tuple:
    if os.path.exists(_MODEL_PATH) and os.path.exists(_VEC_PATH):
        return joblib.load(_MODEL_PATH), joblib.load(_VEC_PATH)
    return _train_and_save(safe_logs)


def is_anomalous(log_string: str, clf, vec) -> tuple[bool, float]:
    """
    Returns (is_anomalous, anomaly_score).
    anomaly_score < 0 means anomalous; more negative = more anomalous.
    IsolationForest.predict returns -1 for anomalies, +1 for normal.
    """
    decoded = urllib.parse.unquote(log_string)
    X       = vec.transform([decoded])
    pred    = clf.predict(X)[0]          # -1 = anomaly, +1 = normal
    score   = float(clf.score_samples(X)[0])   # lower = more anomalous
    return bool(pred == -1), round(score, 4)
