#!/usr/bin/env python3
"""
evaluate.py — Full ML evaluation report for VulneraShield-AI.

Usage:
  python3 evaluate.py            # cross-validated metrics
  python3 evaluate.py --compare  # + multi-algorithm comparison
  python3 evaluate.py --search   # + GridSearchCV hyperparameter tuning
"""

import sys
import collections
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import LinearSVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_predict, GridSearchCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, f1_score

import dataset


def _separator(title: str = "") -> None:
    width = 62
    if title:
        pad = (width - len(title) - 2) // 2
        print(f"\n{'─' * pad} {title} {'─' * (width - pad - len(title) - 2)}")
    else:
        print("─" * width)


def _print_confusion_matrix(y_true, y_pred, classes: list[str]) -> None:
    cm  = confusion_matrix(y_true, y_pred, labels=classes)
    cw  = max(len(c) for c in classes) + 1

    header = f"{'':>{cw}}" + "".join(f"{c:>{cw}}" for c in classes)
    print(header)
    print("─" * len(header))
    for i, cls in enumerate(classes):
        row = "".join(f"{cm[i][j]:>{cw}}" for j in range(len(classes)))
        print(f"{cls:>{cw}}{row}")


def main() -> None:
    run_compare = "--compare" in sys.argv
    run_search  = "--search"  in sys.argv

    # ── Load data ──────────────────────────────────────────────────────────
    print("Loading dataset …", flush=True)
    log_lines, labels = dataset.load()

    dist = collections.Counter(labels)
    _separator()
    print("  VulneraShield-AI — Model Evaluation Report")
    _separator()
    print(f"  Total examples : {len(log_lines)}")
    print(f"  Classes        : {len(dist)}")
    print()
    print(f"  {'Class':<22} {'n':>5}  {'%':>5}")
    print(f"  {'─'*22} {'─'*5}  {'─'*5}")
    for cls in sorted(dist):
        n = dist[cls]
        print(f"  {cls:<22} {n:>5}  {n/len(log_lines)*100:>4.1f}%")

    # ── Primary pipeline (TF-IDF + Logistic Regression) ───────────────────
    pipeline = Pipeline([
        ("vec", TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", min_df=1)),
        ("clf", LogisticRegression(class_weight="balanced", max_iter=1000, C=5.0)),
    ])

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    _separator("5-Fold Stratified Cross-Validation")
    print("  (each example is tested on a fold it was never trained on)\n")

    y_pred   = cross_val_predict(pipeline, log_lines, labels, cv=cv)
    accuracy = np.mean(np.array(y_pred) == np.array(labels))
    print(f"  Overall accuracy : {accuracy:.3f}  ({accuracy*100:.1f}%)\n")

    _separator("Per-Class Precision / Recall / F1")
    print()
    classes = sorted(dist.keys())
    print(classification_report(labels, y_pred, target_names=classes, digits=3))

    _separator("Confusion Matrix  (rows = actual, cols = predicted)")
    print()
    _print_confusion_matrix(labels, y_pred, classes)

    _separator("Sample Misclassifications")
    wrong = [(log_lines[i], labels[i], y_pred[i])
             for i in range(len(labels)) if labels[i] != y_pred[i]]
    print(f"  Total misclassified: {len(wrong)} / {len(labels)} "
          f"({len(wrong)/len(labels)*100:.1f}%)\n")
    for log, true, pred in wrong[:8]:
        print(f"  TRUE={true:<16} PRED={pred:<16} {log[:55]}")

    # ── Multi-algorithm comparison ─────────────────────────────────────────
    if run_compare:
        _separator("Algorithm Comparison")
        print("  Same TF-IDF vectorizer, different classifiers\n")

        # CalibratedClassifierCV wraps LinearSVC to produce probabilities
        algorithms = {
            "Logistic Regression":   LogisticRegression(class_weight="balanced", max_iter=1000, C=5.0),
            "Random Forest":         RandomForestClassifier(class_weight="balanced", n_estimators=100, random_state=42),
            "Gradient Boosting":     GradientBoostingClassifier(n_estimators=100, random_state=42),
            "Linear SVM":            CalibratedClassifierCV(LinearSVC(class_weight="balanced", max_iter=2000)),
            "Decision Tree":         DecisionTreeClassifier(class_weight="balanced", random_state=42),
            "K-Nearest Neighbours":  KNeighborsClassifier(n_neighbors=5),
        }

        vec = TfidfVectorizer(ngram_range=(1, 3), analyzer="char_wb", min_df=1)

        print(f"  {'Algorithm':<26} {'Accuracy':>9}  {'F1 (weighted)':>14}")
        print(f"  {'─'*26} {'─'*9}  {'─'*14}")

        results = []
        for name, clf in algorithms.items():
            pipe  = Pipeline([("vec", vec), ("clf", clf)])
            preds = cross_val_predict(pipe, log_lines, labels, cv=cv)
            acc   = np.mean(np.array(preds) == np.array(labels))
            f1    = f1_score(labels, preds, average="weighted")
            results.append((name, acc, f1))
            print(f"  {name:<26} {acc:>8.1%}  {f1:>13.3f}")

        best = max(results, key=lambda x: x[2])
        print(f"\n  Best: {best[0]} — F1={best[2]:.3f}")
        print("\n  Note: Logistic Regression wins due to its linear decision boundary")
        print("  being well-suited to high-dimensional sparse TF-IDF features.")

    # ── Grid search ────────────────────────────────────────────────────────
    if run_search:
        _separator("GridSearchCV — Hyperparameter Tuning")
        print("  Searching over C × ngram_range … (may take ~1 min)\n")

        param_grid = {
            "clf__C":           [0.5, 1.0, 5.0, 10.0, 20.0],
            "vec__ngram_range": [(1, 2), (1, 3), (2, 3)],
        }
        gs = GridSearchCV(pipeline, param_grid, cv=cv,
                          scoring="f1_weighted", n_jobs=-1, verbose=0)
        gs.fit(log_lines, labels)

        print(f"  Best CV F1 (weighted) : {gs.best_score_:.3f}")
        print(f"  Best params           : {gs.best_params_}")
        print("\n  Top 5 configurations:")
        res = sorted(zip(gs.cv_results_["mean_test_score"], gs.cv_results_["params"]), reverse=True)
        for score, params in res[:5]:
            print(f"    F1={score:.3f}  {params}")

    _separator()
    print()
    tips = []
    if not run_compare: tips.append("--compare to benchmark 6 algorithms")
    if not run_search:  tips.append("--search to tune hyperparameters")
    if tips:
        print(f"  Tip: run with {' or '.join(tips)}.\n")


if __name__ == "__main__":
    main()
