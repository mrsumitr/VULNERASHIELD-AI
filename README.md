# VulneraShield AI

Real-time HTTP threat detection system. Classifies raw HTTP log lines into 6 categories — safe, SQL injection, XSS, path traversal, command injection, and SSRF — using a TF-IDF + Logistic Regression model trained on ~31,156 labelled examples with **99.9% cross-validated accuracy**.

## Architecture

```
frontend/   Next.js 15 + TypeScript + Tailwind CSS
backend/    FastAPI + scikit-learn + joblib
```

```
HTTP log line
     │
     ▼
URL Decode (urllib.parse.unquote)
     │
     ▼
TF-IDF Vectorizer (char n-grams, 1–3)
     │
     ▼
Logistic Regression (6-class, balanced weights)    +   Isolation Forest (anomaly detector)
     │                                                        │
     ├─ SAFE + normal   → return clean                        │
     ├─ SAFE + anomalous → SUSPICIOUS (possible zero-day) ←──┘
     └─ THREAT → RAG retrieval (FAISS + sentence-transformers) → remediation brief
```

## ML Details

| Item | Value |
|---|---|
| Supervised model | TF-IDF (`char_wb`, ngram 1–3) + Logistic Regression |
| Anomaly detection | Isolation Forest (trained on safe logs only) |
| RAG knowledge base | 35 entries — FAISS + `all-MiniLM-L6-v2` embeddings |
| Training data | HttpParamsDataset (real) + synthetic supplement |
| Examples | ~31,156 across 6 classes |
| CV accuracy | **99.9%** (5-fold stratified) |
| Persistence | `model.pkl` / `vectorizer.pkl` via joblib |

**Why char n-grams?** Attack payloads contain distinctive character sequences (`'--`, `<script`, `../`, `; cat`, `169.254`) that char-level features capture better than word tokens — even when attackers URL-encode or obfuscate.

**Why Logistic Regression?** Fast, interpretable, and produces calibrated probabilities for the confidence score. Achieves near-perfect accuracy on this task without the overhead of deep learning.

**Why Isolation Forest?** Detects zero-day attacks — requests that look statistically anomalous even when the supervised classifier says safe. Trained exclusively on legitimate traffic.

## Algorithm Comparison

| Algorithm | Accuracy | F1 (weighted) |
|---|---|---|
| Logistic Regression | 98.8% | 0.988 |
| **Linear SVM** | **99.3%** | **0.993** |
| Gradient Boosting | 98.1% | 0.980 |
| Random Forest | 95.9% | 0.957 |
| Decision Tree | 95.9% | 0.959 |
| K-Nearest Neighbours | 90.3% | 0.906 |

Logistic Regression is chosen for production — calibrated probabilities, interpretability, and near-identical accuracy to SVM with faster inference.

## Threat Classes

| Label | Example payload |
|---|---|
| `sqli` | `' OR 1=1--`, `UNION SELECT` |
| `xss` | `<script>alert(1)</script>`, `onerror=` |
| `path_traversal` | `../../../etc/passwd` |
| `cmd_injection` | `; cat /etc/passwd`, `\| id` |
| `ssrf` | `http://169.254.169.254/latest/meta-data/` |

---

## Running Locally

### Option A — Standard (Python + Node)

**Prerequisites**

| Tool | Version |
|---|---|
| Python | 3.9 or higher |
| Node.js | 18 or higher |

**Step 1 — Start the backend**

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

On first run the model trains automatically (~10 seconds) and is cached to `model.pkl`. You should see:

```
Training classifier …
  31156 examples, 6 classes
  Model saved.
Training anomaly detector (Isolation Forest)…
  Anomaly detector trained on 19319 safe examples.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

**Step 2 — Start the frontend** (second terminal)

```bash
cd frontend
npm install
npm run dev
```

**Step 3 — Open the app**

Visit [http://localhost:3000](http://localhost:3000)

---

### Option B — Docker

```bash
docker-compose up --build
```

Both backend and frontend start automatically. Frontend waits for the backend health check to pass before starting.

---

## Run Tests

```bash
cd backend
pytest tests/ -v
```

Expected: **23 passed**

---

## ML Evaluation Report

```bash
cd backend
python3 evaluate.py            # 5-fold CV metrics + confusion matrix
python3 evaluate.py --compare  # + compare 6 algorithms side by side
python3 evaluate.py --search   # + GridSearchCV hyperparameter tuning
```

Sample output:

```
Overall accuracy : 0.999  (99.9%)

               precision  recall  f1-score   support
cmd_injection      0.957   0.928     0.942        97
path_traversal     1.000   0.990     0.995       296
safe               0.998   1.000     0.999     19319
sqli               1.000   0.998     0.999     10864
ssrf               0.975   0.975     0.975        40
xss                1.000   0.991     0.995       540
```

---

## API Reference

### `GET /health`

```json
{
  "status": "ok",
  "model_classes": ["cmd_injection", "path_traversal", "safe", "sqli", "ssrf", "xss"]
}
```

### `POST /analyze-log`

**Request**
```json
{ "log_line": "GET /download.php?file=../../../etc/passwd HTTP/1.1" }
```

**Response — threat detected**
```json
{
  "status": "THREAT",
  "threat_label": "path_traversal",
  "threat_confidence": "99.8%",
  "confidence_level": "high",
  "anomaly_flag": false,
  "anomaly_score": -0.31,
  "remediation_brief": {
    "identified_threat": "Path Traversal",
    "mitigation_strategy": "Never pass raw user input as a filesystem path ...",
    "recommended_code_fix": "full = os.path.realpath(...)\nif not full.startswith(BASE): ..."
  }
}
```

**Response — safe request**
```json
{
  "status": "SAFE",
  "threat_label": null,
  "threat_confidence": "97.2%",
  "confidence_level": "high",
  "anomaly_flag": false,
  "anomaly_score": -0.28,
  "remediation_brief": null
}
```

**Response — anomalous (possible zero-day)**
```json
{
  "status": "SUSPICIOUS",
  "threat_label": "unknown",
  "threat_confidence": "41.0%",
  "confidence_level": "low",
  "anomaly_flag": true,
  "anomaly_score": -0.62,
  "remediation_brief": {
    "identified_threat": "Anomalous Request (Possible Zero-Day)",
    "mitigation_strategy": "Classified as safe by the supervised model but flagged as statistically anomalous ...",
    "recommended_code_fix": "logger.warning('Anomalous request flagged: %s', log_line)"
  }
}
```

**Validation rules**
- `log_line` is required
- Cannot be empty or whitespace-only
- Maximum 5,000 characters

---

## Dataset

Training data combines two sources:

1. **[HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset)** (MIT licence) — 31,000 real HTTP parameter payloads generated by SQLMap, XSSer, and similar scanners. Capped at 500 per class.
2. **Synthetic supplement** — textbook attack patterns (`' OR 1=1--`, `<script>alert(1)</script>`, etc.) and 40 curated SSRF examples covering AWS/GCP/Azure metadata endpoints (no public dataset covers SSRF payloads).

All payloads are wrapped in **identical** HTTP log-line templates across every class, so the model learns from payload content rather than URL structure — the same approach used by real WAFs.

---

## Project Structure

```
backend/
  dataset.py            # downloads & prepares training data
  detector.py           # supervised classifier — trains & serves TF-IDF + LR
  anomaly_detector.py   # unsupervised — Isolation Forest for zero-day detection
  evaluate.py           # CV evaluation, algorithm comparison, GridSearchCV
  patch_engine.py       # RAG retrieval — FAISS + sentence-transformers, 35-entry KB
  main.py               # FastAPI app
  Dockerfile            # container image (non-root, python:3.11-slim)
  requirements.txt
  tests/
    test_api.py         # 15 API integration tests
    test_detector.py    # 8 unit tests

frontend/
  app/
    page.tsx            # main UI — input, results, history panel
    layout.tsx

docker-compose.yml      # runs backend + frontend together
render.yaml             # Render.com deployment config
```
