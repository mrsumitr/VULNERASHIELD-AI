import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


# ── /health ────────────────────────────────────────────────────────────────

def test_health_returns_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_includes_model_classes():
    r = client.get("/health")
    classes = r.json()["model_classes"]
    assert isinstance(classes, list)
    assert len(classes) > 0


# ── /analyze-log — happy paths ─────────────────────────────────────────────

def test_safe_request():
    r = client.post("/analyze-log", json={"log_line": "GET /index.html HTTP/1.1"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "SAFE"
    assert d["threat_label"] is None
    assert d["remediation_brief"] is None


def test_sqli_detection():
    r = client.post("/analyze-log", json={"log_line": "GET /profile.php?user=' OR 1=1-- HTTP/1.1"})
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "THREAT"
    assert d["threat_label"] == "sqli"


def test_xss_detection():
    r = client.post(
        "/analyze-log",
        json={"log_line": "POST /comment.php HTTP/1.1 text=<script>alert('XSS')</script>"},
    )
    assert r.status_code == 200
    assert r.json()["threat_label"] == "xss"


def test_path_traversal_detection():
    r = client.post(
        "/analyze-log",
        json={"log_line": "GET /download.php?file=../../../etc/passwd HTTP/1.1"},
    )
    assert r.status_code == 200
    assert r.json()["threat_label"] == "path_traversal"


def test_cmd_injection_detection():
    r = client.post(
        "/analyze-log",
        json={"log_line": "GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1"},
    )
    assert r.status_code == 200
    assert r.json()["threat_label"] == "cmd_injection"


def test_ssrf_detection():
    r = client.post(
        "/analyze-log",
        json={"log_line": "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"},
    )
    assert r.status_code == 200
    assert r.json()["threat_label"] == "ssrf"


# ── /analyze-log — response shape ─────────────────────────────────────────

def test_response_has_confidence_fields():
    r = client.post("/analyze-log", json={"log_line": "GET /index.html HTTP/1.1"})
    d = r.json()
    assert "threat_confidence" in d
    assert d["confidence_level"] in ("low", "medium", "high")


def test_threat_response_has_remediation_brief():
    r = client.post("/analyze-log", json={"log_line": "GET /profile.php?user=' OR 1=1-- HTTP/1.1"})
    brief = r.json()["remediation_brief"]
    assert "identified_threat" in brief
    assert "mitigation_strategy" in brief
    assert "recommended_code_fix" in brief
    assert len(brief["mitigation_strategy"]) > 10


# ── /analyze-log — validation ──────────────────────────────────────────────

def test_empty_log_line_rejected():
    r = client.post("/analyze-log", json={"log_line": ""})
    assert r.status_code == 422


def test_whitespace_only_log_line_rejected():
    r = client.post("/analyze-log", json={"log_line": "   "})
    assert r.status_code == 422


def test_log_line_too_long_rejected():
    r = client.post("/analyze-log", json={"log_line": "A" * 5001})
    assert r.status_code == 422


def test_missing_log_line_field_rejected():
    r = client.post("/analyze-log", json={})
    assert r.status_code == 422


def test_max_length_boundary_accepted():
    r = client.post("/analyze-log", json={"log_line": "G" * 5000})
    assert r.status_code == 200
