import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import detector


def test_safe_prediction():
    label, conf = detector.analyze_payload("GET /index.html HTTP/1.1")
    assert label == detector.SAFE
    assert 0.0 <= conf <= 1.0


def test_sqli_prediction():
    label, _ = detector.analyze_payload("GET /profile.php?user=' OR 1=1-- HTTP/1.1")
    assert label == detector.SQLI


def test_xss_prediction():
    label, _ = detector.analyze_payload(
        "POST /comment.php HTTP/1.1 text=<script>alert('XSS')</script>"
    )
    assert label == detector.XSS


def test_path_traversal_prediction():
    label, _ = detector.analyze_payload("GET /download.php?file=../../../etc/passwd HTTP/1.1")
    assert label == detector.PATH_TRAV


def test_cmd_injection_prediction():
    label, _ = detector.analyze_payload("GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1")
    assert label == detector.CMD_INJECT


def test_ssrf_prediction():
    label, _ = detector.analyze_payload(
        "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1"
    )
    assert label == detector.SSRF


def test_confidence_is_probability():
    for log in [
        "GET /index.html HTTP/1.1",
        "GET /profile.php?user=' OR 1=1-- HTTP/1.1",
        "GET /download.php?file=../../../etc/passwd HTTP/1.1",
    ]:
        _, conf = detector.analyze_payload(log)
        assert 0.0 <= conf <= 1.0


def test_known_labels_exhaustive():
    valid = {detector.SAFE, detector.SQLI, detector.XSS,
             detector.PATH_TRAV, detector.CMD_INJECT, detector.SSRF}
    label, _ = detector.analyze_payload("GET /index.html HTTP/1.1")
    assert label in valid
