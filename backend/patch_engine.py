"""
patch_engine.py — RAG-style retrieval for security remediation playbooks.

Architecture:
  1. 35-entry knowledge base covering attack variants, frameworks, and mitigations
  2. SentenceTransformer encodes each KB entry into a dense vector
  3. FAISS IndexFlatL2 stores all vectors for similarity search
  4. At query time: encode the full log line + detected threat → retrieve top-1 entry

This is a Retrieval-Augmented Generation (RAG) retrieval component.
The query uses the actual malicious log line (not just the label) so retrieval
is semantically grounded in the real attack content.
"""

from sentence_transformers import SentenceTransformer
import faiss
import numpy as np

LABEL_TO_THREAT = {
    "sqli":           "SQL Injection",
    "xss":            "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "cmd_injection":  "Command Injection",
    "ssrf":           "Server-Side Request Forgery (SSRF)",
}

# ── Knowledge Base (35 entries) ────────────────────────────────────────────
remediation_kb = [
    # ── SQL Injection ──────────────────────────────────────────────────────
    {
        "threat_type": "SQL Injection",
        "solution": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings. Apply an ORM (SQLAlchemy, Django ORM) that handles escaping automatically.",
        "example_fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    },
    {
        "threat_type": "SQL Injection — UNION-based",
        "solution": "Validate and allowlist column counts. Use parameterized queries. Restrict database user permissions so SELECT-only accounts cannot access system tables.",
        "example_fix": "# Use ORM — raw UNION queries should never reach the database\nusers = User.query.filter_by(id=user_id).all()",
    },
    {
        "threat_type": "SQL Injection — Blind / Time-based",
        "solution": "Apply strict input validation and parameterized queries. Set query timeouts on the database to prevent time-based attacks from being useful.",
        "example_fix": "# PostgreSQL — set statement_timeout\nSET statement_timeout = '2s';\n# Python — use parameterized query\ncur.execute('SELECT * FROM users WHERE name = %s', (name,))",
    },
    {
        "threat_type": "SQL Injection — Authentication Bypass",
        "solution": "Never build login queries with string concatenation. Use prepared statements. Hash passwords with bcrypt and compare hashes rather than using SQL for authentication logic.",
        "example_fix": "# BAD:  'SELECT * FROM users WHERE user=' + username\n# GOOD:\ncur.execute('SELECT password_hash FROM users WHERE username = %s', (username,))\nif bcrypt.checkpw(password, stored_hash): ...",
    },
    # ── XSS ───────────────────────────────────────────────────────────────
    {
        "threat_type": "Cross-Site Scripting (XSS)",
        "solution": "Escape all user-supplied output before rendering in HTML. Use a Content Security Policy (CSP) header. Prefer frameworks with auto-escaping (React, Jinja2 with autoescaping).",
        "example_fix": "import html\nsafe = html.escape(user_input)  # converts < > & ' \" to entities",
    },
    {
        "threat_type": "XSS — Stored / Persistent",
        "solution": "Sanitize input on write AND escape on read. Use a server-side HTML sanitizer (bleach, DOMPurify) to strip dangerous tags before storing in the database.",
        "example_fix": "import bleach\nALLOWED = ['b', 'i', 'u', 'em', 'strong']\nclean = bleach.clean(user_html, tags=ALLOWED, strip=True)",
    },
    {
        "threat_type": "XSS — DOM-based",
        "solution": "Avoid writing user data directly to innerHTML, document.write, or eval. Use textContent instead of innerHTML. Validate and sanitize client-side with DOMPurify.",
        "example_fix": "// BAD:  element.innerHTML = userInput\n// GOOD: element.textContent = userInput\n// Or:   element.innerHTML = DOMPurify.sanitize(userInput)",
    },
    {
        "threat_type": "XSS — Content Security Policy",
        "solution": "Set a strict CSP header to block inline scripts and restrict script sources. Use nonces for legitimate inline scripts.",
        "example_fix": "# FastAPI / Flask response header\nresponse.headers['Content-Security-Policy'] = (\n    \"default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'\"\n)",
    },
    # ── Path Traversal ─────────────────────────────────────────────────────
    {
        "threat_type": "Path Traversal",
        "solution": "Resolve the canonical path and assert it starts with the allowed base directory. Never pass raw user input as a filesystem path. Use an allowlist of permitted filenames.",
        "example_fix": "import os\nBASE = '/var/www/files'\nfull = os.path.realpath(os.path.join(BASE, user_input))\nif not full.startswith(BASE):\n    raise ValueError('Path traversal blocked')",
    },
    {
        "threat_type": "Path Traversal — Encoded (%2F, %2E)",
        "solution": "URL-decode input before path validation. Normalise path separators. Both encoded and double-encoded traversal sequences must be resolved before checking.",
        "example_fix": "import urllib.parse, os\ndecoded = urllib.parse.unquote(urllib.parse.unquote(user_input))\nfull    = os.path.realpath(os.path.join(BASE, decoded))\nif not full.startswith(BASE):\n    raise PermissionError('Blocked')",
    },
    {
        "threat_type": "Path Traversal — Windows UNC paths",
        "solution": "On Windows, normalise backslashes and UNC paths (\\\\server\\share). Use pathlib for cross-platform safe path handling.",
        "example_fix": "from pathlib import Path\nbase = Path('C:/www/files').resolve()\nfull = (base / user_input).resolve()\nif not str(full).startswith(str(base)):\n    raise ValueError('Blocked')",
    },
    # ── Command Injection ──────────────────────────────────────────────────
    {
        "threat_type": "Command Injection",
        "solution": "Avoid spawning shell commands with user input. Pass arguments as a list to subprocess with shell=False. Validate inputs against a strict allowlist.",
        "example_fix": "import subprocess\n# BAD:  os.system('ping ' + host)\n# GOOD:\nresult = subprocess.run(\n    ['ping', '-c', '1', host],\n    capture_output=True, shell=False, timeout=5\n)",
    },
    {
        "threat_type": "Command Injection — Pipe and Semicolon",
        "solution": "Reject inputs containing shell metacharacters (;, |, &, $, `, >, <). Use shlex.quote if shell execution is unavoidable.",
        "example_fix": "import shlex, re\nBAD_CHARS = re.compile(r'[;&|`$><]')\nif BAD_CHARS.search(user_input):\n    raise ValueError('Invalid characters')\n# If shell is unavoidable:\nsafe = shlex.quote(user_input)",
    },
    {
        "threat_type": "Command Injection — Reverse Shell",
        "solution": "Never accept URLs or IP addresses in shell commands. If network operations are needed, use Python's socket or requests library directly — never shell out.",
        "example_fix": "# BAD:  os.system('curl ' + url)\n# GOOD:\nimport requests\nresponse = requests.get(url, timeout=5, allow_redirects=False)",
    },
    # ── SSRF ──────────────────────────────────────────────────────────────
    {
        "threat_type": "Server-Side Request Forgery (SSRF)",
        "solution": "Validate and allowlist permitted URL schemes, hostnames, and IP ranges before making outbound requests. Block requests to private/loopback/cloud-metadata IP ranges.",
        "example_fix": "import ipaddress, urllib.parse\nBLOCKED = [ipaddress.ip_network(r) for r in\n           ['169.254.0.0/16','10.0.0.0/8','192.168.0.0/16','127.0.0.0/8']]\nhost = urllib.parse.urlparse(url).hostname\nip   = ipaddress.ip_address(host)\nif any(ip in net for net in BLOCKED):\n    raise ValueError('SSRF: blocked IP')",
    },
    {
        "threat_type": "SSRF — AWS Metadata Endpoint",
        "solution": "Block requests to 169.254.169.254 and IMDSv1. Enable IMDSv2 (token-required) on all EC2 instances. Use IAM roles with minimal permissions.",
        "example_fix": "# Block in application\nBLOCKED_HOSTS = {'169.254.169.254', 'metadata.aws.internal'}\nif urllib.parse.urlparse(url).hostname in BLOCKED_HOSTS:\n    raise ValueError('Cloud metadata endpoint blocked')\n\n# AWS CLI — enforce IMDSv2\n# aws ec2 modify-instance-metadata-options --http-tokens required",
    },
    {
        "threat_type": "SSRF — GCP / Azure Metadata",
        "solution": "Block requests to GCP metadata (metadata.google.internal) and Azure metadata (169.254.169.254 with Metadata: true header). Use service accounts with minimal IAM permissions.",
        "example_fix": "BLOCKED_HOSTS = {\n    '169.254.169.254',\n    'metadata.google.internal',\n    'metadata.azure.internal',\n}\nparsed = urllib.parse.urlparse(url)\nif parsed.hostname in BLOCKED_HOSTS:\n    raise ValueError('Metadata endpoint blocked')",
    },
    {
        "threat_type": "SSRF — Internal Service Enumeration",
        "solution": "Use an allowlist of permitted external domains. Reject requests to private IP ranges, localhost, and internal hostnames. Implement egress firewall rules at the network level.",
        "example_fix": "ALLOWED_DOMAINS = {'api.example.com', 'cdn.example.com'}\nparsed = urllib.parse.urlparse(url)\nif parsed.hostname not in ALLOWED_DOMAINS:\n    raise ValueError(f'Domain {parsed.hostname} not in allowlist')",
    },
    {
        "threat_type": "SSRF — Protocol Smuggling (gopher, dict, file)",
        "solution": "Allowlist permitted URL schemes. Only allow http:// and https://. Reject file://, gopher://, dict://, ftp://, and other protocols.",
        "example_fix": "parsed = urllib.parse.urlparse(url)\nif parsed.scheme not in ('http', 'https'):\n    raise ValueError(f'Protocol {parsed.scheme} not allowed')",
    },
    # ── General Security ───────────────────────────────────────────────────
    {
        "threat_type": "Input Validation — General",
        "solution": "Validate all user inputs at system boundaries. Define expected format, length, and character set. Reject anything that does not match the allowlist.",
        "example_fix": "import re\ndef validate_username(s: str) -> str:\n    if not re.fullmatch(r'[a-zA-Z0-9_]{3,32}', s):\n        raise ValueError('Invalid username format')\n    return s",
    },
    {
        "threat_type": "Authentication — Brute Force",
        "solution": "Implement rate limiting on login endpoints. Lock accounts after N failed attempts. Use CAPTCHA for repeated failures. Log and alert on suspicious login patterns.",
        "example_fix": "# FastAPI with slowapi rate limiter\nfrom slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/login')\n@limiter.limit('5/minute')\nasync def login(request: Request, creds: Credentials): ...",
    },
    {
        "threat_type": "Sensitive Data Exposure",
        "solution": "Never log passwords, tokens, or PII. Use environment variables for secrets. Encrypt sensitive data at rest. Enforce HTTPS everywhere.",
        "example_fix": "import os\nDB_PASSWORD = os.environ['DB_PASSWORD']  # never hardcode\n# Mask in logs:\nlogging.info('User login attempt: %s', username)  # not password",
    },
    {
        "threat_type": "Security Headers — Missing",
        "solution": "Add security headers to every HTTP response: X-Content-Type-Options, X-Frame-Options, Strict-Transport-Security, Referrer-Policy.",
        "example_fix": "@app.middleware('http')\nasync def add_security_headers(request, call_next):\n    response = await call_next(request)\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    response.headers['X-Frame-Options']        = 'DENY'\n    response.headers['Strict-Transport-Security'] = 'max-age=31536000'\n    return response",
    },
    {
        "threat_type": "File Upload — Unrestricted",
        "solution": "Validate file type by magic bytes (not extension). Enforce size limits. Store uploads outside the web root. Scan with antivirus before storing.",
        "example_fix": "import magic\nALLOWED_TYPES = {'image/jpeg', 'image/png', 'application/pdf'}\nmime = magic.from_buffer(file.read(2048), mime=True)\nif mime not in ALLOWED_TYPES:\n    raise ValueError(f'File type {mime} not allowed')",
    },
    {
        "threat_type": "IDOR — Insecure Direct Object Reference",
        "solution": "Always verify that the authenticated user owns the requested resource. Never trust user-supplied IDs without an ownership check.",
        "example_fix": "# BAD:  document = Document.get(id=request_id)\n# GOOD:\ndocument = Document.query.filter_by(\n    id=request_id,\n    owner_id=current_user.id  # ownership enforced\n).first_or_404()",
    },
    {
        "threat_type": "XXE — XML External Entity",
        "solution": "Disable external entity processing in all XML parsers. Use defusedxml instead of the standard library xml module.",
        "example_fix": "import defusedxml.ElementTree as ET\n# BAD:  import xml.etree.ElementTree as ET\ntree = ET.fromstring(xml_input)  # defusedxml blocks XXE automatically",
    },
    {
        "threat_type": "Dependency Vulnerabilities",
        "solution": "Audit dependencies regularly with pip-audit or safety. Pin dependency versions. Set up automated alerts for new CVEs in your dependencies.",
        "example_fix": "# Run in CI pipeline:\npip install pip-audit\npip-audit --requirement requirements.txt\n\n# Or with safety:\npip install safety\nsafety check",
    },
    {
        "threat_type": "CORS Misconfiguration",
        "solution": "Never use wildcard (*) origins in production. Define an explicit allowlist of trusted origins. Do not reflect the Origin header without validation.",
        "example_fix": "ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'https://yourdomain.com').split(',')\napp.add_middleware(CORSMiddleware,\n    allow_origins=ALLOWED_ORIGINS,  # explicit list, not ['*']\n    allow_credentials=True,\n)",
    },
    {
        "threat_type": "Session Management",
        "solution": "Use cryptographically random session IDs. Regenerate session ID after login. Set Secure, HttpOnly, and SameSite flags on session cookies.",
        "example_fix": "# Flask session cookie config\napp.config.update(\n    SESSION_COOKIE_SECURE=True,\n    SESSION_COOKIE_HTTPONLY=True,\n    SESSION_COOKIE_SAMESITE='Strict',\n    SECRET_KEY=os.urandom(32),\n)",
    },
    {
        "threat_type": "Rate Limiting — API Abuse",
        "solution": "Apply rate limits per IP and per user on all endpoints. Return 429 Too Many Requests with a Retry-After header when limits are exceeded.",
        "example_fix": "from slowapi import Limiter\nfrom slowapi.util import get_remote_address\nlimiter = Limiter(key_func=get_remote_address)\n\n@app.post('/analyze-log')\n@limiter.limit('60/minute')\nasync def analyze_log(request: Request, payload: LogPayload): ...",
    },
    {
        "threat_type": "Error Handling — Information Disclosure",
        "solution": "Never expose stack traces, database errors, or internal paths in API responses. Return generic error messages to users. Log details internally.",
        "example_fix": "@app.exception_handler(Exception)\nasync def global_handler(request, exc):\n    logger.error('Unhandled error: %s', exc, exc_info=True)\n    return JSONResponse(status_code=500,\n        content={'error': 'Internal server error'})",
    },
    {
        "threat_type": "Logging and Monitoring",
        "solution": "Log all authentication events, access-denied errors, and input validation failures. Centralise logs (ELK, Splunk). Set up alerts for anomalous patterns.",
        "example_fix": "import logging\nlogging.basicConfig(\n    level=logging.INFO,\n    format='%(asctime)s %(levelname)s %(name)s %(message)s'\n)\nlogger = logging.getLogger(__name__)\nlogger.warning('Failed login attempt: user=%s ip=%s', username, ip)",
    },
    {
        "threat_type": "Cryptography — Weak Hashing",
        "solution": "Never use MD5 or SHA-1 for passwords. Use bcrypt, Argon2, or scrypt with a sufficient work factor. Always salt hashes.",
        "example_fix": "import bcrypt\n# Hash on registration\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n\n# Verify on login\nif bcrypt.checkpw(password.encode(), stored_hash):\n    ...",
    },
    {
        "threat_type": "Infrastructure — Docker Security",
        "solution": "Run containers as non-root. Use read-only filesystems where possible. Scan images for CVEs. Do not mount the Docker socket into containers.",
        "example_fix": "# Dockerfile best practices\nFROM python:3.11-slim\nRUN useradd -m appuser\nUSER appuser          # non-root\nCOPY --chown=appuser . /app\nWORKDIR /app\nCMD [\"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\"]",
    },
    {
        "threat_type": "Secrets Management",
        "solution": "Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Never commit secrets to Git. Rotate secrets regularly.",
        "example_fix": "# .env file (git-ignored)\nDB_PASSWORD=supersecret\n\n# Python\nfrom dotenv import load_dotenv\nload_dotenv()\nDB_PASSWORD = os.environ['DB_PASSWORD']",
    },
]

# ── Build FAISS index ──────────────────────────────────────────────────────

embed_model  = SentenceTransformer("all-MiniLM-L6-v2")

kb_corpus    = [
    f"Threat: {e['threat_type']}. Mitigation: {e['solution']}"
    for e in remediation_kb
]
kb_embeddings = embed_model.encode(kb_corpus, convert_to_numpy=True)

dimension    = kb_embeddings.shape[1]
faiss_index  = faiss.IndexFlatL2(dimension)
faiss_index.add(kb_embeddings)


def get_remediation_brief(label: str, log_line: str = "") -> dict:
    """
    RAG retrieval: encode (threat label + original log line) as the query,
    then return the most semantically similar KB entry.

    Using the actual log line in the query grounds the retrieval in the
    real attack content, not just the category name.
    """
    friendly   = LABEL_TO_THREAT.get(label, label)
    query      = f"Threat: {friendly}. Attack log: {log_line}" if log_line else friendly
    query_vec  = embed_model.encode([query], convert_to_numpy=True)
    _, indices = faiss_index.search(query_vec, k=1)
    return remediation_kb[indices[0][0]]


if __name__ == "__main__":
    test_cases = [
        ("sqli",           "GET /profile.php?user=' OR 1=1-- HTTP/1.1"),
        ("xss",            "POST /comment.php HTTP/1.1 text=<script>alert(1)</script>"),
        ("path_traversal", "GET /download.php?file=../../../etc/passwd HTTP/1.1"),
        ("cmd_injection",  "GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1"),
        ("ssrf",           "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/"),
    ]
    for label, log in test_cases:
        brief = get_remediation_brief(label, log)
        print(f"{label:20s} → {brief['threat_type']}")
