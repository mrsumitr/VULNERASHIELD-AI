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

remediation_kb = [
    {
        "threat_type": "SQL Injection",
        "solution": (
            "Use parameterized queries / prepared statements. Never concatenate "
            "user input directly into SQL strings. Apply an ORM or query builder "
            "that handles escaping automatically."
        ),
        "example_fix": "cursor.execute('SELECT * FROM users WHERE user = %s', (user_input,))",
    },
    {
        "threat_type": "Cross-Site Scripting (XSS)",
        "solution": (
            "Sanitize and escape all user-supplied data before rendering it in HTML. "
            "Adopt a Content Security Policy (CSP) header and prefer frameworks that "
            "auto-escape template output (React, Jinja2 with autoescaping on)."
        ),
        "example_fix": "import html\nsafe_output = html.escape(user_input)",
    },
    {
        "threat_type": "Path Traversal",
        "solution": (
            "Never pass raw user input as a filesystem path. Resolve the canonical "
            "path and assert it starts with the allowed base directory. Use an "
            "allowlist of permitted filenames where possible."
        ),
        "example_fix": (
            "import os\n"
            "BASE = '/var/www/files'\n"
            "full = os.path.realpath(os.path.join(BASE, user_input))\n"
            "if not full.startswith(BASE):\n"
            "    raise ValueError('Path traversal detected')"
        ),
    },
    {
        "threat_type": "Command Injection",
        "solution": (
            "Avoid spawning shell commands with user input entirely. If unavoidable, "
            "pass arguments as a list (never a string) to subprocess, which bypasses "
            "shell interpretation. Validate/allowlist inputs strictly."
        ),
        "example_fix": (
            "import subprocess\n"
            "# BAD:  os.system('ping ' + host)\n"
            "# GOOD: pass list, shell=False (default)\n"
            "result = subprocess.run(['ping', '-c', '1', host], capture_output=True)"
        ),
    },
    {
        "threat_type": "Server-Side Request Forgery (SSRF)",
        "solution": (
            "Validate and allowlist permitted URL schemes, hostnames, and IP ranges "
            "before making outbound requests. Block requests to private/loopback "
            "ranges (169.254.x.x, 10.x.x.x, 192.168.x.x, 127.x.x.x) and cloud "
            "metadata endpoints."
        ),
        "example_fix": (
            "import ipaddress, urllib.parse\n"
            "BLOCKED = [ipaddress.ip_network(r) for r in\n"
            "           ['169.254.0.0/16','10.0.0.0/8','192.168.0.0/16','127.0.0.0/8']]\n"
            "host = urllib.parse.urlparse(url).hostname\n"
            "ip = ipaddress.ip_address(host)\n"
            "if any(ip in net for net in BLOCKED):\n"
            "    raise ValueError('SSRF: blocked private IP')"
        ),
    },
]

embed_model = SentenceTransformer('all-MiniLM-L6-v2')
kb_corpus = [f"Threat: {e['threat_type']}. Fix: {e['solution']}" for e in remediation_kb]
kb_embeddings = embed_model.encode(kb_corpus, convert_to_numpy=True)

dimension = kb_embeddings.shape[1]
faiss_index = faiss.IndexFlatL2(dimension)
faiss_index.add(kb_embeddings)


def get_remediation_brief(label: str) -> dict:
    """Given an internal label (e.g. 'sqli'), retrieve the closest playbook entry."""
    friendly = LABEL_TO_THREAT.get(label, label)
    query_vec = embed_model.encode([friendly], convert_to_numpy=True)
    _, indices = faiss_index.search(query_vec, k=1)
    return remediation_kb[indices[0][0]]


if __name__ == "__main__":
    for label in LABEL_TO_THREAT:
        brief = get_remediation_brief(label)
        print(f"{label:20s} -> {brief['threat_type']}")
