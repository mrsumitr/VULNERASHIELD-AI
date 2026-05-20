"use client";

import { useState, useEffect, useRef } from "react";

// ── Types ──────────────────────────────────────────────────────────────────

type RemediationBrief = {
  identified_threat: string;
  mitigation_strategy: string;
  recommended_code_fix: string;
};

type AnalysisResult = {
  status: "SAFE" | "THREAT";
  threat_label: string | null;
  threat_confidence: string;
  confidence_level: "low" | "medium" | "high";
  remediation_brief: RemediationBrief | null;
};

type HistoryEntry = {
  logLine: string;
  result: AnalysisResult;
  ts: number;
};

// ── Constants ──────────────────────────────────────────────────────────────

const EXAMPLES = [
  { label: "Safe request",    log: "GET /products.php?category=electronics HTTP/1.1" },
  { label: "SQL Injection",   log: "GET /profile.php?user=' OR 1=1-- HTTP/1.1" },
  { label: "XSS",             log: "POST /comment.php HTTP/1.1 text=<script>alert('XSS')</script>" },
  { label: "Path Traversal",  log: "GET /download.php?file=../../../etc/passwd HTTP/1.1" },
  { label: "Cmd Injection",   log: "GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1" },
  { label: "SSRF",            log: "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" },
  { label: "Encoded SQLi",    log: "GET /view.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" },
];

const THREAT_STYLE: Record<string, string> = {
  sqli:           "text-orange-400 bg-orange-950/50 border-orange-700",
  xss:            "text-yellow-400 bg-yellow-950/50 border-yellow-700",
  path_traversal: "text-purple-400 bg-purple-950/50 border-purple-700",
  cmd_injection:  "text-red-400   bg-red-950/50   border-red-700",
  ssrf:           "text-pink-400  bg-pink-950/50  border-pink-700",
};

const THREAT_NAME: Record<string, string> = {
  sqli:           "SQL Injection",
  xss:            "XSS",
  path_traversal: "Path Traversal",
  cmd_injection:  "Cmd Injection",
  ssrf:           "SSRF",
};

const STORAGE_KEY = "vulnerashield-history";

// ── Sub-components ─────────────────────────────────────────────────────────

function ThreatBadge({ label }: { label: string }) {
  const style = THREAT_STYLE[label] ?? "text-red-400 bg-red-950/50 border-red-700";
  return (
    <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${style}`}>
      {THREAT_NAME[label] ?? label}
    </span>
  );
}

function ConfidenceBar({
  value,
  level,
}: {
  value: string;
  level: "low" | "medium" | "high";
}) {
  const pct = parseFloat(value);
  const color =
    level === "high" ? "bg-emerald-500" :
    level === "medium" ? "bg-yellow-500" :
    "bg-orange-500";
  return (
    <div className="flex items-center gap-3">
      <div
        className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Model confidence: ${value}`}
      >
        <div
          className={`h-full rounded-full transition-all duration-500 ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-sm font-mono text-zinc-300 w-14 text-right" aria-hidden="true">
        {value}
      </span>
    </div>
  );
}

function Skeleton() {
  return (
    <div className="w-full flex flex-col gap-4 animate-pulse" aria-hidden="true">
      <div className="h-24 rounded-lg bg-zinc-800" />
      <div className="h-48 rounded-lg bg-zinc-800" />
    </div>
  );
}

function HistoryPanel({
  entries,
  onClear,
}: {
  entries: HistoryEntry[];
  onClear: () => void;
}) {
  if (entries.length === 0) return null;
  return (
    <section aria-label="Recent scans" className="w-full flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500">
          Recent scans
        </p>
        <button
          onClick={onClear}
          className="text-xs text-zinc-600 hover:text-zinc-400 transition-colors"
          aria-label="Clear scan history"
        >
          Clear
        </button>
      </div>
      <ul className="flex flex-col gap-2">
        {entries.map((e, i) => (
          <li
            key={e.ts}
            className="flex items-center gap-3 px-4 py-3 rounded-lg bg-zinc-900 border border-zinc-800"
            aria-label={`Scan ${i + 1}: ${e.result.status === "SAFE" ? "safe" : THREAT_NAME[e.result.threat_label ?? ""] ?? "threat"}`}
          >
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${e.result.status === "SAFE" ? "bg-emerald-500" : "bg-red-500"}`}
              aria-hidden="true"
            />
            <span className="font-mono text-zinc-400 flex-1 truncate text-xs">
              {e.logLine}
            </span>
            <div className="flex items-center gap-2 shrink-0">
              {e.result.threat_label ? (
                <ThreatBadge label={e.result.threat_label} />
              ) : (
                <span className="text-xs text-emerald-400 font-semibold">SAFE</span>
              )}
              <span className="text-xs text-zinc-500 font-mono">
                {e.result.threat_confidence}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────

export default function Home() {
  const [logLine, setLogLine] = useState("");
  const [result, setResult]   = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const resultRef             = useRef<HTMLDivElement>(null);

  // Hydrate history from localStorage on mount
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch {
      // corrupt storage — silently ignore
    }
  }, []);

  // Persist history to localStorage whenever it changes
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
    } catch {
      // storage quota exceeded — silently ignore
    }
  }, [history]);

  // Scroll result into view after it loads
  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [result]);

  async function analyze() {
    if (!logLine.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
      const res = await fetch(`${API}/analyze-log`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ log_line: logLine }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body?.detail?.[0]?.msg ?? `Server error: ${res.status}`);
      }
      const data: AnalysisResult = await res.json();
      setResult(data);
      setHistory(prev =>
        [{ logLine, result: data, ts: Date.now() }, ...prev].slice(0, 5)
      );
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Failed to reach backend. Is it running on port 8000?"
      );
    } finally {
      setLoading(false);
    }
  }

  function clearHistory() {
    setHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans flex flex-col">
      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg bg-red-600 flex items-center justify-center text-white font-bold text-sm select-none"
            aria-hidden="true"
          >
            VS
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">VulneraShield AI</h1>
            <p className="text-xs text-zinc-500">
              Security Operations Center — Threat Analyzer
            </p>
          </div>
        </div>
        <span className="text-xs text-zinc-600 hidden sm:block" aria-label="Model stats">
          6 threat types · ~1,968 training examples · TF-IDF + LR
        </span>
      </header>

      <main className="flex-1 flex flex-col items-center px-6 py-10 gap-8 max-w-3xl mx-auto w-full">

        {/* Input section */}
        <section aria-label="Log analysis input" className="w-full flex flex-col gap-4">
          <div>
            <label htmlFor="log-input" className="text-sm font-medium text-zinc-300">
              HTTP Log Line
            </label>
            <p id="log-hint" className="text-xs text-zinc-500 mt-0.5">
              Paste a raw HTTP log entry to scan for SQLi, XSS, Path Traversal, Command Injection, or SSRF.
            </p>
          </div>

          <textarea
            id="log-input"
            aria-describedby="log-hint"
            aria-label="HTTP log line to analyze"
            className="w-full h-24 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 text-sm font-mono text-zinc-100 placeholder-zinc-600 resize-none focus:outline-none focus:ring-2 focus:ring-red-600 focus:border-transparent"
            placeholder="e.g. GET /download.php?file=../../../etc/passwd"
            value={logLine}
            onChange={e => setLogLine(e.target.value)}
            onKeyDown={e => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyze();
            }}
          />

          {/* Example quick-fill buttons */}
          <div className="flex flex-wrap gap-2" role="group" aria-label="Example log lines">
            {EXAMPLES.map((ex, i) => (
              <button
                key={i}
                onClick={() => setLogLine(ex.log)}
                className="text-xs px-3 py-1 rounded-full bg-zinc-800 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 transition-colors border border-zinc-700"
                aria-label={`Use example: ${ex.label}`}
              >
                {ex.label}
              </button>
            ))}
          </div>

          <div className="flex justify-end">
            <button
              onClick={analyze}
              disabled={loading || !logLine.trim()}
              aria-busy={loading}
              aria-label={loading ? "Analysis in progress" : "Analyze log line"}
              className="px-6 py-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-zinc-700 disabled:text-zinc-500 text-white text-sm font-medium transition-colors"
            >
              {loading ? "Analyzing…" : "Analyze  ⌘↵"}
            </button>
          </div>
        </section>

        {/* Loading skeleton */}
        {loading && <Skeleton />}

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="w-full rounded-lg border border-orange-700 bg-orange-950/40 px-5 py-4 text-sm text-orange-300"
          >
            {error}
          </div>
        )}

        {/* Result */}
        {result && (
          <section
            ref={resultRef}
            aria-live="polite"
            aria-atomic="true"
            aria-label="Analysis result"
            className="w-full flex flex-col gap-4"
          >
            {/* Status + confidence */}
            <div
              className={`rounded-lg border px-5 py-4 flex flex-col gap-3 ${
                result.status === "SAFE"
                  ? "border-emerald-700 bg-emerald-950/30"
                  : "border-red-800 bg-red-950/20"
              }`}
            >
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div className="flex items-center gap-3">
                  <span className="text-xl" aria-hidden="true">
                    {result.status === "SAFE" ? "✅" : "⚠️"}
                  </span>
                  <div>
                    <p
                      className={`font-semibold ${result.status === "SAFE" ? "text-emerald-400" : "text-red-400"}`}
                    >
                      {result.status === "SAFE"
                        ? "SAFE — Request Operational"
                        : "ALERT — Malicious Threat Detected"}
                    </p>
                    {result.threat_label && (
                      <div className="mt-1">
                        <ThreatBadge label={result.threat_label} />
                      </div>
                    )}
                  </div>
                </div>

                {result.confidence_level === "low" && (
                  <span
                    role="note"
                    className="text-xs font-semibold px-2 py-1 rounded border border-orange-600 text-orange-400 bg-orange-950/50"
                  >
                    Low confidence — review manually
                  </span>
                )}
              </div>

              <div className="flex flex-col gap-1">
                <p className="text-xs text-zinc-500 uppercase tracking-wide">
                  Model confidence
                </p>
                <ConfidenceBar
                  value={result.threat_confidence}
                  level={result.confidence_level}
                />
              </div>
            </div>

            {/* Remediation brief */}
            {result.remediation_brief && (
              <div className="rounded-lg border border-zinc-700 bg-zinc-900 divide-y divide-zinc-800 overflow-hidden">
                <div className="px-5 py-3 bg-zinc-800/60">
                  <p className="text-xs font-semibold uppercase tracking-widest text-zinc-400">
                    Remediation Brief
                  </p>
                </div>

                <div className="px-5 py-4 flex flex-col gap-1">
                  <p className="text-xs text-zinc-500 uppercase tracking-wide">
                    Identified Threat
                  </p>
                  <p className="text-sm font-medium text-red-400">
                    {result.remediation_brief.identified_threat}
                  </p>
                </div>

                <div className="px-5 py-4 flex flex-col gap-1">
                  <p className="text-xs text-zinc-500 uppercase tracking-wide">
                    Mitigation Strategy
                  </p>
                  <p className="text-sm text-zinc-200 leading-relaxed">
                    {result.remediation_brief.mitigation_strategy}
                  </p>
                </div>

                <div className="px-5 py-4 flex flex-col gap-1">
                  <p className="text-xs text-zinc-500 uppercase tracking-wide">
                    Recommended Code Fix
                  </p>
                  <pre className="text-sm font-mono bg-zinc-800 rounded-md px-4 py-3 text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                    {result.remediation_brief.recommended_code_fix}
                  </pre>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Empty state */}
        {!result && !error && !loading && history.length === 0 && (
          <div className="flex-1 flex flex-col items-center justify-center text-center text-zinc-600 gap-2 py-8">
            <p className="text-4xl" aria-hidden="true">🛡️</p>
            <p className="text-sm">Submit a log line to begin analysis</p>
            <p className="text-xs">
              Detects SQL injection, XSS, Path Traversal, Command Injection, and SSRF
            </p>
          </div>
        )}

        {/* Scan history */}
        <HistoryPanel entries={history} onClear={clearHistory} />
      </main>
    </div>
  );
}
