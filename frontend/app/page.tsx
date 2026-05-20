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
  { label: "Safe",           log: "GET /products.php?category=electronics HTTP/1.1" },
  { label: "SQL Injection",  log: "GET /profile.php?user=' OR 1=1-- HTTP/1.1" },
  { label: "XSS",            log: "POST /comment.php HTTP/1.1 text=<script>alert('XSS')</script>" },
  { label: "Path Traversal", log: "GET /download.php?file=../../../etc/passwd HTTP/1.1" },
  { label: "Cmd Injection",  log: "GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1" },
  { label: "SSRF",           log: "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" },
  { label: "Encoded SQLi",   log: "GET /view.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" },
];

const THREAT_LABEL: Record<string, string> = {
  sqli:           "SQL Injection",
  xss:            "Cross-Site Scripting",
  path_traversal: "Path Traversal",
  cmd_injection:  "Command Injection",
  ssrf:           "Server-Side Request Forgery",
};

const STORAGE_KEY = "vulnerashield-history";

// ── Helpers ────────────────────────────────────────────────────────────────

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

// ── Page ───────────────────────────────────────────────────────────────────

export default function Home() {
  const [logLine, setLogLine] = useState("");
  const [result, setResult]   = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [online, setOnline]   = useState<boolean | null>(null);
  const resultRef             = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch { /* ignore */ }
  }, []);

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(history)); }
    catch { /* ignore */ }
  }, [history]);

  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, [result]);

  useEffect(() => {
    const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    fetch(`${API}/health`).then(r => setOnline(r.ok)).catch(() => setOnline(false));
  }, []);

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
      setHistory(prev => [{ logLine, result: data, ts: Date.now() }, ...prev].slice(0, 5));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach backend.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col">

      {/* Header */}
      <header className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-red-600 flex items-center justify-center text-white font-bold text-xs select-none">
            VS
          </div>
          <div>
            <h1 className="text-sm font-semibold tracking-tight">VulneraShield AI</h1>
            <p className="text-xs text-zinc-500">HTTP Threat Classifier · TF-IDF + Logistic Regression</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-1.5 h-1.5 rounded-full ${online ? "bg-emerald-500" : "bg-zinc-600"}`} />
          <span className="text-xs text-zinc-400 hidden sm:block">
            {online ? "Backend online" : "Connecting…"}
          </span>
        </div>
      </header>

      {/* Stats */}
      <div className="border-b border-zinc-800 bg-zinc-900 px-6 py-2 flex gap-6 text-xs overflow-x-auto">
        <span className="text-zinc-500">Accuracy <span className="text-zinc-200 font-mono">98.7%</span></span>
        <span className="text-zinc-500">CV Folds <span className="text-zinc-200 font-mono">5</span></span>
        <span className="text-zinc-500">Training examples <span className="text-zinc-200 font-mono">1,968</span></span>
        <span className="text-zinc-500">Threat classes <span className="text-zinc-200 font-mono">6</span></span>
      </div>

      <main className="flex-1 max-w-2xl mx-auto w-full px-4 sm:px-6 py-8 flex flex-col gap-6">

        {/* Input */}
        <section aria-label="Log input" className="flex flex-col gap-3">
          <label htmlFor="log-input" className="text-xs font-semibold uppercase tracking-widest text-zinc-400">
            HTTP Log Line
          </label>

          <textarea
            id="log-input"
            aria-label="HTTP log line to analyze"
            className="w-full h-24 bg-zinc-900 border border-zinc-700 rounded px-3 py-2.5 text-sm font-mono text-zinc-100 placeholder-zinc-600 resize-none focus:outline-none focus:border-zinc-500 transition-colors"
            placeholder="e.g. GET /download.php?file=../../../etc/passwd HTTP/1.1"
            value={logLine}
            onChange={e => setLogLine(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyze(); }}
          />

          {/* Examples */}
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Example log lines">
            {EXAMPLES.map((ex, i) => (
              <button
                key={i}
                onClick={() => { setLogLine(ex.log); setResult(null); setError(null); }}
                className="text-xs px-2.5 py-1 rounded border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-zinc-200 transition-colors"
              >
                {ex.label}
              </button>
            ))}
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs text-zinc-600 font-mono">{logLine.length} / 5000</span>
            <button
              onClick={analyze}
              disabled={loading || !logLine.trim()}
              aria-busy={loading}
              className="px-4 py-1.5 rounded bg-red-600 hover:bg-red-500 disabled:bg-zinc-800 disabled:text-zinc-600 text-white text-xs font-semibold transition-colors"
            >
              {loading ? "Analyzing…" : "Analyze"}
            </button>
          </div>
        </section>

        {/* Loading */}
        {loading && (
          <div className="flex items-center gap-3 px-4 py-3 rounded border border-zinc-800 bg-zinc-900" aria-live="polite">
            <div className="w-4 h-4 rounded-full border-2 border-zinc-600 border-t-zinc-300 animate-spin shrink-0" />
            <span className="text-xs text-zinc-400">Classifying threat pattern…</span>
          </div>
        )}

        {/* Error */}
        {error && (
          <div role="alert" className="px-4 py-3 rounded border border-zinc-700 bg-zinc-900 text-xs text-zinc-300">
            Error: {error}
          </div>
        )}

        {/* Result */}
        {result && (
          <section
            ref={resultRef}
            aria-live="polite"
            aria-label="Analysis result"
            className="flex flex-col gap-4"
          >
            {/* Status */}
            <div className={`px-4 py-4 rounded border flex flex-col gap-3 ${
              result.status === "SAFE"
                ? "border-zinc-700 bg-zinc-900"
                : "border-red-900 bg-zinc-900"
            }`}>
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold uppercase tracking-widest ${
                      result.status === "SAFE" ? "text-emerald-400" : "text-red-400"
                    }`}>
                      {result.status === "SAFE" ? "Safe" : "Threat Detected"}
                    </span>
                    {result.confidence_level === "low" && (
                      <span className="text-xs text-zinc-500 border border-zinc-700 px-1.5 py-0.5 rounded">
                        Low confidence — review manually
                      </span>
                    )}
                  </div>
                  {result.threat_label && (
                    <p className="text-sm font-semibold text-zinc-100">
                      {THREAT_LABEL[result.threat_label] ?? result.threat_label}
                    </p>
                  )}
                </div>
                <span className="text-xs font-mono text-zinc-400 shrink-0">{result.threat_confidence}</span>
              </div>

              {/* Confidence bar */}
              <div
                className="h-1 bg-zinc-800 rounded-full overflow-hidden"
                role="progressbar"
                aria-valuenow={parseFloat(result.threat_confidence)}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                <div
                  className={`h-full rounded-full transition-all duration-500 ${
                    result.confidence_level === "high" ? "bg-emerald-600" :
                    result.confidence_level === "medium" ? "bg-yellow-600" : "bg-zinc-500"
                  }`}
                  style={{ width: result.threat_confidence }}
                />
              </div>
            </div>

            {/* Remediation */}
            {result.remediation_brief && (
              <div className="rounded border border-zinc-800 bg-zinc-900 overflow-hidden text-sm">
                <div className="px-4 py-2.5 border-b border-zinc-800 bg-zinc-800/50">
                  <p className="text-xs font-semibold uppercase tracking-widest text-zinc-300">Remediation</p>
                </div>

                <div className="divide-y divide-zinc-800">
                  <div className="px-4 py-3 flex flex-col gap-1">
                    <p className="text-xs text-zinc-500 uppercase tracking-wide">Threat</p>
                    <p className="text-sm text-zinc-100 font-medium">{result.remediation_brief.identified_threat}</p>
                  </div>

                  <div className="px-4 py-3 flex flex-col gap-1">
                    <p className="text-xs text-zinc-500 uppercase tracking-wide">Mitigation</p>
                    <p className="text-sm text-zinc-300 leading-relaxed">{result.remediation_brief.mitigation_strategy}</p>
                  </div>

                  <div className="px-4 py-3 flex flex-col gap-1.5">
                    <p className="text-xs text-zinc-500 uppercase tracking-wide">Code Fix</p>
                    <pre className="text-xs font-mono bg-zinc-950 border border-zinc-800 rounded px-3 py-2.5 text-emerald-400 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                      {result.remediation_brief.recommended_code_fix}
                    </pre>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Empty state */}
        {!result && !error && !loading && history.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 gap-2 text-center">
            <p className="text-xs text-zinc-600 uppercase tracking-widest">Ready</p>
            <p className="text-sm text-zinc-500">Paste an HTTP log line above to begin analysis</p>
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <section aria-label="Recent scans" className="flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500">Recent Scans</p>
              <button
                onClick={() => { setHistory([]); localStorage.removeItem(STORAGE_KEY); }}
                className="text-xs text-zinc-600 hover:text-zinc-400 transition-colors"
              >
                Clear
              </button>
            </div>
            <ul className="flex flex-col gap-1">
              {history.map((e) => (
                <li key={e.ts} className="flex items-center gap-3 px-3 py-2.5 rounded border border-zinc-800 bg-zinc-900 text-xs">
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${e.result.status === "SAFE" ? "bg-emerald-500" : "bg-red-500"}`} />
                  <span className="font-mono text-zinc-400 flex-1 truncate">{e.logLine}</span>
                  <span className={`shrink-0 font-semibold ${e.result.status === "SAFE" ? "text-emerald-400" : "text-red-400"}`}>
                    {e.result.status === "SAFE" ? "Safe" : (THREAT_LABEL[e.result.threat_label ?? ""] ?? e.result.threat_label)}
                  </span>
                  <span className="text-zinc-600 shrink-0 hidden sm:block">{timeAgo(e.ts)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

      </main>

      <footer className="border-t border-zinc-800 px-6 py-3">
        <p className="text-xs text-zinc-600 text-center">VulneraShield AI · TF-IDF + Logistic Regression · 98.7% CV Accuracy · 6 threat classes</p>
      </footer>
    </div>
  );
}
