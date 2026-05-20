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
  { label: "Safe",          log: "GET /products.php?category=electronics HTTP/1.1" },
  { label: "SQLi",          log: "GET /profile.php?user=' OR 1=1-- HTTP/1.1" },
  { label: "XSS",           log: "POST /comment.php HTTP/1.1 text=<script>alert('XSS')</script>" },
  { label: "Path Traversal",log: "GET /download.php?file=../../../etc/passwd HTTP/1.1" },
  { label: "Cmd Injection", log: "GET /ping.php?host=127.0.0.1; cat /etc/passwd HTTP/1.1" },
  { label: "SSRF",          log: "GET /fetch.php?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" },
  { label: "Encoded SQLi",  log: "GET /view.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" },
];

const THREAT_META: Record<string, { name: string; color: string; badge: string; icon: string }> = {
  sqli:           { name: "SQL Injection",   color: "border-orange-500 bg-orange-950/30", badge: "text-orange-300 bg-orange-950 border-orange-700", icon: "🗄️" },
  xss:            { name: "XSS",             color: "border-yellow-500 bg-yellow-950/30", badge: "text-yellow-300 bg-yellow-950 border-yellow-700", icon: "💉" },
  path_traversal: { name: "Path Traversal",  color: "border-purple-500 bg-purple-950/30", badge: "text-purple-300 bg-purple-950 border-purple-700", icon: "📁" },
  cmd_injection:  { name: "Cmd Injection",   color: "border-red-500    bg-red-950/30",    badge: "text-red-300    bg-red-950    border-red-700",    icon: "⚡" },
  ssrf:           { name: "SSRF",            color: "border-pink-500   bg-pink-950/30",   badge: "text-pink-300   bg-pink-950   border-pink-700",   icon: "🌐" },
};

const EXAMPLE_STYLE: Record<string, string> = {
  "Safe":          "border-emerald-800 text-emerald-400 hover:bg-emerald-950/50",
  "SQLi":          "border-orange-800  text-orange-400  hover:bg-orange-950/50",
  "XSS":           "border-yellow-800  text-yellow-400  hover:bg-yellow-950/50",
  "Path Traversal":"border-purple-800  text-purple-400  hover:bg-purple-950/50",
  "Cmd Injection": "border-red-800     text-red-400     hover:bg-red-950/50",
  "SSRF":          "border-pink-800    text-pink-400    hover:bg-pink-950/50",
  "Encoded SQLi":  "border-orange-800  text-orange-400  hover:bg-orange-950/50",
};

const STORAGE_KEY = "vulnerashield-history";

// ── Sub-components ─────────────────────────────────────────────────────────

function ThreatBadge({ label }: { label: string }) {
  const meta = THREAT_META[label];
  if (!meta) return <span className="text-xs font-mono text-red-400">{label}</span>;
  return (
    <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full border ${meta.badge}`}>
      <span>{meta.icon}</span>
      {meta.name}
    </span>
  );
}

function ConfidenceBar({ value, level }: { value: string; level: "low" | "medium" | "high" }) {
  const pct = parseFloat(value);
  const color = level === "high" ? "bg-emerald-500" : level === "medium" ? "bg-yellow-500" : "bg-orange-500";
  const label = level === "high" ? "High" : level === "medium" ? "Medium" : "Low";
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex justify-between text-xs">
        <span className="text-zinc-300 uppercase tracking-widest">Model Confidence</span>
        <span className={`font-mono font-semibold ${level === "high" ? "text-emerald-400" : level === "medium" ? "text-yellow-400" : "text-orange-400"}`}>
          {value} · {label}
        </span>
      </div>
      <div
        className="h-1.5 bg-zinc-800 rounded-full overflow-hidden"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label={`Model confidence: ${value}`}
      >
        <div className={`h-full rounded-full transition-all duration-700 ${color}`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function ScanningLoader() {
  return (
    <div className="w-full rounded-xl border border-zinc-700 bg-zinc-900 p-6 flex flex-col gap-4" aria-hidden="true">
      <div className="flex items-center gap-3">
        <div className="relative w-8 h-8">
          <div className="w-8 h-8 rounded-full border-2 border-red-600 border-t-transparent animate-spin" />
        </div>
        <div className="flex flex-col gap-1">
          <div className="h-3 w-32 bg-zinc-700 rounded animate-pulse" />
          <div className="h-2 w-20 bg-zinc-800 rounded animate-pulse" />
        </div>
      </div>
      <div className="relative h-16 bg-zinc-800 rounded-lg overflow-hidden">
        <div className="scan-line absolute inset-x-0 h-0.5 bg-gradient-to-r from-transparent via-red-500 to-transparent" />
      </div>
      <div className="flex gap-2">
        <div className="h-2 flex-1 bg-zinc-800 rounded animate-pulse" />
        <div className="h-2 flex-1 bg-zinc-800 rounded animate-pulse" />
        <div className="h-2 w-12 bg-zinc-800 rounded animate-pulse" />
      </div>
      <p className="text-xs text-zinc-400 text-center tracking-widest uppercase">Analyzing threat patterns…</p>
    </div>
  );
}

function HistoryPanel({ entries, onClear }: { entries: HistoryEntry[]; onClear: () => void }) {
  if (entries.length === 0) return null;

  function timeAgo(ts: number) {
    const s = Math.floor((Date.now() - ts) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  }

  return (
    <section aria-label="Recent scans" className="w-full flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs font-semibold uppercase tracking-widest text-zinc-300">
          Recent Scans
        </p>
        <button
          onClick={onClear}
          className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors px-2 py-0.5 rounded border border-zinc-700 hover:border-zinc-500"
          aria-label="Clear scan history"
        >
          Clear all
        </button>
      </div>
      <ul className="flex flex-col gap-2">
        {entries.map((e, i) => {
          const meta = e.result.threat_label ? THREAT_META[e.result.threat_label] : null;
          return (
            <li
              key={e.ts}
              className={`flex items-center gap-3 px-4 py-3 rounded-lg border transition-colors ${
                e.result.status === "SAFE"
                  ? "bg-zinc-900 border-zinc-800"
                  : `bg-zinc-900 border-zinc-800 hover:${meta?.color ?? ""}`
              }`}
              aria-label={`Scan ${i + 1}`}
            >
              <span className={`w-2 h-2 rounded-full shrink-0 ${e.result.status === "SAFE" ? "bg-emerald-500" : "bg-red-500"}`} aria-hidden="true" />
              <span className="font-mono text-zinc-300 flex-1 truncate text-xs">{e.logLine}</span>
              <div className="flex items-center gap-2 shrink-0">
                {e.result.threat_label ? (
                  <ThreatBadge label={e.result.threat_label} />
                ) : (
                  <span className="text-xs text-emerald-400 font-semibold">SAFE</span>
                )}
                <span className="text-xs text-zinc-400 font-mono hidden sm:block">{timeAgo(e.ts)}</span>
              </div>
            </li>
          );
        })}
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
      setError(e instanceof Error ? e.message : "Failed to reach backend. Is it running on port 8000?");
    } finally {
      setLoading(false);
    }
  }

  function clearHistory() {
    setHistory([]);
    localStorage.removeItem(STORAGE_KEY);
  }

  const threatMeta = result?.threat_label ? THREAT_META[result.threat_label] : null;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 font-sans flex flex-col dot-grid">

      {/* Header */}
      <header className="border-b border-zinc-800 bg-zinc-950/90 backdrop-blur-sm sticky top-0 z-10 px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-red-600 to-red-800 flex items-center justify-center font-bold text-sm select-none shadow-lg shadow-red-900/30" aria-hidden="true">
            VS
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-tight leading-none">VulneraShield AI</h1>
            <p className="text-xs text-zinc-400 mt-0.5">Security Operations Center</p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="hidden sm:flex items-center gap-1.5">
            <span className={`w-2 h-2 rounded-full pulse-dot ${online === null ? "bg-zinc-600" : online ? "bg-emerald-500" : "bg-red-500"}`} />
            <span className="text-xs text-zinc-300">{online === null ? "Connecting…" : online ? "System Online" : "Offline"}</span>
          </div>
          <span className="text-xs text-zinc-400 hidden md:block">TF-IDF + LR · 98.7% CV Accuracy</span>
        </div>
      </header>

      {/* Stats bar */}
      <div className="border-b border-zinc-800/50 bg-zinc-900/40 px-6 py-2 flex items-center gap-6 overflow-x-auto">
        {[
          { label: "Accuracy",  value: "98.7%",   color: "text-emerald-400" },
          { label: "Classes",   value: "6",        color: "text-blue-400"    },
          { label: "Training",  value: "~1,968",   color: "text-violet-400"  },
          { label: "Algorithm", value: "TF-IDF + LR", color: "text-zinc-300" },
        ].map(s => (
          <div key={s.label} className="flex items-center gap-2 shrink-0">
            <span className="text-xs text-zinc-400 uppercase tracking-widest">{s.label}</span>
            <span className={`text-xs font-semibold font-mono ${s.color}`}>{s.value}</span>
          </div>
        ))}
      </div>

      <main className="flex-1 flex flex-col items-center px-4 sm:px-6 py-8 gap-6 max-w-3xl mx-auto w-full">

        {/* Input card */}
        <section aria-label="Log analysis input" className="w-full flex flex-col gap-4 bg-zinc-900/60 border border-zinc-800 rounded-xl p-5">
          <div className="flex items-start justify-between">
            <div>
              <label htmlFor="log-input" className="text-sm font-semibold text-zinc-200">
                HTTP Log Line
              </label>
              <p id="log-hint" className="text-xs text-zinc-400 mt-0.5">
                Paste a raw HTTP log entry — SQLi, XSS, Path Traversal, Cmd Injection, or SSRF
              </p>
            </div>
            {logLine && (
              <button onClick={() => { setLogLine(""); setResult(null); setError(null); }}
                className="text-xs text-zinc-400 hover:text-zinc-200 transition-colors shrink-0 ml-4">
                Clear
              </button>
            )}
          </div>

          <textarea
            id="log-input"
            aria-describedby="log-hint"
            aria-label="HTTP log line to analyze"
            className="w-full h-20 bg-zinc-950 border border-zinc-600 rounded-lg px-4 py-3 text-sm font-mono text-zinc-100 placeholder-zinc-500 resize-none focus:outline-none focus:ring-2 focus:ring-red-600/70 focus:border-red-600 transition-all"
            placeholder="e.g. GET /download.php?file=../../../etc/passwd HTTP/1.1"
            value={logLine}
            onChange={e => setLogLine(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) analyze(); }}
          />

          {/* Example buttons */}
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Example log lines">
            {EXAMPLES.map((ex, i) => (
              <button
                key={i}
                onClick={() => { setLogLine(ex.log); setResult(null); setError(null); }}
                className={`text-xs px-2.5 py-1 rounded-md border bg-transparent transition-colors ${EXAMPLE_STYLE[ex.label] ?? "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}
                aria-label={`Use example: ${ex.label}`}
              >
                {ex.label}
              </button>
            ))}
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-xs text-zinc-400 font-mono">{logLine.length} / 5000 chars · ⌘↵ to scan</span>
            <button
              onClick={analyze}
              disabled={loading || !logLine.trim()}
              aria-busy={loading}
              aria-label={loading ? "Analysis in progress" : "Analyze log line"}
              className="px-5 py-2 rounded-lg bg-red-600 hover:bg-red-500 disabled:bg-zinc-800 disabled:text-zinc-600 text-white text-sm font-semibold transition-all shadow-lg shadow-red-900/20 disabled:shadow-none"
            >
              {loading ? "Scanning…" : "Scan →"}
            </button>
          </div>
        </section>

        {/* Scanning loader */}
        {loading && <ScanningLoader />}

        {/* Error */}
        {error && (
          <div role="alert" className="w-full rounded-xl border border-orange-800 bg-orange-950/30 px-5 py-4 flex items-start gap-3">
            <span className="text-orange-500 text-lg shrink-0">⚠</span>
            <p className="text-sm text-orange-300">{error}</p>
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
            {/* Status card */}
            <div className={`rounded-xl border-2 px-6 py-5 flex flex-col gap-4 ${
              result.status === "SAFE"
                ? "border-emerald-700 bg-emerald-950/20"
                : `${threatMeta?.color ?? "border-red-700 bg-red-950/20"}`
            }`}>
              <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-4">
                  <div className={`w-12 h-12 rounded-xl flex items-center justify-center text-2xl shrink-0 ${
                    result.status === "SAFE" ? "bg-emerald-900/50" : "bg-red-900/30"
                  }`}>
                    {result.status === "SAFE" ? "✅" : (threatMeta?.icon ?? "⚠️")}
                  </div>
                  <div>
                    <p className={`text-lg font-bold tracking-tight ${result.status === "SAFE" ? "text-emerald-400" : "text-red-400"}`}>
                      {result.status === "SAFE" ? "Request is SAFE" : "THREAT DETECTED"}
                    </p>
                    {result.threat_label && (
                      <div className="mt-1.5">
                        <ThreatBadge label={result.threat_label} />
                      </div>
                    )}
                  </div>
                </div>

                {result.confidence_level === "low" && (
                  <span role="note" className="text-xs font-semibold px-3 py-1.5 rounded-lg border border-orange-600 text-orange-400 bg-orange-950/50">
                    Low confidence — review manually
                  </span>
                )}
              </div>

              <ConfidenceBar value={result.threat_confidence} level={result.confidence_level} />
            </div>

            {/* Remediation card */}
            {result.remediation_brief && (
              <div className="rounded-xl border border-zinc-700 bg-zinc-900/80 overflow-hidden">
                <div className="px-5 py-3 bg-zinc-800/80 flex items-center gap-2 border-b border-zinc-700">
                  <span className="text-sm">🛠</span>
                  <p className="text-xs font-bold uppercase tracking-widest text-zinc-200">
                    Remediation Playbook
                  </p>
                </div>

                <div className="divide-y divide-zinc-800">
                  <div className="px-5 py-4 flex gap-4">
                    <span className="w-6 h-6 rounded-full bg-red-900/50 border border-red-800 text-red-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">1</span>
                    <div className="flex flex-col gap-1">
                      <p className="text-xs text-zinc-300 uppercase tracking-wide font-semibold">Identified Threat</p>
                      <p className="text-sm font-semibold text-red-400">{result.remediation_brief.identified_threat}</p>
                    </div>
                  </div>

                  <div className="px-5 py-4 flex gap-4">
                    <span className="w-6 h-6 rounded-full bg-yellow-900/50 border border-yellow-800 text-yellow-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">2</span>
                    <div className="flex flex-col gap-1">
                      <p className="text-xs text-zinc-300 uppercase tracking-wide font-semibold">Mitigation Strategy</p>
                      <p className="text-sm text-zinc-200 leading-relaxed">{result.remediation_brief.mitigation_strategy}</p>
                    </div>
                  </div>

                  <div className="px-5 py-4 flex gap-4">
                    <span className="w-6 h-6 rounded-full bg-emerald-900/50 border border-emerald-800 text-emerald-400 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5">3</span>
                    <div className="flex flex-col gap-1 w-full">
                      <p className="text-xs text-zinc-300 uppercase tracking-wide font-semibold">Recommended Code Fix</p>
                      <pre className="text-xs font-mono bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-3 text-emerald-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {result.remediation_brief.recommended_code_fix}
                      </pre>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Empty state */}
        {!result && !error && !loading && history.length === 0 && (
          <div className="flex-1 flex flex-col items-center justify-center text-center gap-4 py-12">
            <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center text-3xl">
              🛡️
            </div>
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium text-zinc-300">Submit a log line to begin analysis</p>
              <p className="text-xs text-zinc-400">Detects 5 attack classes using ML-based pattern recognition</p>
            </div>
            <div className="grid grid-cols-3 gap-2 mt-2">
              {Object.entries(THREAT_META).map(([key, m]) => (
                <div key={key} className="px-3 py-2 rounded-lg bg-zinc-900 border border-zinc-800 text-center">
                  <span className="text-lg">{m.icon}</span>
                  <p className="text-xs text-zinc-300 mt-0.5">{m.name}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* History */}
        <HistoryPanel entries={history} onClear={clearHistory} />

      </main>

      <footer className="border-t border-zinc-800/50 px-6 py-3 text-center">
        <p className="text-xs text-zinc-500">VulneraShield AI · TF-IDF + Logistic Regression · 98.7% CV Accuracy · 6 threat classes</p>
      </footer>
    </div>
  );
}
