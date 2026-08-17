import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';

function loadInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('phishchecker-theme');
    if (stored === 'dark' || stored === 'light') return stored;
  } catch { }
  return 'dark';
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(loadInitialTheme);
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState('standard');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [reportId, setReportId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.documentElement.classList.remove('dark', 'light');
    document.documentElement.classList.add(theme);
    try { localStorage.setItem('phishchecker-theme', theme); } catch { }
  }, [theme]);

  useEffect(() => {
    inputRef.current?.focus();
    const onHash = () => {
      const m = window.location.hash.match(/^#\/scan\/([^/]+)$/);
      setReportId(m ? decodeURIComponent(m[1]) : null);
    };
    onHash();
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    if (!reportId) return;
    setReport(null);
    fetchScanDetail(reportId).then(setReport).catch(() => setReport(null));
  }, [reportId]);

  useEffect(() => {
    loadHistory();
    getStatus().then(setStatus).catch(() => setStatus(null));
  }, []);

  async function loadHistory() {
    try {
      const data = await fetchHistory();
      setHistory(data.items || []);
    } catch { }
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }
    setLoading(true);
    try {
      const data = await submitScan(url.trim(), mode);
      setResult(data);
      setHistory(prev => [data as unknown as HistoryItem, ...prev].slice(0, 50));
    } catch (err: any) {
      setError(err?.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  async function copyScanLink() {
    if (!result?.id) return;
    const link = `${window.location.origin}${window.location.pathname}#/scan/${result.id}`;
    try {
      await navigator.clipboard.writeText(link);
    } catch { }
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen bg-[#F5F5F0] text-neutral-900 dark:bg-[#0a0a0a] dark:text-neutral-100 hx-texture">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 py-6">
          <header className="flex items-center justify-between mb-10">
            <h1 className="text-xl font-semibold tracking-tight">PhishChecker</h1>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }}
                className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium"
              >
                {showHistory ? 'Hide history' : 'History'}
              </button>
              <button
                onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
                className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium"
              >
                {theme === 'dark' ? 'Light' : 'Dark'}
              </button>
            </div>
          </header>

          {status && (
            <div className="mb-6 flex flex-wrap items-center gap-2 text-xs text-neutral-500 dark:text-neutral-400">
              <span className="hx-chip px-2 py-1 rounded-lg">{status.service} v{status.version}</span>
              {Object.entries(status.features).map(([k, v]) => (
                <span key={k} className={`hx-chip px-2 py-1 rounded-lg ${v ? '' : 'opacity-50 line-through'}`}>
                  {k}
                </span>
              ))}
            </div>
          )}

          <main className="space-y-6">
            <section className="hx-panel rounded-xl p-5">
              <form onSubmit={handleScan} className="space-y-4">
                <div className="flex gap-2">
                  <input
                    ref={inputRef}
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="hx-input flex-1 px-3.5 py-2 rounded-lg text-sm"
                  />
                  <select
                    value={mode}
                    onChange={e => setMode(e.target.value)}
                    className="hx-input px-3 py-2 rounded-lg text-sm"
                  >
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="it">IT</option>
                  </select>
                  <button
                    type="submit"
                    disabled={loading}
                    className="hx-btn-primary px-5 py-2 rounded-lg text-sm font-medium disabled:opacity-60"
                  >
                    {loading ? 'Scanning...' : 'Scan'}
                  </button>
                </div>
                {error && <p className="text-red-500 text-xs">{error}</p>}
              </form>
            </section>

            {!reportId && result && (
              <section className="hx-panel rounded-xl p-5 space-y-4 hx-animate-in">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className={`hx-risk-${result.risk === 'high' ? 'high' : result.risk === 'suspicious' ? 'suspicious' : 'low'} px-2 py-1 rounded-md text-xs font-semibold`}>
                      {result.risk?.toUpperCase()}
                    </span>
                    <span className="text-4xl font-semibold">{result.score ?? '—'}</span>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={copyScanLink} className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium">Copy link</button>
                    <button onClick={() => downloadExport('json')} className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium">Export JSON</button>
                    <button onClick={() => downloadExport('csv')} className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium">Export CSV</button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">URL</span>
                    <p className="break-all leading-relaxed">{result.url}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Domain</span>
                    <p className="break-all leading-relaxed">{result.domain}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Mode</span>
                    <p className="capitalize">{result.mode}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Started</span>
                    <p>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className="hx-divider pt-3">
                    <h3 className="text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-2">Findings</h3>
                    <ul className="list-disc pl-5 text-sm space-y-1">
                      {result.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}

                {result.details && (
                  <details className="text-sm">
                    <summary className="cursor-pointer select-none text-neutral-500 dark:text-neutral-400 text-xs">Raw details</summary>
                    <pre className="mt-2 whitespace-pre-wrap break-words bg-black/5 dark:bg-white/5 p-3 rounded-lg text-xs leading-relaxed">
                      {JSON.stringify(result.details, null, 2)}
                    </pre>
                  </details>
                )}
              </section>
            )}

            {reportId && report && (
              <section className="hx-panel rounded-xl p-5 space-y-4 hx-animate-in">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 className="text-base font-semibold">Scan report</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="hx-btn-ghost px-3 py-1.5 rounded-lg text-xs font-medium">
                    Back
                  </button>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <span className={`hx-risk-${report.risk === 'high' ? 'high' : report.risk === 'suspicious' ? 'suspicious' : 'low'} px-2 py-1 rounded-md text-xs font-semibold`}>{report.risk?.toUpperCase()}</span>
                  <span className="text-4xl font-semibold">{report.score ?? '—'}</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">URL</span>
                    <p className="break-all leading-relaxed">{report.url}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Domain</span>
                    <p className="break-all leading-relaxed">{report.domain}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Mode</span>
                    <p className="capitalize">{report.mode}</p>
                  </div>
                  <div>
                    <span className="block text-xs text-neutral-500 dark:text-neutral-400 mb-1">Started</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>
                {report.reasons && report.reasons.length > 0 && (
                  <div className="hx-divider pt-3">
                    <h3 className="text-xs font-medium text-neutral-500 dark:text-neutral-400 mb-2">Findings</h3>
                    <ul className="list-disc pl-5 text-sm space-y-1">
                      {report.reasons.map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
              </section>
            )}

            {reportId && !report && (
              <section className="hx-panel rounded-xl p-5 text-sm text-neutral-500 dark:text-neutral-400">Loading scan report...</section>
            )}

            {showHistory && (
              <section className="hx-panel rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold">Recent scans</h2>
                  <button onClick={loadHistory} className="text-xs text-sky-500 hover:text-sky-400">Refresh</button>
                </div>
                {history.length === 0 && <p className="text-sm text-neutral-500 dark:text-neutral-400">No scans yet.</p>}
                {history.length > 0 && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs text-neutral-500 dark:text-neutral-400 border-b border-black/5 dark:border-white/10">
                          <th className="py-2 pr-4 font-medium">Time</th>
                          <th className="py-2 pr-4 font-medium">Domain</th>
                          <th className="py-2 pr-4 font-medium">Risk</th>
                          <th className="py-2 pr-4 font-medium">Score</th>
                          <th className="py-2 font-medium">Mode</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <tr key={h.id || i} className="border-b border-black/5 dark:border-white/10 last:border-0">
                            <td className="py-2.5 pr-4 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                              {h.started_at ? new Date(h.started_at).toLocaleString() : '—'}
                            </td>
                            <td className="py-2.5 pr-4 break-all leading-relaxed">{h.domain}</td>
                            <td className="py-2.5 pr-4 capitalize">{h.risk}</td>
                            <td className="py-2.5 pr-4">{h.score}</td>
                            <td className="py-2.5 capitalize">{h.mode}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            )}
          </main>

          <footer className="mt-16 mb-8 text-center text-xs text-neutral-400 dark:text-neutral-600">
            PhishChecker · privacy-first scanning
          </footer>
        </div>
      </div>
    </ThemeContext.Provider>
  );
}
