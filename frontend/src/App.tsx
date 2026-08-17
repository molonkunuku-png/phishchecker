import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';

function loadInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('phishchecker-theme');
    if (stored === 'dark' || stored === 'light') return stored;
  } catch { }
  return 'light';
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
      <div className="min-h-screen bg-[var(--color-background)] text-[var(--color-foreground)]">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 py-8">
          <header className="flex items-center justify-between mb-8">
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-semibold tracking-tight">PhishChecker</h1>
              {status && (
                <span className="pc-chip px-2 py-1 rounded-md hidden sm:inline">
                  v{status.version}
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }}
                className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium"
              >
                {showHistory ? 'Hide history' : 'History'}
              </button>
              <button
                onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
                className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium"
              >
                {theme === 'dark' ? 'Light' : 'Dark'}
              </button>
            </div>
          </header>

          <main className="space-y-5">
            <section className="pc-panel rounded-xl p-5">
              <form onSubmit={handleScan} className="space-y-4">
                <div className="flex gap-2">
                  <input
                    ref={inputRef}
                    value={url}
                    onChange={e => setUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="pc-input flex-1 px-3.5 py-2 rounded-lg text-sm"
                  />
                  <select
                    value={mode}
                    onChange={e => setMode(e.target.value)}
                    className="pc-input px-3 py-2 rounded-lg text-sm"
                  >
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="it">IT</option>
                  </select>
                  <button
                    type="submit"
                    disabled={loading}
                    className="pc-btn-primary px-5 py-2 rounded-lg text-sm font-medium disabled:opacity-60"
                  >
                    {loading ? 'Scanning...' : 'Scan'}
                  </button>
                </div>
                {error && <p className="text-sm" style={{ color: 'var(--color-destructive)' }}>{error}</p>}
              </form>
            </section>

            {!reportId && result && (
              <section className="pc-panel rounded-xl p-5 space-y-4 pc-animate-in">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                      result.risk === 'high' ? 'pc-risk-high' :
                      result.risk === 'suspicious' ? 'pc-risk-suspicious' :
                      'pc-risk-low'
                    }`}>
                      {result.risk?.toUpperCase()}
                    </span>
                    <span className="text-3xl font-semibold tracking-tight">{result.score ?? '—'}</span>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={copyScanLink} className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium">Copy link</button>
                    <button onClick={() => downloadExport('json')} className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium">Export JSON</button>
                    <button onClick={() => downloadExport('csv')} className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium">Export CSV</button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>URL</span>
                    <p className="break-all leading-relaxed">{result.url}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Domain</span>
                    <p className="break-all leading-relaxed">{result.domain}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Mode</span>
                    <p className="capitalize">{result.mode}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Started</span>
                    <p>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className="pc-divider pt-3">
                    <h3 className="text-xs font-semibold mb-2" style={{ color: 'var(--color-muted-foreground)' }}>Findings</h3>
                    <ul className="list-disc pl-5 text-sm space-y-1 leading-relaxed">
                      {result.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}

                {result.details && (
                  <details className="text-sm">
                    <summary className="cursor-pointer select-none text-sm font-medium" style={{ color: 'var(--color-muted-foreground)' }}>Raw details</summary>
                    <pre className="mt-2 whitespace-pre-wrap break-words p-3 rounded-lg text-xs leading-relaxed" style={{ background: 'var(--color-muted)' }}>
                      {JSON.stringify(result.details, null, 2)}
                    </pre>
                  </details>
                )}
              </section>
            )}

            {reportId && report && (
              <section className="pc-panel rounded-xl p-5 space-y-4 pc-animate-in">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <h2 className="text-base font-semibold">Scan report</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="pc-btn-ghost px-3 py-1.5 rounded-lg text-sm font-medium">
                    Back
                  </button>
                </div>
                <div className="flex flex-wrap items-center gap-3">
                  <span className={`px-2.5 py-1 rounded-md text-xs font-semibold ${
                    report.risk === 'high' ? 'pc-risk-high' :
                    report.risk === 'suspicious' ? 'pc-risk-suspicious' :
                    'pc-risk-low'
                  }`}>{report.risk?.toUpperCase()}</span>
                  <span className="text-3xl font-semibold tracking-tight">{report.score ?? '—'}</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>URL</span>
                    <p className="break-all leading-relaxed">{report.url}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Domain</span>
                    <p className="break-all leading-relaxed">{report.domain}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Mode</span>
                    <p className="capitalize">{report.mode}</p>
                  </div>
                  <div>
                    <span className="block text-xs font-medium mb-1" style={{ color: 'var(--color-muted-foreground)' }}>Started</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>
                {report.reasons && report.reasons.length > 0 && (
                  <div className="pc-divider pt-3">
                    <h3 className="text-xs font-semibold mb-2" style={{ color: 'var(--color-muted-foreground)' }}>Findings</h3>
                    <ul className="list-disc pl-5 text-sm space-y-1 leading-relaxed">
                      {report.reasons.map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
              </section>
            )}

            {reportId && !report && (
              <section className="pc-panel rounded-xl p-5 text-sm" style={{ color: 'var(--color-muted-foreground)' }}>Loading scan report...</section>
            )}

            {showHistory && (
              <section className="pc-panel rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-base font-semibold">Recent scans</h2>
                  <button onClick={loadHistory} className="text-sm font-medium" style={{ color: 'var(--color-secondary)' }}>Refresh</button>
                </div>
                {history.length === 0 && <p className="text-sm" style={{ color: 'var(--color-muted-foreground)' }}>No scans yet.</p>}
                {history.length > 0 && (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs font-medium" style={{ color: 'var(--color-muted-foreground)', borderBottom: '1px solid var(--color-border)' }}>
                          <th className="py-2 pr-4">Time</th>
                          <th className="py-2 pr-4">Domain</th>
                          <th className="py-2 pr-4">Risk</th>
                          <th className="py-2 pr-4">Score</th>
                          <th className="py-2">Mode</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <tr key={h.id || i} style={{ borderBottom: '1px solid var(--color-border)' }}>
                            <td className="py-2.5 pr-4 text-xs whitespace-nowrap" style={{ color: 'var(--color-muted-foreground)' }}>
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

          <footer className="mt-16 mb-8 text-center text-xs" style={{ color: 'var(--color-muted-foreground)' }}>
            PhishChecker · privacy-first scanning
          </footer>
        </div>
      </div>
    </ThemeContext.Provider>
  );
}
