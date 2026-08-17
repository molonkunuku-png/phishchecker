import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport } from './lib/api';
import type { ScanResult, HistoryItem } from './lib/types';

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
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.documentElement.classList.remove('dark', 'light');
    document.documentElement.classList.add(theme);
    try { localStorage.setItem('phishchecker-theme', theme); } catch { }
  }, [theme]);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    loadHistory();
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
    const link = `${window.location.origin}/#/scan/${result.id}`;
    try {
      await navigator.clipboard.writeText(link);
    } catch { }
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen bg-gray-950 text-gray-100 p-4">
        <header className="max-w-4xl mx-auto flex items-center justify-between py-6">
          <h1 className="text-2xl font-bold tracking-tight">PhishChecker</h1>
          <div className="flex items-center gap-2">
            <button
              onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }}
              className="px-3 py-1.5 rounded border border-gray-700 hover:border-gray-500 text-sm"
            >
              {showHistory ? 'Hide history' : 'History'}
            </button>
            <button
              onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
              className="px-3 py-1.5 rounded border border-gray-700 hover:border-gray-500 text-sm"
            >
              {theme === 'dark' ? 'Light' : 'Dark'}
            </button>
          </div>
        </header>

        <main className="max-w-4xl mx-auto space-y-6">
          <section className="rounded border border-gray-800 bg-gray-900 p-4">
            <form onSubmit={handleScan} className="space-y-3">
              <div className="flex gap-2">
                <input
                  ref={inputRef}
                  value={url}
                  onChange={e => setUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="flex-1 px-4 py-2 rounded bg-gray-950 border border-gray-700 focus:border-sky-500 outline-none"
                />
                <select
                  value={mode}
                  onChange={e => setMode(e.target.value)}
                  className="px-3 py-2 rounded bg-gray-950 border border-gray-700"
                >
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="it">IT</option>
                </select>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-6 py-2 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-50 font-medium"
                >
                  {loading ? 'Scanning...' : 'Scan'}
                </button>
              </div>
              {error && <p className="text-red-400 text-sm">{error}</p>}
            </form>
          </section>

          {result && (
            <section className="rounded border border-gray-800 bg-gray-900 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold ${
                    result.risk === 'high' ? 'bg-red-900 text-red-200' :
                    result.risk === 'suspicious' ? 'bg-yellow-900 text-yellow-200' :
                    'bg-green-900 text-green-200'
                  }`}>
                    {result.risk?.toUpperCase()}
                  </span>
                  <span className="text-3xl font-bold">{result.score ?? '—'}</span>
                </div>
                <div className="flex gap-2">
                  <button onClick={copyScanLink} className="text-xs px-2 py-1 rounded border border-gray-700 hover:border-gray-500">
                    Copy link
                  </button>
                  <button onClick={() => downloadExport('json')} className="text-xs px-2 py-1 rounded border border-gray-700 hover:border-gray-500">
                    Export JSON
                  </button>
                  <button onClick={() => downloadExport('csv')} className="text-xs px-2 py-1 rounded border border-gray-700 hover:border-gray-500">
                    Export CSV
                  </button>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div>
                  <span className="text-gray-500">URL</span>
                  <p className="break-all">{result.url}</p>
                </div>
                <div>
                  <span className="text-gray-500">Domain</span>
                  <p className="break-all">{result.domain}</p>
                </div>
                <div>
                  <span className="text-gray-500">Mode</span>
                  <p className="capitalize">{result.mode}</p>
                </div>
                <div>
                  <span className="text-gray-500">Started</span>
                  <p>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                </div>
              </div>
              {result.reasons && result.reasons.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-gray-300 mb-1">Findings</h3>
                  <ul className="list-disc pl-5 text-sm text-gray-300 space-y-1">
                    {result.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                  </ul>
                </div>
              )}
              {result.details && (
                <details className="text-sm text-gray-300">
                  <summary className="cursor-pointer select-none text-gray-400">Raw details</summary>
                  <pre className="mt-2 whitespace-pre-wrap break-words bg-gray-950 p-3 rounded border border-gray-800">
                    {JSON.stringify(result.details, null, 2)}
                  </pre>
                </details>
              )}
            </section>
          )}

          {showHistory && (
            <section className="rounded border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold">Recent scans</h2>
                <div className="flex gap-2">
                  <button onClick={loadHistory} className="text-xs text-sky-400 hover:text-sky-300">Refresh</button>
                </div>
              </div>
              {history.length === 0 && <p className="text-sm text-gray-500">No scans yet.</p>}
              {history.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-400 border-b border-gray-800">
                        <th className="py-2">Time</th>
                        <th>Domain</th>
                        <th>Risk</th>
                        <th>Score</th>
                        <th>Mode</th>
                      </tr>
                    </thead>
                    <tbody>
                      {history.map((h, i) => (
                        <tr key={h.id || i} className="border-b border-gray-800/50">
                          <td className="py-2 text-xs text-gray-400 whitespace-nowrap">
                            {h.started_at ? new Date(h.started_at).toLocaleString() : '—'}
                          </td>
                          <td className="py-2 break-all">{h.domain}</td>
                          <td className="py-2 capitalize">{h.risk}</td>
                          <td className="py-2">{h.score}</td>
                          <td className="py-2">{h.mode}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
        </main>
      </div>
    </ThemeContext.Provider>
  );
}
