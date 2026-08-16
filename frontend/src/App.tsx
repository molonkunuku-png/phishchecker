import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory } from './lib/api';
import type { ScanResult, HistoryItem } from './lib/types';

function loadInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('phishchecker-theme');
    if (stored === 'dark' || stored === 'light') return stored;
  } catch {}
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
  const [apiKey, setApiKey] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.documentElement.classList.remove('dark', 'light');
    document.documentElement.classList.add(theme);
    try { localStorage.setItem('phishchecker-theme', theme); } catch {}
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
    } catch {}
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
      const headers: Record<string, string> = {};
      if (apiKey.trim()) headers['X-Api-Key'] = apiKey.trim();
      const data = await submitScan(url.trim(), mode);
      setResult(data);
      setHistory(prev => [data as unknown as HistoryItem, ...prev].slice(0, 20));
    } catch (err: any) {
      setError(err?.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen bg-gray-950 text-gray-100 p-4">
        <header className="max-w-4xl mx-auto flex items-center justify-between py-6">
          <h1 className="text-2xl font-bold tracking-tight">PhishChecker</h1>
          <button
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
            className="px-3 py-1.5 rounded border border-gray-700 hover:border-gray-500 text-sm"
          >
            {theme === 'dark' ? 'Light' : 'Dark'}
          </button>
        </header>

        <main className="max-w-4xl mx-auto space-y-6">
          <form onSubmit={handleScan} className="space-y-3">
            <div className="flex gap-2">
              <input
                ref={inputRef}
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="flex-1 px-4 py-2 rounded bg-gray-900 border border-gray-700 focus:border-sky-500 outline-none"
              />
              <select
                value={mode}
                onChange={e => setMode(e.target.value)}
                className="px-3 py-2 rounded bg-gray-900 border border-gray-700"
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
            <div className="flex gap-2 items-center">
              <input
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="API key (optional)"
                className="px-3 py-2 rounded bg-gray-900 border border-gray-700 focus:border-sky-500 outline-none text-sm"
              />
              <span className="text-xs text-gray-500">Leave blank for unauthenticated if allowed</span>
            </div>
            {error && <p className="text-red-400 text-sm">{error}</p>}
          </form>

          {result && (
            <section className="rounded border border-gray-800 bg-gray-900 p-4 space-y-2">
              <div className="flex items-center gap-3">
                <span className={`px-2 py-1 rounded text-xs font-bold ${
                  result.risk === 'high' ? 'bg-red-900 text-red-200' :
                  result.risk === 'suspicious' ? 'bg-yellow-900 text-yellow-200' :
                  'bg-green-900 text-green-200'
                }`}>
                  {result.risk?.toUpperCase()}
                </span>
                <span className="text-2xl font-bold">{result.score ?? '—'}</span>
              </div>
              <p className="text-sm text-gray-400 break-all">{result.url}</p>
              {result.reasons && result.reasons.length > 0 && (
                <ul className="list-disc pl-5 text-sm text-gray-300 space-y-1">
                  {result.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                </ul>
              )}
              {result.id && (
                <p className="text-xs text-gray-500">Scan ID: {result.id}</p>
              )}
            </section>
          )}

          {history.length > 0 && (
            <section className="rounded border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold">Recent scans</h2>
                <button onClick={loadHistory} className="text-xs text-sky-400 hover:text-sky-300">Refresh</button>
              </div>
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
            </section>
          )}
        </main>
      </div>
    </ThemeContext.Provider>
  );
}
