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
      <div className="min-h-screen" style={{ background: 'var(--mapped-surface-page)', color: 'var(--mapped-text-body)' }}>
        <nav className="pc-nav">
          <a href="/" className="pc-nav-logo">PHISHCHECKER</a>
          <div className="pc-nav-items">
            <button onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }} className="pc-nav-item">History</button>
            <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className="pc-nav-item">{theme === 'dark' ? 'Light' : 'Dark'}</button>
            {status && <span className="pc-chip" style={{ marginLeft: '0.5em' }}>v{status.version}</span>}
          </div>
          <button onClick={() => { document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth' }); }} className="pc-nav-cta">Scan now</button>
        </nav>

        <main style={{ paddingTop: '4.2em' }}>
          <section className="pc-panel" style={{ borderTop: 'none', borderRadius: 0, borderLeft: 'none', borderRight: 'none' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '3em 1.5em' }}>
              <p className="pc-chip" style={{ marginBottom: '1em' }}>PRIVACY-FIRST SCANNING</p>
              <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(2.2rem, 5vw, 3.6rem)', lineHeight: 0.95, letterSpacing: '-0.03em', color: 'var(--mapped-text-headings)', marginBottom: '0.7em' }}>
                Check links before<br />you trust them.
              </h1>
              <p style={{ fontSize: '1.05em', lineHeight: 1.4, maxWidth: '26em', color: 'var(--mapped-text-body)', marginBottom: '1.8em' }}>
                Fast phishing-risk analysis with clear results. No accounts. No tracking. Just scan.
              </p>
              <form onSubmit={handleScan} id="scan" style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '0.5em', maxWidth: '42em' }}>
                <input ref={inputRef} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" className="pc-input" />
                <select value={mode} onChange={e => setMode(e.target.value)} className="pc-select">
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="it">IT</option>
                </select>
                <button type="submit" disabled={loading} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                  {loading ? 'Scanning...' : 'Scan'}
                </button>
              </form>
              {error && <p style={{ color: '#b91c1c', marginTop: '0.75em', fontSize: '0.85em' }}>{error}</p>}
            </div>
          </section>

          {!reportId && result && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: '#fff' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '1.2em' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em' }}>
                    <span className={`${result.risk === 'high' ? 'pc-risk-high' : result.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low'}`}>{result.risk?.toUpperCase()}</span>
                    <span style={{ fontSize: '2.4rem', fontWeight: 600, letterSpacing: '-0.03em', lineHeight: 1, color: 'var(--mapped-text-headings)' }}>{result.score ?? '—'}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap' }}>
                    <button onClick={copyScanLink} className="pc-btn-ghost">Copy link</button>
                    <button onClick={() => downloadExport('json')} className="pc-btn-ghost">Export JSON</button>
                    <button onClick={() => downloadExport('csv')} className="pc-btn-ghost">Export CSV</button>
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1.2em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>URL</span>
                    <p style={{ wordBreak: 'break-all' }}>{result.url}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain</span>
                    <p style={{ wordBreak: 'break-all' }}>{result.domain}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Mode</span>
                    <p style={{ textTransform: 'capitalize' }}>{result.mode}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Started</span>
                    <p>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>
                {result.reasons && result.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.6em' }}>Findings</h3>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em', fontSize: '0.9em', lineHeight: 1.5 }}>
                      {result.reasons.map((r: string, i: number) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
                {result.details && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>Raw details</summary>
                    <pre style={{ marginTop: '0.8em', whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '1em', background: 'var(--brand-grey-100)', fontSize: '0.8em', lineHeight: 1.6, border: '1px solid var(--mapped-border-default)' }}>{JSON.stringify(result.details, null, 2)}</pre>
                  </details>
                )}
              </div>
            </section>
          )}

          {reportId && report && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: '#fff' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Scan report</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="pc-btn-ghost">Back</button>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em', marginBottom: '1.2em', flexWrap: 'wrap' }}>
                  <span className={`${report.risk === 'high' ? 'pc-risk-high' : report.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low'}`}>{report.risk?.toUpperCase()}</span>
                  <span style={{ fontSize: '2.4rem', fontWeight: 600, letterSpacing: '-0.03em', lineHeight: 1, color: 'var(--mapped-text-headings)' }}>{report.score ?? '—'}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1.2em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>URL</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.url}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.domain}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Mode</span>
                    <p style={{ textTransform: 'capitalize' }}>{report.mode}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Started</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                </div>
                {report.reasons && report.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.6em' }}>Findings</h3>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em', fontSize: '0.9em', lineHeight: 1.5 }}>
                      {report.reasons.map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </section>
          )}

          {reportId && !report && (
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: '#fff' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em', color: 'var(--mapped-text-body)' }}>Loading scan report...</div>
            </section>
          )}

          {showHistory && (
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: '#fff' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Recent scans</h2>
                  <button onClick={loadHistory} className="pc-btn-ghost" style={{ color: 'var(--mapped-text-action)' }}>Refresh</button>
                </div>
                {history.length === 0 && <p style={{ color: 'var(--mapped-text-body)', fontSize: '0.9em' }}>No scans yet.</p>}
                {history.length > 0 && (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85em' }}>
                      <thead>
                        <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--mapped-border-default)', color: 'var(--mapped-text-body)' }}>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Time</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Domain</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Risk</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Score</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Mode</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.map((h, i) => (
                          <tr key={h.id || i} style={{ borderBottom: '1px solid var(--mapped-border-default)' }}>
                            <td style={{ padding: '0.7em 0.8em', whiteSpace: 'nowrap', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>{h.started_at ? new Date(h.started_at).toLocaleString() : '—'}</td>
                            <td style={{ padding: '0.7em 0.8em', wordBreak: 'break-all' }}>{h.domain}</td>
                            <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{h.risk}</td>
                            <td style={{ padding: '0.7em 0.8em' }}>{h.score}</td>
                            <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{h.mode}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </section>
          )}
        </main>

        <footer style={{ borderTop: '1px solid var(--mapped-border-default)', background: '#fff', marginTop: '2em' }}>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.5em', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5em', fontSize: '0.75em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>
            <span>PhishChecker</span>
            <span>Privacy-first scanning</span>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
