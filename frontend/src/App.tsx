import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';

function downloadPDF(result: ScanResult) {
  const lines = [
    'PhishChecker Report',
    `URL: ${result.url}`,
    `Domain: ${result.domain}`,
    `Risk: ${result.risk}`,
    `Score: ${result.score ?? '—'}/100`,
    `Mode: ${result.mode}`,
    `Started: ${result.started_at ? new Date(result.started_at).toLocaleString() : '—'}`,
    '',
    'Findings:'
  ];
  if (result.reasons?.length) {
    for (const r of result.reasons) lines.push(`- ${r}`);
  } else {
    lines.push('- None');
  }
  const text = lines.join('\n');
  const blob = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `phishchecker-${result.domain || 'scan'}.txt`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function loadInitialTheme(): Theme {
  try {
    const stored = localStorage.getItem('phishchecker-theme');
    if (stored === 'dark' || stored === 'light') return stored;
  } catch { }
  return 'light';
}

function riskPercent(risk?: string): number {
  if (risk === 'high') return 85;
  if (risk === 'suspicious') return 55;
  if (risk === 'low') return 20;
  return 0;
}

function scoreColor(score?: number | null): string {
  if (score == null) return 'var(--mapped-text-body)';
  if (score < 40) return '#b91c1c';
  if (score < 70) return '#b45309';
  return '#047857';
}

type Category = 'headers' | 'url' | 'tls' | 'reputation' | 'behavior' | 'other';

function categoryOf(reason: string): Category {
  const r = reason.toLowerCase();
  if (/csp|x-frame|x-content-type|permissions-policy|referrer-policy|security header/.test(r)) return 'headers';
  if (/url|domain|typo|homograph|punycode|subdomain|ip|tld|extension|path|query|@/.test(r)) return 'url';
  if (/tls|ssl|certificate|https|lock/.test(r)) return 'tls';
  if (/reputation|blacklist|feed|phish|abuse|vt|sandbox|known/.test(r)) return 'reputation';
  if (/redirect|behavior|runtime|javascript|form|iframe|popup|autofocus/.test(r)) return 'behavior';
  return 'other';
}

function categorize(reasons: string[]): Record<Category, string[]> {
  const map: Record<Category, string[]> = { headers: [], url: [], tls: [], reputation: [], behavior: [], other: [] };
  for (const r of reasons) {
    map[categoryOf(r)].push(r);
  }
  return map;
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
  const [showAwareness, setShowAwareness] = useState(false);
  const [showApi, setShowApi] = useState(false);
  const [reportId, setReportId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [expandedFindings, setExpandedFindings] = useState(false);
  const [activeCategories, setActiveCategories] = useState<Set<Category>>(new Set());
  const [showStatus, setShowStatus] = useState(false);
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [showCompare, setShowCompare] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<string>('all');
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize] = useState(10);
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

  async function loadHistory(page = historyPage, page_size = historyPageSize) {
    try {
      const data = await fetchHistory({ page, page_size });
      setHistory(data.items || []);
    } catch { }
  }

  useEffect(() => {
    loadHistory(historyPage, historyPageSize);
  }, [historyFilter, historyPage]);

  useEffect(() => {
    getStatus().then(setStatus).catch(() => setStatus(null));
  }, []);

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setExpandedFindings(false);
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

  function toggleCategory(key: string) {
    setActiveCategories(prev => {
      const next = new Set(prev);
      const cat = key as Category;
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  const historyStats = {
    total: history.length,
    high: history.filter(h => h.risk === 'high').length,
    suspicious: history.filter(h => h.risk === 'suspicious').length,
    low: history.filter(h => h.risk === 'low').length,
  };

  const currentScore = result?.score ?? report?.score ?? null;
  const currentRisk = result?.risk ?? report?.risk ?? undefined;
  const riskPct = riskPercent(currentRisk);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen" style={{ background: 'var(--mapped-surface-page)', color: 'var(--mapped-text-body)' }}>
        <nav className="pc-nav">
          <a href="/" className="pc-nav-logo">PHISHCHECKER</a>
          <button onClick={() => { const items = document.getElementById('pc-nav-items'); if (items) items.classList.toggle('pc-nav-open'); }} className="pc-nav-hamburger" aria-label="Toggle navigation" style={{ display: 'none', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 1em', fontSize: '1.2em', lineHeight: 1 }}>☰</button>
          <div id="pc-nav-items" className="pc-nav-items">
            <button onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }} className="pc-nav-item">History</button>
            <button onClick={() => { setShowAwareness(v => !v); }} className="pc-nav-item">{showAwareness ? 'Scan' : 'Awareness'}</button>
            <button onClick={() => { setShowApi(v => !v); }} className="pc-nav-item">{showApi ? 'Scan' : 'API'}</button>
            <button onClick={() => { setShowStatus(v => !v); if (!showStatus) getStatus().then(setStatus).catch(() => setStatus(null)); }} className="pc-nav-item">{showStatus ? 'Scan' : 'Status'}</button>
            <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className="pc-nav-item" aria-label="Toggle theme">{theme === 'dark' ? 'Light' : 'Dark'}</button>
          </div>
          <button onClick={() => { document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth' }); }} className="pc-nav-cta">Scan now</button>
        </nav>

        <main style={{ paddingTop: '4.2em' }}>
          <section className="pc-panel" style={{ borderTop: 'none', borderRadius: 0, borderLeft: 'none', borderRight: 'none' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '3em 1.5em' }} className="pc-section">
              <p className="pc-chip" style={{ marginBottom: '1em', background: 'var(--mapped-surface-default)', borderColor: 'var(--mapped-border-default)', color: 'var(--mapped-text-action)' }}>PRIVACY-FIRST SCANNING</p>
              <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(2.2rem, 5vw, 3.6rem)', lineHeight: 0.95, letterSpacing: '-0.03em', color: 'var(--mapped-text-headings)', marginBottom: '0.7em' }}>
                Check links before<br />you trust them.
              </h1>
              <p style={{ fontSize: '1.05em', lineHeight: 1.4, maxWidth: '26em', color: 'var(--mapped-text-body)', marginBottom: '1.8em' }}>
                Fast phishing-risk analysis with clear results. No accounts. No tracking. Just scan.
              </p>
              <form onSubmit={handleScan} id="scan" className="pc-scan-form" style={{ display: 'grid', gridTemplateColumns: '1fr auto auto', gap: '0.5em', maxWidth: '42em' }}>
                <input ref={inputRef} value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" className="pc-input pc-placeholder" disabled={loading} />
                <select value={mode} onChange={e => setMode(e.target.value)} className="pc-select" disabled={loading}>
                  <option value="quick">Quick</option>
                  <option value="standard">Standard</option>
                  <option value="it">IT</option>
                </select>
                <button type="submit" disabled={loading} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                  {loading ? 'Scanning...' : 'Scan'}
                </button>
              </form>
              {loading && (
                <div style={{ marginTop: '1.2em', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em' }}>
                  <div className="pc-skeleton" />
                  <div className="pc-skeleton" />
                  <div className="pc-skeleton" />
                </div>
              )}
              {!loading && !result && !error && (
                <div style={{ marginTop: '1.2em', padding: '1.2em', border: '1px dashed var(--mapped-border-default)', background: 'var(--mapped-surface-default)', color: 'var(--mapped-text-body)', fontSize: '0.9em', textAlign: 'center' }}>
                  Paste a URL above and press Scan to analyze phishing risk.
                </div>
              )}
              {error && <p style={{ color: '#b91c1c', marginTop: '0.75em', fontSize: '0.85em' }}>{error}</p>}
            </div>
          </section>

          {!result && !loading && !reportId && (
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.6em 1.5em', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em' }} className="pc-section">
                {history.slice(0, 3).map((h) => (
                  <div key={h.id} style={{ border: '1px solid var(--mapped-border-default)', padding: '1em', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5em', gap: '0.5em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>{h.domain}</span>
                      <span className={`${h.risk === 'high' ? 'pc-risk-high' : h.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low'}`}>{h.risk}</span>
                    </div>
                    <div style={{ fontSize: '0.8em', color: 'var(--mapped-text-body)' }}>{h.score}/100</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {showAwareness && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', marginBottom: '0.8em' }}>Phishing awareness</h2>
                <div style={{ display: 'grid', gap: '1em', fontSize: '0.9em', lineHeight: 1.6 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>Red flags</h3>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                      <li>Unexpected links or attachments from unknown senders</li>
                      <li>URLs that impersonate known brands with typos or extra words</li>
                      <li>Requests for credentials, OTPs, or payments via email/SMS</li>
                      <li>Shortened URLs that hide the real destination</li>
                    </ul>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>How to check safely</h3>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                      <li>Hover to inspect the real link destination</li>
                      <li>Use this scanner for fast risk analysis</li>
                      <li>Check SSL/TLS and certificate age</li>
                      <li>Prefer official apps over links when possible</li>
                    </ul>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>Understanding risk</h3>
                    <p>High risk means multiple suspicious indicators were found. Suspicious means some signals warrant caution. Clean means no strong phishing indicators were detected in the checked URL.</p>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showApi && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', marginBottom: '0.8em' }}>API reference</h2>
                <div style={{ display: 'grid', gap: '1em', fontSize: '0.9em', lineHeight: 1.6 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>POST</span>
                      <code style={{ background: 'var(--brand-grey-200)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans</code>
                    </div>
                    <p>Submit a URL for scanning. Requires CSRF token from <code>/api/csrf</code>.</p>
                    <pre style={{ marginTop: '0.6em', whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '1em', background: 'var(--mapped-surface-default)', fontSize: '0.8em', lineHeight: 1.6, border: '1px solid var(--mapped-border-default)' }}>{`{
  "url": "https://example.com",
  "mode": "standard"
}`}</pre>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>GET</span>
                      <code style={{ background: 'var(--brand-grey-200)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans/history</code>
                    </div>
                    <p>List recent scans. Supports <code>page</code> and <code>page_size</code> query params.</p>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>GET</span>
                      <code style={{ background: 'var(--brand-grey-200)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/status</code>
                    </div>
                    <p>Service health, version, and feature flags.</p>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>GET</span>
                      <code style={{ background: 'var(--brand-grey-200)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans/export</code>
                    </div>
                    <p>Export scan history. Use <code>?format=json</code> or <code>?format=csv</code>.</p>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showStatus && status && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Service status</h2>
                  <span className="pc-chip" style={{ background: '#059669', color: '#fff', borderColor: '#059669' }}>Operational</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Service</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.service || 'PhishChecker'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Version</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.version || '—'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Public scanning</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.features?.publicScanning ? 'Enabled' : 'Disabled'}</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.2em', padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', fontSize: '0.85em', color: 'var(--mapped-text-body)', lineHeight: 1.6 }}>
                  This status view shows current service health and feature availability. For live scan results, use the scanner above.
                </div>
              </div>
            </section>
          )}

          {!reportId && result && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '1.2em' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em', flexWrap: 'wrap' }}>
                    <div style={{ position: 'relative', width: '3.2em', height: '3.2em' }}>
                      <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                        <circle cx="18" cy="18" r="15.5" fill="none" stroke="var(--brand-grey-200)" strokeWidth="3" />
                        <circle cx="18" cy="18" r="15.5" fill="none" stroke={scoreColor(currentScore)} strokeWidth="3" strokeDasharray={`${(riskPct / 100) * 97.39} 97.39`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 420ms ease, stroke 420ms ease' }} />
                      </svg>
                      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75em', fontWeight: 700, color: 'var(--mapped-text-headings)', transform: 'none' }}>{currentScore ?? '—'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk score</div>
                      <div style={{ fontSize: '0.85em', fontWeight: 600, color: scoreColor(currentScore) }}>{currentRisk ? currentRisk.toUpperCase() : '—'}</div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap' }}>
                    <button onClick={copyScanLink} className="pc-btn-ghost">Copy link</button>
                    <button onClick={() => downloadExport('json')} className="pc-btn-ghost">Export JSON</button>
                    <button onClick={() => downloadExport('csv')} className="pc-btn-ghost">Export CSV</button>
                    <button onClick={() => result && downloadPDF(result)} className="pc-btn-ghost">Export report</button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1.2em', fontSize: '0.9em', lineHeight: 1.5, marginBottom: '1.4em' }} className="pc-mobile-stack">
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
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Cert age</span>
                    <p>{(() => { const ssl = (result.details?.ssl || {}) as any; return ssl?.age_days != null ? `${ssl.age_days} days` : (ssl?.valid ? 'Valid' : '—'); })()}</p>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em', marginBottom: '1.4em' }}>
                  <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>Risk level</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: scoreColor(currentScore) }}>{currentRisk || '—'}</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${riskPct}%`, background: scoreColor(currentScore), transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                  <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>Score</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: 'var(--mapped-text-headings)' }}>{currentScore ?? '—'}/100</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${Math.max(0, Math.min(100, currentScore ?? 0))}%`, background: 'var(--mapped-text-action)', transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '0.6em', flexWrap: 'wrap' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>Findings</h3>
                      <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap' }}>
                        {(() => {
                          const cats = categorize(result.reasons);
                          const active = activeCategories;
                          return Object.entries(cats).map(([key, items]) => {
                            const count = items.length;
                            if (count === 0) return null;
                            const cat = key as Category;
                            const on = active.has(cat);
                            const label = `${key} (${count})`;
                            const bg = on ? 'var(--mapped-surface-default)' : 'transparent';
                            const border = on ? 'var(--mapped-border-default)' : 'var(--mapped-border-default)';
                            const color = on ? 'var(--mapped-text-body)' : 'var(--mapped-text-body)';
                            return (
                              <button key={key} type="button" onClick={() => toggleCategory(key)} style={{
                                background: bg,
                                border,
                                color,
                                padding: '0.35em 0.65em',
                                fontSize: '0.7em',
                                fontWeight: 500,
                                letterSpacing: '0.06em',
                                textTransform: 'uppercase',
                                cursor: 'pointer',
                                opacity: on ? 1 : 0.55
                              }}>{label}</button>
                            );
                          });
                        })()}
                      </div>
                    </div>
                    {(() => {
                      const cats = categorize(result.reasons);
                      const total = result.reasons.length;
                      return Object.entries(cats).filter(([, items]) => items.length > 0).map(([key, items]) => {
                        const pct = Math.round((items.length / Math.max(1, total)) * 100);
                        return (
                          <div key={key} style={{ marginBottom: '0.6em' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75em', color: 'var(--mapped-text-body)', marginBottom: '0.25em' }}>
                              <span style={{ textTransform: 'capitalize' }}>{key}</span>
                              <span>{pct}%</span>
                            </div>
                            <div style={{ height: '4px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                              <div style={{ height: '100%', width: `${pct}%`, background: 'var(--mapped-text-action)', transition: 'width 420ms ease' }} />
                            </div>
                          </div>
                        );
                      });
                    })()}
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.4em', fontSize: '0.9em', lineHeight: 1.5, marginTop: '0.8em' }}>
                      {(activeCategories.size === 0 ? result.reasons : result.reasons.filter((r: string) => activeCategories.has(categoryOf(r)))).map((r: string, i: number) => (
                        <li key={i} style={{ paddingLeft: '0.3em' }}>{r}</li>
                      ))}
                    </ul>
                    {expandedFindings && (
                      <div style={{ marginTop: '1em', padding: '1em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                        These signals are based on URL structure, domain age, known patterns, and routing behavior. High risk means multiple suspicious indicators were found. Low risk means no strong phishing signals were detected.
                      </div>
                    )}
                  </div>
                )}

                {result.details && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>Raw details</summary>
                    <pre style={{ marginTop: '0.8em', whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '1em', background: 'var(--mapped-surface-default)', fontSize: '0.8em', lineHeight: 1.6, border: '1px solid var(--mapped-border-default)' }}>{JSON.stringify(result.details, null, 2)}</pre>
                  </details>
                )}
              </div>
            </section>
          )}

          {reportId && report && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Scan report</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="pc-btn-ghost">Back</button>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em', marginBottom: '1.2em', flexWrap: 'wrap' }}>
                  <div style={{ position: 'relative', width: '3.2em', height: '3.2em' }}>
                    <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                      <circle cx="18" cy="18" r="15.5" fill="none" stroke="var(--brand-grey-200)" strokeWidth="3" />
                      <circle cx="18" cy="18" r="15.5" fill="none" stroke={scoreColor(report.score)} strokeWidth="3" strokeDasharray={`${riskPercent(report.risk)} 100`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 420ms ease, stroke 420ms ease' }} />
                    </svg>
                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75em', fontWeight: 700, color: 'var(--mapped-text-headings)', transform: 'none' }}>{report.score ?? '—'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk score</div>
                    <div style={{ fontSize: '0.85em', fontWeight: 600, color: scoreColor(report.score) }}>{report.risk ? report.risk.toUpperCase() : '—'}</div>
                  </div>
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
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Cert age</span>
                    <p>{(() => { const ssl = (report.details?.ssl || {}) as any; return ssl?.age_days != null ? `${ssl.age_days} days` : (ssl?.valid ? 'Valid' : '—'); })()}</p>
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
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em', color: 'var(--mapped-text-body)' }}>Loading scan report...</div>
            </section>
          )}

          {showHistory && (
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Recent scans</h2>
                  <button onClick={() => loadHistory()} className="pc-btn-ghost" style={{ color: 'var(--mapped-text-action)' }}>Refresh</button>
                </div>

                {history.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(12em, 1fr))', gap: '0.8em', marginBottom: '1.2em' }}>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Total</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--mapped-text-headings)' }}>{historyStats.total}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>High</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: '#b91c1c' }}>{historyStats.high}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Suspicious</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: '#b45309' }}>{historyStats.suspicious}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Low</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: '#047857' }}>{historyStats.low}</div>
                    </div>
                  </div>
                )}

                {history.length === 0 && <p style={{ color: 'var(--mapped-text-body)', fontSize: '0.9em' }}>No scans yet.</p>}
                {history.length > 0 && (
                  <div style={{ overflowX: 'auto' }}>
                    <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap', marginBottom: '0.8em' }}>
                      {['all','high','suspicious','low'].map(f => (
                        <button key={f} type="button" onClick={() => { setHistoryFilter(f); setHistoryPage(1); }} className="pc-btn-ghost" style={{ opacity: historyFilter === f ? 1 : 0.6 }}>{f === 'all' ? 'All' : f[0].toUpperCase() + f.slice(1)}</button>
                      ))}
                    </div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85em' }}>
                      <thead>
                        <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--mapped-border-default)', color: 'var(--mapped-text-body)' }}>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', width: '2.5em' }}>Compare</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Time</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Domain</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Risk</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Score</th>
                          <th style={{ padding: '0.6em 0.8em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase' }}>Mode</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.filter(h => historyFilter === 'all' || h.risk === historyFilter).map((h, i) => {
                          const checked = compareIds.includes(h.id || '');
                          return (
                            <tr key={h.id || i} style={{ borderBottom: '1px solid var(--mapped-border-default)', background: checked ? 'var(--mapped-surface-default)' : 'transparent' }}>
                              <td style={{ padding: '0.7em 0.8em' }}>
                                <input type="checkbox" checked={checked} onChange={() => {
                                  setCompareIds(prev => prev.includes(h.id || '') ? prev.filter(x => x !== h.id) : [...prev, h.id || ''].slice(0, 2));
                                }} />
                              </td>
                              <td style={{ padding: '0.7em 0.8em', whiteSpace: 'nowrap', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>{h.started_at ? new Date(h.started_at).toLocaleString() : '—'}</td>
                              <td style={{ padding: '0.7em 0.8em', wordBreak: 'break-all' }}>{h.domain}</td>
                              <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{h.risk}</td>
                              <td style={{ padding: '0.7em 0.8em' }}>{h.score}</td>
                              <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{h.mode}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.8em', fontSize: '0.8em', color: 'var(--mapped-text-body)' }}>
                      <span>{history.length ? `Page ${historyPage}` : ''}</span>
                      <div style={{ display: 'flex', gap: '0.4em' }}>
                        <button disabled={historyPage <= 1} onClick={() => setHistoryPage(p => p - 1)} className="pc-btn-ghost">Prev</button>
                        <button disabled={history.length < historyPageSize} onClick={() => setHistoryPage(p => p + 1)} className="pc-btn-ghost">Next</button>
                      </div>
                    </div>
                  </div>
                )}
                {compareIds.length === 2 && (
                  <div style={{ marginTop: '1.2em', display: 'flex', justifyContent: 'flex-end' }}>
                    <button onClick={() => setShowCompare(true)} className="pc-btn-primary" style={{ padding: '0.7em 1em' }}>Compare selected</button>
                  </div>
                )}
              </div>
            </section>
          )}

          {showCompare && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>Comparison</h2>
                  <button onClick={() => setShowCompare(false)} className="pc-btn-ghost">Close</button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em' }}>
                  {compareIds.map(id => {
                    const item = history.find(h => h.id === id);
                    if (!item) return null;
                    const scoreColorVal = scoreColor(item.score);
                    return (
                      <div key={id} style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                        <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain</div>
                        <div style={{ wordBreak: 'break-all', marginBottom: '1em' }}>{item.domain}</div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6em', fontSize: '0.85em' }}>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk</div>
                            <div style={{ color: scoreColorVal, fontWeight: 600 }}>{item.risk}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Score</div>
                            <div style={{ fontWeight: 600 }}>{item.score}/100</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Mode</div>
                            <div style={{ textTransform: 'capitalize' }}>{item.mode}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Duration</div>
                            <div>{item.duration_ms != null ? `${item.duration_ms} ms` : '—'}</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>
          )}

          <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
              <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--mapped-text-headings)', marginBottom: '0.8em' }}>How it works</h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }}>
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>01 — Paste</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>Drop any link into the scanner. We do not require accounts or personal data.</p>
                </div>
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>02 — Analyze</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>Check domain signals, URL patterns, and routing behavior for phishing indicators.</p>
                </div>
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>03 — Decide</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>Get a risk score and clear findings. Export or share the result when needed.</p>
                </div>
              </div>
            </div>
          </section>
        </main>

        <footer style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginTop: '2em' }}>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.5em', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5em', fontSize: '0.75em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>
            <span>PhishChecker</span>
            <span>Privacy-first scanning</span>
            <span>{status?.version ? `v${status.version}` : ''}</span>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
