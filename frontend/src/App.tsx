import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail, submitBulk } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';

function downloadPDF(result: ScanResult) {
  const lines = [
    'PhishChecker Report',
    `URL: ${result.url}`,
    `Domain: ${result.domain}`,
    `Risk: ${result.risk}`,
    `Score: ${result.score ?? '—'}/100`,
    `Mode: ${modeLabel(result.mode)}`,
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

function relativeTime(iso?: string | null): string {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return 'Just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} min ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr} hr ago`;
  const day = Math.floor(hr / 24);
  return `${day} day${day === 1 ? '' : 's'} ago`;
}

function modeLabel(mode?: string): string {
  if (!mode) return '—';
  const m = mode.toLowerCase();
  if (m === 'it') return 'IT';
  if (m === 'quick') return 'Quick';
  if (m === 'standard') return 'Standard';
  if (m === 'family') return 'Family';
  return mode.charAt(0).toUpperCase() + mode.slice(1);
}

function familySummary(result: ScanResult | null): string {
  if (!result) return '—';
  const risk = (result.risk || '').toLowerCase();
  if (risk === 'high') return 'This looks risky. Avoid entering any details or downloading anything from this site.';
  if (risk === 'suspicious') return 'Some signs are concerning. Treat this site with extra caution.';
  if (risk === 'clean') return 'No strong warning signs were found, but always stay cautious online.';
  return 'Scan complete. When in doubt, verify with the official source.';
}

function findingSummary(r: string): string {
  const low = r.toLowerCase();
  if (/missing.*header/.test(low)) return 'Add the missing security header to improve response hardening.';
  if (/strict-transport-security/.test(low)) return 'Enable HSTS so browsers only use HTTPS for this origin.';
  if (/content-security-policy/.test(low)) return 'Add CSP to limit inline script, framing, and unsafe sources.';
  if (/x-frame-options/.test(low)) return 'Set X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.';
  if (/x-content-type-options/.test(low)) return 'Set X-Content-Type-Options: nosniff to avoid MIME-type confusion.';
  if (/referrer-policy/.test(low)) return 'Add a referrer policy to control how much referrer information is sent.';
  if (/permissions-policy/.test(low)) return 'Add Permissions-Policy to disable unused browser features.';
  if (/ssl validation issue/.test(low)) return 'Fix TLS validation so the certificate chain, hostname, or expiry passes.';
  if (/could not fetch url/.test(low)) return 'The scanner could not fetch the URL; retry from a stable network.';
  if (/listed in/.test(low)) return 'This domain appeared in a public phishing/threat feed.';
  if (/short or unusual domain shape/.test(low)) return 'Short or unusually shaped domains are more common in phishing.';
  return 'Review this signal as part of the overall URL risk assessment.';
}

function riskColor(risk?: string): string {
  if (risk === 'high') return '#b91c1c';
  if (risk === 'suspicious') return '#b45309';
  if (risk === 'clean') return '#047857';
  return 'var(--mapped-text-body)';
}

function scoreColor(score?: number | null): string {
  if (score == null) return 'var(--mapped-text-body)';
  if (score < 50) return '#b91c1c';
  if (score < 80) return '#b45309';
  return '#047857';
}

function confidenceMeta(score?: number | null): { label: string; color: string } | null {
  if (score == null) return null;
  if (score < 50) return { label: 'High risk', color: '#b91c1c' };
  if (score < 80) return { label: 'Elevated risk', color: '#b45309' };
  return { label: 'Low risk', color: '#047857' };
}

function sslGrade(details?: Record<string, unknown>): { grade: string; color: string } | null {
  const ssl = (details?.ssl || {}) as any;
  if (!ssl || !ssl.valid) return { grade: 'F', color: '#b91c1c' };
  const age = ssl.age_days as number | undefined;
  if (age == null) return { grade: 'A', color: '#047857' };
  if (age < 30) return { grade: 'A+', color: '#047857' };
  if (age < 180) return { grade: 'A', color: '#059669' };
  if (age < 365) return { grade: 'B', color: '#b45309' };
  return { grade: 'C', color: '#b91c1c' };
}

type Severity = 'high' | 'medium' | 'low';

function severityOf(reason: string): Severity {
  const r = reason.toLowerCase();
  if (/certificate|tls|ssl|https|lock/.test(r)) return 'high';
  if (/phish|blacklist|abuse|known|sandbox|could not fetch/.test(r)) return 'high';
  if (/missing.*header|x-frame|x-content-type|referrer-policy|permissions-policy|strict-transport-security/.test(r)) return 'medium';
  if (/redirect|javascript|iframe|popup|form|behavior/.test(r)) return 'medium';
  return 'low';
}

function severityStyle(s: Severity): { bg: string; text: string } {
  if (s === 'high') return { bg: '#b91c1c', text: '#fff' };
  if (s === 'medium') return { bg: '#b45309', text: '#fff' };
  return { bg: '#047857', text: '#fff' };
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(loadInitialTheme);
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState('standard');
  const [familyMode, setFamilyMode] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [showAwareness, setShowAwareness] = useState(false);
  const [awarenessMode, setAwarenessMode] = useState<'simple' | 'detailed'>('simple');
  const [showApi, setShowApi] = useState(false);
  const [reportId, setReportId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [showStatus, setShowStatus] = useState(false);
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [showCompare, setShowCompare] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<string>('all');
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPageSize] = useState(10);
  const [historySearch, setHistorySearch] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);
  const [navShadow, setNavShadow] = useState(false);
  const [findingFilter, setFindingFilter] = useState<string>('all');
  const [batchMode, setBatchMode] = useState(false);
  const [batchInput, setBatchInput] = useState('');
  const [batchResults, setBatchResults] = useState<ScanResult[] | null>(null);
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchError, setBatchError] = useState<string | null>(null);

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
    const onScroll = () => setNavShadow(window.scrollY > 10);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
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

  const visibleHistory = historySearch
    ? history.filter(h =>
        (h.domain || '').toLowerCase().includes(historySearch.toLowerCase()) ||
        (h.url || '').toLowerCase().includes(historySearch.toLowerCase()) ||
        (h.risk || '').toLowerCase().includes(historySearch.toLowerCase())
      )
    : history;

  useEffect(() => {
    setHistoryPage(1);
    loadHistory(1, historyPageSize);
  }, [historyFilter]);

  useEffect(() => {
    loadHistory(historyPage, historyPageSize);
  }, [historyPage]);

  useEffect(() => {
    getStatus().then(setStatus).catch(() => setStatus(null));
  }, []);

  function validateUrl(u: string): { ok: boolean; msg?: string } {
    const trimmed = u.trim();
    if (!trimmed) return { ok: false, msg: 'Enter a URL' };
    let host = '';
    try {
      const parsed = new URL(trimmed);
      host = parsed.hostname;
    } catch {
      try {
        host = new URL('https://' + trimmed).hostname;
      } catch {
        return { ok: false, msg: 'Enter a valid URL like https://example.com' };
      }
    }
    if (!host.includes('.') || host.endsWith('.') || host.startsWith('.')) return { ok: false, msg: 'Domain looks incomplete' };
    return { ok: true };
  }

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setFindingFilter('all');
    const trimmed = url.trim();
    const v = validateUrl(trimmed);
    if (!v.ok) {
      setError(v.msg || 'Please enter a valid URL');
      return;
    }
    setLoading(true);
    try {
      const scanMode = familyMode ? 'family' : mode;
      const data = await submitScan(trimmed, scanMode);
      setResult(data);
      setHistory(prev => [data as unknown as HistoryItem, ...prev].slice(0, 50));
    } catch (err: any) {
      setError(err?.response?.data?.error || err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleBatch(e: React.FormEvent) {
    e.preventDefault();
    setBatchError(null);
    setBatchResults(null);
    const raw = batchInput.split(/\n+/).map(s => s.trim()).filter(Boolean).slice(0, 20);
    if (!raw.length) {
      setBatchError('Enter at least one URL');
      return;
    }
    const invalid = raw.find(u => !validateUrl(u).ok);
    if (invalid) {
      setBatchError(`Invalid URL: ${invalid}`);
      return;
    }
    setBatchRunning(true);
    try {
      const data = await submitBulk(raw, 'quick');
      setBatchResults(data.results || []);
    } catch (err: any) {
      setBatchError(err?.response?.data?.error || err.message || 'Batch scan failed');
    } finally {
      setBatchRunning(false);
    }
  }

  async function copyScanLink() {
    if (!result?.id) return;
    const link = `${window.location.origin}${window.location.pathname}#/scan/${result.id}`;
    try {
      await navigator.clipboard.writeText(link);
    } catch { }
  }

  async function copyScanJSON() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    } catch { }
  }

  const historyStats = {
    total: visibleHistory.length,
    high: visibleHistory.filter(h => h.risk === 'high').length,
    suspicious: visibleHistory.filter(h => h.risk === 'suspicious').length,
    low: visibleHistory.filter(h => h.risk === 'low').length,
  };

  const currentScore = result?.score ?? report?.score ?? null;
  const currentRisk = result?.risk ?? report?.risk ?? undefined;
  const riskPct = riskPercent(currentRisk);
  const confidence = confidenceMeta(currentScore);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen" style={{ background: 'var(--mapped-surface-page)', color: 'var(--mapped-text-body)' }}>
        <nav className={`pc-nav ${navShadow ? 'pc-nav-shadow' : ''}`} style={{ overflow: 'visible' }}>
          <a href="#main" className="pc-skip-link">Skip to content</a>
          <a href="/" className="pc-nav-logo">PHISHCHECKER</a>
          <button onClick={() => { const items = document.getElementById('pc-nav-items'); if (items) items.classList.toggle('pc-nav-open'); }} className="pc-nav-hamburger" aria-label="Toggle navigation" style={{ display: 'none', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 1em', fontSize: '1.2em', lineHeight: 1 }}>☰</button>
          <div id="pc-nav-items" className="pc-nav-items">
            <button onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }} className={`pc-nav-item ${showHistory ? 'pc-nav-item-active' : ''}`}>History</button>
            <button onClick={() => { setShowAwareness(v => !v); }} className={`pc-nav-item ${showAwareness ? 'pc-nav-item-active' : ''}`}>{showAwareness ? 'Scan' : 'Awareness'}</button>
            <button onClick={() => { setShowApi(v => !v); }} className={`pc-nav-item ${showApi ? 'pc-nav-item-active' : ''}`}>{showApi ? 'Scan' : 'API'}</button>
            <button onClick={() => { setShowStatus(v => !v); if (!showStatus) getStatus().then(setStatus).catch(() => setStatus(null)); }} className={`pc-nav-item ${showStatus ? 'pc-nav-item-active' : ''}`}>{showStatus ? 'Scan' : 'Status'}</button>
            <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className={`pc-nav-item ${theme === 'dark' ? 'pc-nav-item-active' : ''}`} aria-label="Toggle theme">{theme === 'dark' ? 'Theme ☀' : 'Theme ☾'}</button>
          </div>
          <button onClick={() => { document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth' }); }} className="pc-nav-cta" style={{ marginLeft: 'auto', flexShrink: 0 }}>Scan now</button>
        </nav>

        <main id="main" style={{ paddingTop: '4.2em' }}>
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
                <label htmlFor="url-input" style={{ position: 'absolute', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', width: '1px', height: '1px' }}>URL to check</label>
                <div style={{ position: 'relative' }}>
                  <input ref={inputRef} id="url-input" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" className="pc-input pc-placeholder" disabled={loading} aria-describedby="url-hint" style={{ paddingRight: url ? '2.2em' : undefined }} />
                  {url && (
                    <button type="button" onClick={() => setUrl('')} disabled={loading} aria-label="Clear URL" style={{ position: 'absolute', right: '0.6em', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.9em', padding: '0.3em', lineHeight: 1 }}>×</button>
                  )}
                </div>
                <select value={mode} onChange={e => setMode(e.target.value)} className="pc-select" disabled={loading || familyMode} aria-label="Scan mode">
                  <option value="quick">Quick — fast surface check</option>
                  <option value="standard">Standard — balanced depth</option>
                  <option value="it">IT — deep technical scan</option>
                </select>
                {mode && (
                  <span id="url-hint" style={{ fontSize: '0.7em', color: 'var(--mapped-text-body)', padding: '0.4em 0' }}>
                    {mode === 'quick' ? 'Lightweight: headers, TLS, basic patterns.' : mode === 'standard' ? 'Balanced: headers, TLS, domain patterns, behavior.' : 'Deep: full header audit, TLS details, behavior, routing, extended intel.'}
                  </span>
                )}
                <button type="submit" disabled={loading} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                  {loading ? (<span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />Scanning...</span>) : 'Scan'}
                </button>
              </form>
              <div style={{ marginTop: '0.8em', display: 'flex', alignItems: 'center', gap: '0.6em', flexWrap: 'wrap' }}>
                <button type="button" onClick={() => setFamilyMode(v => !v)} className="pc-btn-ghost" style={{ fontSize: '0.85em', color: familyMode ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-action)', background: familyMode ? 'var(--mapped-surface-action)' : 'transparent', border: '1px solid', borderColor: familyMode ? 'var(--mapped-surface-action)' : 'var(--mapped-border-default)' }}>
                  {familyMode ? 'Family mode: on' : 'Scanning for someone else? Try Family mode'}
                </button>
                {familyMode && (
                  <span style={{ fontSize: '0.8em', color: 'var(--mapped-text-body)' }}>Showing a simpler result with plain-language guidance.</span>
                )}
              </div>
              {loading && (
                <div aria-busy="true" style={{ marginTop: '1.2em', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em' }}>
                  <div className="pc-skeleton" />
                  <div className="pc-skeleton" />
                  <div className="pc-skeleton" />
                </div>
              )}
              {!loading && !result && !error && (
                <div aria-live="polite" style={{ marginTop: '1.2em', padding: '1.2em', border: '1px dashed var(--mapped-border-default)', background: 'var(--mapped-surface-default)', color: 'var(--mapped-text-body)', fontSize: '0.9em', textAlign: 'center' }}>
                  Paste a URL above and press Enter to scan.
                  <div style={{ marginTop: '0.4em', fontSize: '0.75em', opacity: 0.8 }}>Keyboard shortcut: focus URL, then Enter</div>
                </div>
              )}
              <div style={{ marginTop: '0.8em', display: 'inline-flex', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', opacity: 0.85 }}>
                <span aria-hidden="true" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3em' }}>🔒</span>
                <span>No personal data stored</span>
              </div>
              {error && (
                <p role="alert" aria-live="assertive" style={{ color: '#b91c1c', marginTop: '0.75em', fontSize: '0.85em', display: 'flex', alignItems: 'center', gap: '0.5em', flexWrap: 'wrap' }}>
                  {error}
                  <button type="button" onClick={() => setError(null)} className="pc-btn-ghost" style={{ fontSize: '0.8em' }}>Retry</button>
                </p>
              )}
            </div>
          </section>

          <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.6em 1.5em' }} className="pc-section">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '0.8em', flexWrap: 'wrap' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--mapped-text-headings)' }}>Batch scan</h2>
                <button type="button" onClick={() => { setBatchMode(v => !v); setBatchResults(null); setBatchError(null); }} className="pc-btn-ghost" style={{ fontSize: '0.7em' }}>{batchMode ? 'Close batch' : 'Open batch'}</button>
              </div>
              {batchMode && (
                <form onSubmit={handleBatch} style={{ display: 'grid', gap: '0.6em', maxWidth: '42em' }}>
                  <label htmlFor="batch-input" style={{ position: 'absolute', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', width: '1px', height: '1px' }}>URLs</label>
                  <textarea id="batch-input" value={batchInput} onChange={e => setBatchInput(e.target.value)} placeholder="One URL per line&#10;https://example.com&#10;https://example.org" className="pc-input pc-placeholder" disabled={batchRunning} rows={6} style={{ resize: 'vertical' }} />
                  <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap' }}>
                    <button type="submit" disabled={batchRunning} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                      {batchRunning ? (<span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />Scanning...</span>) : 'Scan batch'}
                    </button>
                    <span style={{ fontSize: '0.7em', color: 'var(--mapped-text-body)', alignSelf: 'center' }}>Max 20 URLs</span>
                  </div>
                  {batchError && (
                    <p style={{ color: '#b91c1c', marginTop: '0.4em', fontSize: '0.85em', display: 'flex', alignItems: 'center', gap: '0.5em', flexWrap: 'wrap' }}>
                      {batchError}
                      <button type="button" onClick={() => setBatchError(null)} className="pc-btn-ghost" style={{ fontSize: '0.8em' }}>Retry</button>
                    </p>
                  )}
                  {batchResults && (
                    <div style={{ marginTop: '0.8em', display: 'grid', gap: '0.6em' }}>
                      {batchResults.map(r => (
                        <div key={r.id || r.url} style={{ border: '1px solid var(--mapped-border-default)', padding: '0.8em', background: 'var(--mapped-surface-default)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5em', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '0.75em', fontWeight: 600, color: 'var(--mapped-text-headings)', wordBreak: 'break-all' }}>{r.domain || r.url}</span>
                            <span className={`${r.risk === 'high' ? 'pc-risk-high' : r.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low'}`}>{r.risk}</span>
                          </div>
                          <div style={{ fontSize: '0.8em', color: 'var(--mapped-text-body)', marginTop: '0.3em' }}>{r.score}/100 · {modeLabel(r.mode)} · {r.duration_ms != null ? `${r.duration_ms} ms` : '—'}</div>
                          {r.reasons?.length ? (
                            <ul style={{ listStyle: 'disc', paddingLeft: '1.1em', marginTop: '0.4em', fontSize: '0.8em', color: 'var(--mapped-text-body)', display: 'grid', gap: '0.2em' }}>
                              {r.reasons.map((x, i) => <li key={i}>{x}</li>)}
                            </ul>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  )}
                </form>
              )}
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
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '0.8em', flexWrap: 'wrap' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', margin: 0 }}>Phishing awareness</h2>
                  <div style={{ display: 'inline-flex', gap: '0.4em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '0.3em', borderRadius: '999px' }}>
                    <button type="button" onClick={() => setAwarenessMode('simple')} className="pc-btn-ghost" style={{ fontSize: '0.8em', borderRadius: '999px', background: awarenessMode === 'simple' ? 'var(--mapped-surface-action)' : 'transparent', color: awarenessMode === 'simple' ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-body)' }}>Simple mode</button>
                    <button type="button" onClick={() => setAwarenessMode('detailed')} className="pc-btn-ghost" style={{ fontSize: '0.8em', borderRadius: '999px', background: awarenessMode === 'detailed' ? 'var(--mapped-surface-action)' : 'transparent', color: awarenessMode === 'detailed' ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-body)' }}>Detailed mode</button>
                  </div>
                </div>

                {awarenessMode === 'simple' && (
                  <div style={{ fontSize: '1.05em', lineHeight: 1.7, color: 'var(--mapped-text-body)' }}>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <p style={{ margin: 0, fontSize: '1.05em' }}>Phishing is when someone pretends to be a trusted person or brand.</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em' }}>They want your password, OTP, or payment.</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em' }}>New or unknown senders are the biggest warning sign.</p>
                    </div>

                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '1em', fontWeight: 700, color: 'var(--mapped-text-headings)', margin: '0 0 0.6em' }}>Example 1: Fake bank text</h3>
                      <div style={{ background: 'var(--bg)', border: '1px solid var(--mapped-border-default)', borderRadius: '0.6em', padding: '1em', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace', fontSize: '0.95em', lineHeight: 1.6 }}>
                        <div style={{ color: 'var(--mapped-text-body)' }}>SMS: <strong style={{ color: '#fca5a5' }}>ALERT:</strong> Your bank account is locked.</div>
                        <div style={{ color: 'var(--mapped-text-body)', marginTop: '0.4em' }}>Tap here to verify: <span style={{ color: '#93c5fd' }}>http://bank-secure.xyz/login</span></div>
                        <div style={{ color: '#fca5a5', marginTop: '0.6em', fontWeight: 700 }}>Red flags:</div>
                        <ul style={{ color: 'var(--mapped-text-body)', paddingLeft: '1.2em', marginTop: '0.3em' }}>
                          <li>Creates fear with words like "locked" or "urgent"</li>
                          <li>Uses a strange web address, not your bank's site</li>
                          <li>Asks for login details by text</li>
                        </ul>
                      </div>
                    </div>

                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '1em', fontWeight: 700, color: 'var(--mapped-text-headings)', margin: '0 0 0.6em' }}>Example 2: Fake delivery notification</h3>
                      <div style={{ background: 'var(--bg)', border: '1px solid var(--mapped-border-default)', borderRadius: '0.6em', padding: '1em', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace', fontSize: '0.95em', lineHeight: 1.6 }}>
                        <div style={{ color: 'var(--mapped-text-body)' }}>Email: <strong style={{ color: '#fca5a5' }}>Action required:</strong> Your parcel cannot be delivered.</div>
                        <div style={{ color: 'var(--mapped-text-body)', marginTop: '0.4em' }}>Open the label here: <span style={{ color: '#93c5fd' }}>https://delivery-tracking.info/parcel</span></div>
                        <div style={{ color: '#fca5a5', marginTop: '0.6em', fontWeight: 700 }}>Red flags:</div>
                        <ul style={{ color: 'var(--mapped-text-body)', paddingLeft: '1.2em', marginTop: '0.3em' }}>
                          <li>No tracking number from the real courier</li>
                          <li>Link domain does not match the courier name</li>
                          <li>Asks you to download or open an unexpected file</li>
                        </ul>
                      </div>
                    </div>

                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '1em', fontWeight: 700, color: 'var(--mapped-text-headings)', margin: '0 0 0.6em' }}>Example 3: Fake account alert</h3>
                      <div style={{ background: 'var(--bg)', border: '1px solid var(--mapped-border-default)', borderRadius: '0.6em', padding: '1em', fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace', fontSize: '0.95em', lineHeight: 1.6 }}>
                        <div style={{ color: 'var(--mapped-text-body)' }}>Email: <strong style={{ color: '#fca5a5' }}>Security notice:</strong> Someone logged into your account.</div>
                        <div style={{ color: 'var(--mapped-text-body)', marginTop: '0.4em' }}>Secure it now: <span style={{ color: '#93c5fd' }}>https://account-security-alert.xyz/reset</span></div>
                        <div style={{ color: '#fca5a5', marginTop: '0.6em', fontWeight: 700 }}>Red flags:</div>
                        <ul style={{ color: 'var(--mapped-text-body)', paddingLeft: '1.2em', marginTop: '0.3em' }}>
                          <li>No account name, service name, or location</li>
                          <li>Asks you to reset password on a suspicious site</li>
                          <li>Feels urgent even though it gives no real proof</li>
                        </ul>
                      </div>
                    </div>

                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                      <h3 style={{ fontSize: '1em', fontWeight: 700, color: 'var(--mapped-text-headings)', margin: '0 0 0.6em' }}>Quick checks</h3>
                      <ul style={{ color: 'var(--mapped-text-body)', paddingLeft: '1.2em', display: 'grid', gap: '0.4em', fontSize: '1.05em' }}>
                        <li>Hover over a link to see where it really goes.</li>
                        <li>Open the app or website directly instead of clicking the message.</li>
                        <li>Ask: did I expect this? Is it asking for secrets?</li>
                        <li>When in doubt, do not tap. Verify with the official source.</li>
                      </ul>
                    </div>
                  </div>
                )}

                {awarenessMode === 'detailed' && (
                  <div style={{ fontSize: '0.9em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>Red flags</h3>
                      <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                        <li>Unexpected links or attachments from unknown senders</li>
                        <li>URLs that impersonate known brands with typos or extra words</li>
                        <li>Requests for credentials, OTPs, or payments via email/SMS</li>
                        <li>Shortened URLs that hide the real destination</li>
                      </ul>
                    </div>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
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
                )}
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
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>API access</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.features?.publicScanning ? 'Open' : 'Restricted'}</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.2em', padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', fontSize: '0.85em', color: 'var(--mapped-text-body)', lineHeight: 1.6 }}>
                  Scanner availability: use the form above for direct scans. This panel shows service health and access mode only.
                  <div style={{ marginTop: '0.6em' }}>
                    <strong>API access:</strong> {status.features?.publicScanning ? 'Open' : 'Restricted'} — contact <a href="mailto:molonkunuku@gmail.com" style={{ color: 'var(--mapped-text-action)', textDecoration: 'underline' }}>molonkunuku@gmail.com</a> to request access.
                  </div>
                </div>
              </div>
            </section>
          )}

          {!reportId && result && (
            <section className={`pc-animate-in ${familyMode ? 'pc-family-mode' : ''}`} style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '1.2em' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em', flexWrap: 'wrap' }}>
                    <div style={{ position: 'relative', width: '3.2em', height: '3.2em' }}>
                      <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                        <circle cx="18" cy="18" r="15.5" fill="none" stroke="var(--brand-grey-200)" strokeWidth="3" />
                        <circle cx="18" cy="18" r="15.5" fill="none" stroke={riskColor(currentRisk)} strokeWidth="3" strokeDasharray={`${(riskPct / 100) * 97.39} 97.39`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 420ms ease, stroke 420ms ease' }} />
                      </svg>
                      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75em', fontWeight: 700, color: 'var(--mapped-text-headings)', transform: 'none' }}>{currentScore ?? '—'}</div>
                    </div>
                    <div>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk score</div>
                      <div style={{ fontSize: '0.85em', fontWeight: 600, color: riskColor(currentRisk) }}>{currentRisk ? currentRisk.toUpperCase() : '—'}</div>
                      {confidence && (
                        <div style={{ fontSize: '0.65em', color: confidence.color, fontWeight: 600 }}>{confidence.label}</div>
                      )}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap' }}>
                    <button onClick={copyScanLink} className="pc-btn-ghost">Copy link</button>
                    <button onClick={copyScanJSON} className="pc-btn-ghost">Copy JSON</button>
                    <button onClick={() => downloadExport('json')} className="pc-btn-ghost">Export JSON</button>
                    <button onClick={() => downloadExport('csv')} className="pc-btn-ghost">Export CSV</button>
                    <button onClick={() => window.print()} className="pc-btn-ghost">Print</button>
                    <button onClick={() => result && downloadPDF(result)} className="pc-btn-ghost">Export report</button>
                  </div>
                </div>

                {familyMode && result && (
                  <div style={{ marginTop: '1em', padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', fontSize: '1.05em', lineHeight: 1.7, color: 'var(--mapped-text-body)' }}>
                    {familySummary(result)}
                  </div>
                )}

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
                    <p>{modeLabel(result.mode)}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Started</span>
                    <p>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain age</span>
                    <p>{(() => { const da = (result.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', marginTop: '0.25em' }}>New domains are more likely to be used in short-lived phishing campaigns.</div></>; })()}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Duration</span>
                    <p>{result.duration_ms != null ? `${result.duration_ms} ms` : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Certificate</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center' }}>{(() => { const ssl = (result.details?.ssl || {}) as any; const grade = sslGrade(result.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return (<><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>Copy</button></>); })()}</p>
                  </div>
                </div>

                {((result.details || {}) as any).score_math && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>Score breakdown</summary>
                    <div style={{ marginTop: '0.8em', padding: '1em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.4em 1em', alignItems: 'center' }}>
                        <span>Base score</span><span style={{ fontWeight: 600 }}>100</span>
                        <span>Headers</span><span style={{ color: '#b91c1c' }}>-{((result.details as any)?.score_math as any)?.header_penalty}</span>
                        <span>SSL/TLS</span><span style={{ color: '#b91c1c' }}>-{((result.details as any)?.score_math as any)?.ssl_penalty}</span>
                        <span>Threat intel</span><span style={{ color: '#b91c1c' }}>-{((result.details as any)?.score_math as any)?.threat_intel_penalty}</span>
                        <span>Domain shape</span><span style={{ color: '#b91c1c' }}>-{((result.details as any)?.score_math as any)?.domain_penalty}</span>
                        <span style={{ fontWeight: 600, borderTop: '1px solid var(--mapped-border-default)', paddingTop: '0.4em' }}>Final score</span><span style={{ fontWeight: 700, color: scoreColor(currentScore) }}>{((result.details as any)?.score_math as any)?.final_score}</span>
                      </div>
                    </div>
                  </details>
                )}

                {(((result.details || {}) as any).redirect_chain?.length || 0) > 1 && (
                  <div style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>Redirect chain</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4em', color: 'var(--mapped-text-body)', lineHeight: 1.6, wordBreak: 'break-all' }}>
                      {(((result.details || {}) as any).redirect_chain as string[]).map((u: string, i: number, arr: string[]) => (
                        <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4em' }}>
                          <span style={{ fontSize: '0.8em', fontWeight: 600, color: 'var(--mapped-text-action)' }}>{i + 1}</span>
                          <span>{u}</span>
                          {i < arr.length - 1 && <span style={{ color: 'var(--mapped-text-body)', opacity: 0.7 }}>→</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em', marginBottom: '1.4em' }}>
                  <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>Risk level</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: riskColor(currentRisk) }}>{currentRisk || '—'}</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${riskPct}%`, background: riskColor(currentRisk), transition: 'width 420ms ease' }} />
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
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.6em' }}>Findings</h3>
                    <div style={{ display: 'flex', gap: '0.4em', marginBottom: '0.6em', flexWrap: 'wrap' }}>
                      {['all', 'high', 'medium', 'low'].map(f => (
                        <button key={f} onClick={() => setFindingFilter(f)} className="pc-btn-ghost" style={{ fontSize: '0.7em', textTransform: 'capitalize', background: findingFilter === f ? 'var(--mapped-surface-action)' : undefined, color: findingFilter === f ? 'var(--mapped-text-on-action)' : undefined }}>{f === 'all' ? 'All' : f}</button>
                      ))}
                    </div>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.45em', fontSize: '0.9em', lineHeight: 1.5 }}>
                      {result.reasons.filter((r: string) => { const sev = severityOf(r); return findingFilter === 'all' || sev === findingFilter; }).map((r: string, i: number) => {
                        const sev = severityOf(r);
                        const st = severityStyle(sev);
                        return (
                          <li key={i} style={{ paddingLeft: '0.3em' }}>
                            <details style={{ display: 'inline-block', width: '100%' }}>
                              <summary style={{ cursor: 'pointer', fontWeight: 600, color: 'var(--mapped-text-headings)', listStyle: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.4em', flexWrap: 'wrap' }}>
                                <span style={{ fontSize: '0.65em', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', background: st.bg, color: st.text, padding: '0.2em 0.45em', borderRadius: '0.25em' }}>{sev}</span>
                                <span>{r}</span>
                              </summary>
                              <div style={{ marginTop: '0.5em', padding: '0.8em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                                {findingSummary(r)}
                              </div>
                            </details>
                          </li>
                        );
                      })}
                    </ul>
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
                      <circle cx="18" cy="18" r="15.5" fill="none" stroke={riskColor(report.risk)} strokeWidth="3" strokeDasharray={`${riskPercent(report.risk) / 100 * 97.39} 97.39`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 420ms ease, stroke 420ms ease' }} />
                    </svg>
                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75em', fontWeight: 700, color: 'var(--mapped-text-headings)', transform: 'none' }}>{report.score ?? '—'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk score</div>
                    <div style={{ fontSize: '0.85em', fontWeight: 600, color: riskColor(report.risk) }}>{report.risk ? report.risk.toUpperCase() : '—'}</div>
                    {confidence && (
                      <div style={{ fontSize: '0.65em', color: confidence.color, fontWeight: 600 }}>{confidence.label}</div>
                    )}
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
                    <p>{modeLabel(report.mode)}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Started</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain age</span>
                    <p>{(() => { const da = (report.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', marginTop: '0.25em' }}>New domains are more likely to be used in short-lived phishing campaigns.</div></>; })()}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Duration</span>
                    <p>{report.duration_ms != null ? `${report.duration_ms} ms` : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Certificate</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center' }}>{(() => { const ssl = (report.details?.ssl || {}) as any; const grade = sslGrade(report.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return (<><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>Copy</button></>); })()}</p>
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
                  <div>
                    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', margin: 0 }}>Recent scans</h2>
                    <div style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', marginTop: '0.35em' }}>Results shown for [X hours], then cleared.</div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap', alignItems: 'center' }}>
                    <input value={historySearch} onChange={e => setHistorySearch(e.target.value)} placeholder="Search domain, url, risk" className="pc-input" style={{ padding: '0.55em 0.7em', fontSize: '0.8em', minWidth: '14em' }} />
                    <button onClick={() => loadHistory()} className="pc-btn-ghost" style={{ color: 'var(--mapped-text-action)' }}>Refresh</button>
                  </div>
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

                {history.length === 0 && <div className="pc-history-empty" aria-live="polite">No scans yet.</div>}
                {history.length > 0 && visibleHistory.length === 0 && (
                  <div className="pc-history-empty" aria-live="polite">No matching scans.</div>
                )}
                {visibleHistory.length > 0 && (
                  <div className="pc-history-wrap">
                    <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap', marginBottom: '0.8em', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap' }}>
                        {['all','high','suspicious','low'].map(f => (
                          <button key={f} type="button" onClick={() => { setHistoryFilter(f); setHistoryPage(1); }} className="pc-btn-ghost" style={{ opacity: historyFilter === f ? 1 : 0.6 }}>{f === 'all' ? 'All' : f[0].toUpperCase() + f.slice(1)}</button>
                        ))}
                      </div>
                      {historySearch && (
                        <button type="button" onClick={() => setHistorySearch('')} className="pc-btn-ghost" style={{ fontSize: '0.7em' }}>Clear search</button>
                      )}
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
                        {visibleHistory.filter(h => historyFilter === 'all' || h.risk === historyFilter).map((h, i) => {
                          const checked = compareIds.includes(h.id || '');
                          return (
                            <tr key={h.id || i} style={{ borderBottom: '1px solid var(--mapped-border-default)', background: checked ? 'var(--mapped-surface-default)' : 'transparent' }}>
                              <td style={{ padding: '0.7em 0.8em' }}>
                                <input type="checkbox" checked={checked} onChange={() => {
                                  setCompareIds(prev => prev.includes(h.id || '') ? prev.filter(x => x !== h.id) : [...prev, h.id || ''].slice(0, 2));
                                }} />
                              </td>
                              <td style={{ padding: '0.7em 0.8em', whiteSpace: 'nowrap', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>{relativeTime(h.started_at)}</td>
                              <td style={{ padding: '0.7em 0.8em', wordBreak: 'break-all' }}>{h.domain}</td>
                              <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{h.risk}</td>
                              <td style={{ padding: '0.7em 0.8em' }}>{h.score}</td>
                              <td style={{ padding: '0.7em 0.8em', textTransform: 'capitalize' }}>{modeLabel(h.mode)}</td>
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
                    const riskColorVal = riskColor(item.risk);
                    return (
                      <div key={id} style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                        <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>Domain</div>
                        <div style={{ wordBreak: 'break-all', marginBottom: '1em' }}>{item.domain}</div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6em', fontSize: '0.85em' }}>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Risk</div>
                            <div style={{ color: riskColorVal, fontWeight: 600 }}>{item.risk}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Score</div>
                            <div style={{ fontWeight: 600 }}>{item.score}/100</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>Mode</div>
                            <div style={{ textTransform: 'capitalize' }}>{modeLabel(item.mode)}</div>
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
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }} className="pc-section pc-mobile-stack">
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
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '0 1.5em 1.5em', display: 'flex', gap: '1em', flexWrap: 'wrap', fontSize: '0.7em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>
            <a href="/privacy" style={{ color: 'var(--mapped-text-action)', textDecoration: 'none' }}>Privacy</a>
            <a href="/terms" style={{ color: 'var(--mapped-text-action)', textDecoration: 'none' }}>Terms</a>
            <button type="button" onClick={() => document.getElementById('changelog')?.scrollIntoView({ behavior: 'smooth' })} style={{ background: 'none', border: 'none', color: 'var(--mapped-text-action)', cursor: 'pointer', padding: 0, font: 'inherit' }}>Changelog</button>
            <span>© {new Date().getFullYear()} PhishChecker</span>
          </div>
          <div id="changelog" style={{ maxWidth: '56em', margin: '0 auto', padding: '0 1.5em 1.5em', fontSize: '0.8em', color: 'var(--mapped-text-body)', lineHeight: 1.6 }}>
            <details>
              <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.75em' }}>Recent changes</summary>
              <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', marginTop: '0.6em', display: 'grid', gap: '0.3em' }}>
                <li>Score/risk alignment and live blocklist lookup</li>
                <li>Findings filter chips and expand/collapse all</li>
                <li>URL validation, mobile overlap fixes, and contrast improvements</li>
                <li>Redirect chain visualization and score breakdown panels</li>
              </ul>
            </details>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
