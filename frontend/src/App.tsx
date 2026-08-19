import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail, submitBulk, submitScreenshotScan, submitQRScan, submitFlag, fetchFlags, createScheduledCheck, fetchScheduledChecks } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';
import { LANG, type Lang } from './lib/i18n';
import { UI } from './lib/ui-i18n';

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

function scoreColor(score?: number | null): string {
  if (score == null) return 'var(--mapped-text-body)';
  if (score < 50) return 'var(--pc-risk-high)';
  if (score < 80) return 'var(--pc-risk-suspicious)';
  return 'var(--pc-risk-low)';
}

function riskColor(risk?: string): string {
  if (risk === 'high') return 'var(--pc-risk-high)';
  if (risk === 'suspicious') return 'var(--pc-risk-suspicious)';
  if (risk === 'clean') return 'var(--pc-risk-low)';
  return 'var(--mapped-text-body)';
}

function confidenceMeta(score?: number | null): { label: string; color: string } | null {
  if (score == null) return null;
  if (score < 50) return { label: 'High risk', color: 'var(--pc-risk-high)' };
  if (score < 80) return { label: 'Elevated risk', color: 'var(--pc-risk-suspicious)' };
  return { label: 'Low risk', color: 'var(--pc-risk-low)' };
}

function sslGrade(details?: Record<string, unknown>): { grade: string; color: string } | null {
  const ssl = (details?.ssl || {}) as any;
  if (!ssl || !ssl.valid) return { grade: 'F', color: 'var(--pc-risk-high)' };
  const age = ssl.age_days as number | undefined;
  if (age == null) return { grade: 'A', color: 'var(--pc-risk-low)' };
  if (age < 30) return { grade: 'A+', color: 'var(--pc-risk-low)' };
  if (age < 180) return { grade: 'A', color: 'var(--pc-risk-low)' };
  if (age < 365) return { grade: 'B', color: 'var(--pc-risk-suspicious)' };
  return { grade: 'C', color: 'var(--pc-risk-high)' };
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
  if (s === 'high') return { bg: 'var(--pc-risk-high)', text: 'var(--pc-risk-on)' };
  if (s === 'medium') return { bg: 'var(--pc-risk-suspicious)', text: 'var(--pc-risk-on)' };
  return { bg: 'var(--pc-risk-low)', text: 'var(--pc-risk-on)' };
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(loadInitialTheme);
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState<'quick' | 'standard' | 'it'>('standard');
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
  const [lang, setLang] = useState<Lang>(() => {
    try {
      const stored = localStorage.getItem('phishchecker-lang');
      if (stored && stored in LANG) return stored as Lang;
    } catch { }
    return 'en';
  });

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
    try { localStorage.setItem('phishchecker-lang', lang); } catch { }
  }, [lang]);

  useEffect(() => {
    const onScroll = () => setNavShadow(window.scrollY > 10);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const changeLang = (next: Lang) => () => setLang(next);
  const t = (key: string) => UI[lang][key];

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

  async function doScan(): Promise<void> {
    setError(null);
    setResult(null);
    setReportId(null);
    setReport(null);
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

  async function handleScan(e: React.FormEvent) {
    e.preventDefault();
    await doScan();
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
        <nav className={`pc-nav ${navShadow ? 'pc-nav-scrolled' : ''}`} style={{ overflow: 'visible' }}>
          <a href="#main" className="pc-skip-link">{t("skipToContent")}</a>
          <a href="/" className="pc-nav-brand" aria-label={t("ariaHome")}>
            <svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
              <path d="M32 4L8 14v14c0 16 10.4 28.8 24 34 13.6-5.2 24-18 24-34V14L32 4z" fill="url(#shieldGrad)" opacity="0.15"/>
              <path d="M32 8L12 16.5V30c0 14.3 9.2 26 20 30.5C42.8 56 52 44.3 52 30V16.5L32 8z" fill="url(#shieldGrad)" opacity="0.25"/>
              <path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="url(#shieldGrad)"/>
              <path d="M24 34l6 6 10-12" stroke="#0D1B2A" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
              <defs>
                <linearGradient id="shieldGrad" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
                  <stop offset="0%" stopColor="#D4AF37"/>
                  <stop offset="100%" stopColor="#bfa030"/>
                </linearGradient>
              </defs>
            </svg>
            {t("brand")}
          </a>
          <button onClick={() => { const items = document.getElementById('pc-nav-items'); if (items) items.classList.toggle('pc-nav-open'); }} className="pc-nav-hamburger" aria-label={t("toggleNav")} style={{ display: 'none', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 1em', fontSize: '1.2em', lineHeight: 1 }}>☰</button>
          <div id="pc-nav-items" className="pc-nav-links">
            <button onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }} className={`pc-nav-link ${showHistory ? 'pc-nav-item-active' : ''}`}>{LANG[lang].nav.history}</button>
            <button onClick={() => { setShowAwareness(v => !v); }} className={`pc-nav-link ${showAwareness ? 'pc-nav-item-active' : ''}`}>{showAwareness ? LANG[lang].scan : LANG[lang].nav.awareness}</button>
            <button onClick={() => { setShowApi(v => !v); }} className={`pc-nav-link ${showApi ? 'pc-nav-item-active' : ''}`}>{showApi ? LANG[lang].scan : LANG[lang].nav.api}</button>
            <button onClick={() => { setShowStatus(v => !v); if (!showStatus) getStatus().then(setStatus).catch(() => setStatus(null)); }} className={`pc-nav-link ${showStatus ? 'pc-nav-item-active' : ''}`}>{showStatus ? LANG[lang].scan : LANG[lang].nav.status}</button>
            <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className={`pc-nav-link ${theme === 'dark' ? 'pc-nav-item-active' : ''}`} aria-label={t("toggleTheme")}>{theme === 'dark' ? '☀ Light' : '☾ Dark'}</button>
            <span style={{ display: 'inline-flex', gap: '0.3em', alignItems: 'center', marginLeft: '0.4em' }}>
              {(Object.keys(LANG) as Lang[]).map(k => (
                <button key={k} onClick={changeLang(k)} aria-label={k} className={`pc-nav-link ${lang === k ? 'pc-nav-item-active' : ''}`} style={{ padding: '0.3em 0.5em', fontSize: '0.75em', borderRadius: '999px' }}>{k.toUpperCase()}</button>
              ))}
            </span>
          </div>
          <button onClick={() => { document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth' }); }} className="pc-nav-cta" style={{ marginLeft: 'auto', flexShrink: 0 }}>{t("scanNow")}</button>
        </nav>

        <main id="main" style={{ paddingTop: '4.5em' }}>
          <section className="pc-panel" style={{ borderTop: 'none', borderRadius: 0, borderLeft: 'none', borderRight: 'none', background: 'linear-gradient(180deg, var(--bg-surface) 0%, var(--bg-midnight) 100%)' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '3.5em 1.5em' }} className="pc-section">
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em', padding: '0.35em 0.8em', borderRadius: '9999px', background: 'var(--gold-muted)', border: '1px solid var(--border-gold)', color: 'var(--gold)', fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '1.2em' }}>
                <svg width="14" height="14" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="currentColor"/><path d="M24 34l6 6 10-12" stroke="#0D1B2A" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>
                Privacy-first scanning
              </div>
              <h1 style={{ fontFamily: 'var(--font-display)', fontSize: 'clamp(2.2rem, 5vw, 3.5rem)', lineHeight: 1.05, letterSpacing: '-0.03em', color: 'var(--text-primary)', marginBottom: '0.8em', maxWidth: '18ch' }}>
                Check links before you trust them.
              </h1>
              <p style={{ fontSize: '1.15em', lineHeight: 1.5, maxWidth: '32ch', color: 'var(--text-secondary)', marginBottom: '2em' }}>
                Fast phishing-risk analysis with plain-language results. No accounts. No tracking. Just scan.
              </p>
              <form onSubmit={handleScan} id="scan" className="pc-scan-form" style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.6em', maxWidth: '38em' }}>
                <label htmlFor="url-input" style={{ position: 'absolute', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', width: '1px', height: '1px' }}>{t("urlLabel")}</label>
                <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap' }}>
                  <div style={{ position: 'relative', flex: '1 1 auto', minWidth: '14em' }}>
                    <input ref={inputRef} id="url-input" value={url} onChange={e => setUrl(e.target.value)} placeholder={t("urlPlaceholder")} className="pc-input pc-placeholder" disabled={loading} aria-describedby="url-hint" style={{ paddingRight: url ? '2.2em' : undefined }} />
                    {url && (
                      <button type="button" onClick={() => setUrl('')} disabled={loading} aria-label={t("clearUrl")} style={{ position: 'absolute', right: '0.6em', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.9em', padding: '0.3em', lineHeight: 1 }}>×</button>
                    )}
                  </div>
                  <select value={mode} onChange={e => setMode(e.target.value as 'quick' | 'standard' | 'it')} className="pc-select" disabled={loading || familyMode} aria-label={t("fieldMode")} style={{ minWidth: '10em' }}>
                    <option value="quick">{t("quick")}</option>
                    <option value="standard">{t("standard")}</option>
                    <option value="it">{t("itMode")}</option>
                  </select>
                  <button type="submit" disabled={loading} className="pc-btn-primary" style={{ whiteSpace: 'nowrap', minHeight: '44px' }}>
                    {loading ? (<span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />{LANG[lang].scanning}</span>) : LANG[lang].scan}
                  </button>
                </div>
                {mode && (
                  <span id="url-hint" style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', padding: '0.2em 0' }}>
                    {LANG[lang].urlHint[mode]}
                  </span>
                )}
              </form>
              <div style={{ marginTop: '0.8em', display: 'flex', alignItems: 'center', gap: '0.6em', flexWrap: 'wrap' }}>
                <button type="button" onClick={() => setFamilyMode(v => !v)} className="pc-btn-ghost" style={{ fontSize: '0.85em', color: familyMode ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-action)', background: familyMode ? 'var(--mapped-surface-action)' : 'transparent', border: '1px solid', borderColor: familyMode ? 'var(--mapped-surface-action)' : 'var(--mapped-border-default)' }}>
                  {familyMode ? LANG[lang].familyMode.on : LANG[lang].familyMode.off}
                </button>
                {familyMode && (
                  <span style={{ fontSize: '0.8em', color: 'var(--mapped-text-body)' }}>{LANG[lang].familyMode.helper}</span>
                )}
              </div>
              {loading && (
                <div aria-busy="true" style={{ marginTop: '1.2em', display: 'grid', gap: '0.8em', maxWidth: '38em' }}>
                  <div style={{ display: 'flex', gap: '0.6em', alignItems: 'center' }}>
                    <div className="pc-skeleton" style={{ width: '2.5em', height: '2.5em', borderRadius: '50%', flexShrink: 0 }} />
                    <div style={{ flex: 1, display: 'grid', gap: '0.5em' }}>
                      <div className="pc-skeleton pc-skeleton-title" style={{ width: '70%' }} />
                      <div className="pc-skeleton pc-skeleton-text-short" style={{ width: '40%' }} />
                    </div>
                  </div>
                  <div className="pc-skeleton" style={{ height: '4.5em' }} />
                  <div className="pc-skeleton" style={{ height: '4.5em' }} />
                </div>
              )}
              <div style={{ marginTop: '1em', display: 'grid', gap: '0.8em', maxWidth: '38em' }}>
                <div style={{ fontSize: '0.75em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{t("moreTools")}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(12em, 1fr))', gap: '0.6em' }}>
                  <label className="pc-card" style={{ padding: '1em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', borderRadius: 'var(--r-md)', cursor: 'pointer', display: 'grid', gap: '0.4em' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("screenshotTitle")}</span>
                    <span style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{LANG[lang].screenshot.body}</span>
                    <input type="file" accept="image/*" style={{ fontSize: '0.7em' }} onChange={async (e) => { const file = e.target.files?.[0]; if (!file) return; const reader = new FileReader(); reader.onload = async () => { setError(null); setResult(null); setLoading(true); try { const data = await submitScreenshotScan(reader.result as string); setResult(data as any); } catch (err: any) { setError(err?.message || 'scan failed'); } finally { setLoading(false); } }; reader.readAsDataURL(file); }} />
                  </label>
                  <label className="pc-card" style={{ padding: '1em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', borderRadius: 'var(--r-md)', cursor: 'pointer', display: 'grid', gap: '0.4em' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("qrTitle")}</span>
                    <span style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{LANG[lang].qr.body}</span>
                    <input type="file" accept="image/*" style={{ fontSize: '0.7em' }} onChange={async (e) => { const file = e.target.files?.[0]; if (!file) return; const reader = new FileReader(); reader.onload = async () => { setError(null); setResult(null); setLoading(true); try { const data = await submitQRScan(reader.result as string); setResult(data as any); } catch (err: any) { setError(err?.message || 'scan failed'); } finally { setLoading(false); } }; reader.readAsDataURL(file); }} />
                  </label>
                </div>
              </div>

              <div style={{ marginTop: '1.2em', display: 'grid', gap: '0.8em', maxWidth: '38em' }}>
                <div style={{ fontSize: '0.75em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>{t("communityTitle")}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(12em, 1fr))', gap: '0.6em' }}>
                  <div className="pc-card" style={{ padding: '1em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', borderRadius: 'var(--r-md)', display: 'grid', gap: '0.4em' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("flagTitle")}</span>
                    <span style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{t("flagBody")}</span>
                    <button type="button" className="pc-btn-secondary" style={{ fontSize: '0.8em', padding: '0.5em 0.7em' }} onClick={async () => { const url = prompt('Suspicious URL'); if (!url) return; const notes = prompt('Notes', '') || ''; setLoading(true); try { const data = await submitFlag({ url: url.trim(), domain: new URL(url.trim()).hostname, notes }); alert('Flagged: ' + JSON.stringify(data)); } catch (err: any) { setError(err?.message || 'failed'); } finally { setLoading(false); } }}>{t("reportUrl")}</button>
                  </div>
                  <div className="pc-card" style={{ padding: '1em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', borderRadius: 'var(--r-md)', display: 'grid', gap: '0.4em' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("scheduledTitle")}</span>
                    <span style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{t("scheduledBody")}</span>
                    <button type="button" className="pc-btn-secondary" style={{ fontSize: '0.8em', padding: '0.5em 0.7em' }} onClick={async () => { const url = prompt('URL to monitor'); if (!url) return; const mins = prompt('Repeat every (minutes):', '1440'); if (!mins) return; const hours = Math.max(1, Math.round(Number(mins) / 60)); setLoading(true); try { const data = await createScheduledCheck({ url: url.trim(), cadence_hours: hours }); alert('Scheduled: ' + JSON.stringify(data)); } catch (err: any) { setError(err?.message || 'failed'); } finally { setLoading(false); } }}>{t("createMonitor")}</button>
                  </div>
                </div>
              </div>
              {!loading && !result && !error && (
                <div aria-live="polite" style={{ marginTop: '1.2em', padding: '1.6em', border: '1px dashed var(--border-subtle)', background: 'var(--bg-surface-raised)', color: 'var(--text-muted)', fontSize: '0.95em', textAlign: 'center', borderRadius: 'var(--r-lg)' }}>
                  <div style={{ fontSize: '2.4em', marginBottom: '0.6em', opacity: 0.9 }} aria-hidden="true">🛡️</div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '0.3em' }}>{t("noScansTitle")}</div>
                  <div>{t("noScansBody")}</div>
                  <div style={{ marginTop: '0.4em', fontSize: '0.8em', opacity: 0.8 }}>{t("noScansShortcut")}</div>
                </div>
              )}

              <div style={{ marginTop: '2em', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(8em, 1fr))', gap: '0.6em', fontSize: '0.8em', color: 'var(--text-muted)', textAlign: 'center' }} aria-label={t("serviceStats")}>
                <div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--gold)', fontFamily: 'var(--font-display)' }}>100%</div>
                  <div style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("uptime")}</div>
                </div>
                <div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--gold)', fontFamily: 'var(--font-display)' }}>0</div>
                  <div style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("scansBlocked")}</div>
                </div>
                <div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--gold)', fontFamily: 'var(--font-display)' }}>{t("free")}</div>
                  <div style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("forever")}</div>
                </div>
              </div>
              <div style={{ marginTop: '0.8em', display: 'inline-flex', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <span>{t("noPersonalData")}</span>
              </div>
              {error && (
                <div role="alert" aria-live="assertive" style={{ position: 'fixed', top: '1em', left: '50%', transform: 'translateX(-50%)', zIndex: 200, background: 'var(--pc-risk-high)', color: 'var(--pc-risk-on)', padding: '0.8em 1.2em', borderRadius: '0.4em', fontSize: '0.85em', boxShadow: '0 6px 20px rgba(0,0,0,0.25)', display: 'flex', alignItems: 'center', gap: '0.6em', maxWidth: '92vw' }}>
                  <span style={{ fontWeight: 600 }}>{t("errorTitle")}</span>
                  <span>{error}</span>
                  <button type="button" onClick={doScan} className="pc-btn-ghost" style={{ fontSize: '0.8em', borderColor: 'rgba(255,255,255,0.35)', color: 'inherit' }}>{t("retry")}</button>
                </div>
              )}
            </div>
          </section>

          <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.6em 1.5em' }} className="pc-section">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1em', marginBottom: '0.8em', flexWrap: 'wrap' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--mapped-text-headings)' }}>{t("batchTitle")}</h2>
                <button type="button" onClick={() => { setBatchMode(v => !v); setBatchResults(null); setBatchError(null); }} className="pc-btn-ghost" style={{ fontSize: '0.7em' }}>{batchMode ? 'Close batch' : 'Open batch'}</button>
              </div>
              {batchMode && (
                <form onSubmit={handleBatch} style={{ display: 'grid', gap: '0.6em', maxWidth: '42em' }}>
                  <label htmlFor="batch-input" style={{ position: 'absolute', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', width: '1px', height: '1px' }}>{t("batchLabel")}</label>
                  <textarea id="batch-input" value={batchInput} onChange={e => setBatchInput(e.target.value)} placeholder={t("batchPlaceholder")} className="pc-input pc-placeholder" disabled={batchRunning} rows={6} style={{ resize: 'vertical' }} />
                  <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap' }}>
                    <button type="submit" disabled={batchRunning} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                      {batchRunning ? (<span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />{t("scanning")}</span>) : 'Scan batch'}
                    </button>
                    <span style={{ fontSize: '0.7em', color: 'var(--mapped-text-body)', alignSelf: 'center' }}>{t("maxUrls")}</span>
                  </div>
                  {batchError && (
                    <p style={{ color: 'var(--pc-risk-high)', marginTop: '0.4em', fontSize: '0.85em', display: 'flex', alignItems: 'center', gap: '0.5em', flexWrap: 'wrap' }}>
                      {batchError}
                      <button type="button" onClick={() => setBatchError(null)} className="pc-btn-ghost" style={{ fontSize: '0.8em' }}>{t("retry")}</button>
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
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', margin: 0 }}>{t("awarenessTitle")}</h2>
                  <div style={{ display: 'inline-flex', gap: '0.4em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '0.3em', borderRadius: '999px' }}>
                    <button type="button" onClick={() => setAwarenessMode('simple')} className="pc-btn-ghost" style={{ fontSize: '0.8em', borderRadius: '999px', background: awarenessMode === 'simple' ? 'var(--mapped-surface-action)' : 'transparent', color: awarenessMode === 'simple' ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-body)' }}>{t("simpleMode")}</button>
                    <button type="button" onClick={() => setAwarenessMode('detailed')} className="pc-btn-ghost" style={{ fontSize: '0.8em', borderRadius: '999px', background: awarenessMode === 'detailed' ? 'var(--mapped-surface-action)' : 'transparent', color: awarenessMode === 'detailed' ? 'var(--mapped-text-on-action)' : 'var(--mapped-text-body)' }}>{t("detailedMode")}</button>
                  </div>
                </div>

                {awarenessMode === 'simple' && (
                  <div style={{ fontSize: '1.05em', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                    <div style={{ padding: '1.2em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', marginBottom: '1.2em', borderRadius: 'var(--r-lg)' }}>
                      <p style={{ margin: 0, fontSize: '1.05em', color: 'var(--text-primary)' }}>{t("awarenessLead")}</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em', color: 'var(--text-primary)' }}>They want your password, OTP, or payment.</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em', color: 'var(--text-primary)' }}>{t("awarenessLine2")}</p>
                    </div>

                    <div style={{ padding: '1.2em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', marginBottom: '1.2em', borderRadius: 'var(--r-lg)' }}>
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true">📱</span> Example 1: Fake bank text
                      </h3>
                      <div style={{ background: 'var(--bg-midnight)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '22em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-muted)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("smsLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: '#fca5a5' }}>{t("alertLabel")}</strong> Your bank account is locked.<br/>
                          <span style={{ color: '#93c5fd' }}>{t("tapHere")}</span><br/>
                          <span style={{ color: 'var(--danger)', textDecoration: 'underline' }}>http://bank-secure.xyz/login</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: '0.35em', fontSize: '0.85em', color: '#fca5a5' }}>
                          ⚠ Red flags: fear words, strange address, asks for login by text
                        </div>
                      </div>
                    </div>

                    <div style={{ padding: '1.2em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', marginBottom: '1.2em', borderRadius: 'var(--r-lg)' }}>
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true">📧</span> Example 2: Fake delivery notification
                      </h3>
                      <div style={{ background: 'var(--bg-midnight)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '24em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-muted)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("emailLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: '#fca5a5' }}>{t("actionRequired")}</strong> Your parcel cannot be delivered.<br/>
                          Open the label: <span style={{ color: '#93c5fd' }}>https://delivery-tracking.info/parcel</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: '0.35em', fontSize: '0.85em', color: '#fca5a5' }}>
                          ⚠ Red flags: no tracking number, wrong domain, asks to download file
                        </div>
                      </div>
                    </div>

                    <div style={{ padding: '1.2em', border: '1px solid var(--border-subtle)', background: 'var(--bg-surface-raised)', marginBottom: '1.2em', borderRadius: 'var(--r-lg)' }}>
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true">🔐</span> Example 3: Fake account alert
                      </h3>
                      <div style={{ background: 'var(--bg-midnight)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '24em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-muted)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("emailLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: '#fca5a5' }}>{t("securityNotice")}</strong> Someone logged into your account.<br/>
                          Secure it now: <span style={{ color: '#93c5fd' }}>https://account-security-alert.xyz/reset</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', borderRadius: '0.35em', fontSize: '0.85em', color: '#fca5a5' }}>
                          ⚠ Red flags: no account details, asks reset on unknown site, fake urgency
                        </div>
                      </div>
                    </div>

                    <div style={{ padding: '1.2em', border: '1px solid var(--border-gold)', background: 'linear-gradient(135deg, var(--bg-surface) 0%, rgba(212,175,55,0.03) 100%)', borderRadius: 'var(--r-lg)' }}>
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--gold)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true">✅</span> Quick checks
                      </h3>
                      <ul style={{ color: 'var(--text-secondary)', paddingLeft: '1.2em', display: 'grid', gap: '0.5em', fontSize: '1.05em' }}>
                        <li>{t("checkHover")}</li>
                        <li>{t("checkApp")}</li>
                        <li>Ask: did I expect this? Is it asking for secrets?</li>
                        <li>When in doubt, do not tap. Verify with the official source.</li>
                      </ul>
                    </div>
                  </div>
                )}

                {awarenessMode === 'detailed' && (
                  <div style={{ fontSize: '0.9em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>{t("redFlags")}</h3>
                      <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                        <li>{t("detailUnexpected")}</li>
                        <li>{t("detailImpersonate")}</li>
                        <li>Requests for credentials, OTPs, or payments via email/SMS</li>
                        <li>{t("detailShortened")}</li>
                      </ul>
                    </div>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>{t("howToCheck")}</h3>
                      <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                        <li>{t("howHover")}</li>
                        <li>{t("howScanner")}</li>
                        <li>{t("howSsl")}</li>
                        <li>{t("howOfficial")}</li>
                      </ul>
                    </div>
                    <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>{t("understandingRisk")}</h3>
                      <p>{t("riskHigh")} {t("riskSuspicious")} {t("riskClean")}</p>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {showApi && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', marginBottom: '0.8em' }}>{t("apiTitle")}</h2>
                <div style={{ display: 'grid', gap: '1em', fontSize: '0.9em', lineHeight: 1.6 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>POST</span>
                      <code style={{ background: 'var(--brand-grey-200)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans</code>
                    </div>
                    <p>{t("apiScanPost")} <code>/api/csrf</code>.</p>
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
                    <p>{t("apiHistory")} <code>page</code> {t("and")} <code>page_size</code> {t("queryParams")}.</p>
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
                    <p>{t("apiExport")} <code>?format=json</code> {t("or")} <code>?format=csv</code>.</p>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showStatus && status && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>{t("statusTitle")}</h2>
                  <span className="pc-chip" style={{ background: 'var(--pc-ok)', color: '#fff', borderColor: 'var(--pc-ok)' }}>{t("operational")}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("statusService")}</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.service || 'PhishChecker'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("statusVersion")}</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.version || '—'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("apiAccess")}</div>
                    <div style={{ color: 'var(--mapped-text-headings)', fontWeight: 600 }}>{status.features?.publicScanning ? 'Open' : 'Restricted'}</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.2em', padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', fontSize: '0.85em', color: 'var(--mapped-text-body)', lineHeight: 1.6 }}>
                  Scanner availability: use the form above for direct scans. This panel shows service health and access mode only.
                  <div style={{ marginTop: '0.6em' }}>
                    <strong>{t("supportText")}</strong> use the in-app contact or <a href="/security.txt" style={{ color: 'var(--mapped-text-action)', textDecoration: 'underline' }}>{t("securityContact")}</a>.
                  </div>
                </div>
              </div>
            </section>
          )}

          {!reportId && result && (
            <section className={`pc-animate-in ${familyMode ? 'pc-family-mode' : ''}`} style={{ borderTop: '1px solid var(--border-subtle)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '1.2em', alignItems: 'center', marginBottom: '1.4em' }}>
                  <div className="pc-gauge" aria-hidden="true">
                    <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
                      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--sapphire-muted)" strokeWidth="8" />
                      <circle cx="50" cy="50" r="42" fill="none" stroke="var(--gold)" strokeWidth="8" strokeLinecap="round" strokeDasharray={`${(Math.max(0, Math.min(100, currentScore ?? 0)) / 100) * 264} 264`} style={{ transition: 'stroke-dasharray 1s cubic-bezier(0.4, 0, 0.2, 1)' }} />
                    </svg>
                    <div className="pc-gauge-text">
                      <div className="pc-gauge-score" style={{ color: currentScore != null && currentScore < 50 ? 'var(--danger)' : currentScore != null && currentScore < 80 ? 'var(--warning)' : 'var(--success)' }}>{currentScore ?? '—'}</div>
                      <div className="pc-gauge-label">of 100</div>
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.3em' }}>{t("riskScore")}</div>
                    <div style={{ fontSize: '1.1rem', fontWeight: 700, color: currentRisk === 'high' ? 'var(--danger)' : currentRisk === 'suspicious' ? 'var(--warning)' : currentRisk === 'clean' ? 'var(--success)' : 'var(--text-primary)', marginBottom: '0.3em' }}>{currentRisk ? currentRisk.toUpperCase() : '—'}</div>
                    {confidence && (
                      <div style={{ fontSize: '0.75em', color: confidence.color, fontWeight: 600 }}>{confidence.label}</div>
                    )}
                  </div>
                </div>

                {familyMode && result && (
                  <div style={{ marginBottom: '1.2em', padding: '1.1em', border: '1px solid var(--border-gold)', background: 'linear-gradient(135deg, var(--bg-surface) 0%, rgba(212,175,55,0.04) 100%)', borderRadius: 'var(--r-lg)', fontSize: '1.05em', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--gold)', marginBottom: '0.4em' }}>
                      <svg width="16" height="16" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="currentColor"/><path d="M24 34l6 6 10-12" stroke="#0D1B2A" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none"/></svg>
                      Family Mode
                    </div>
                    {familySummary(result)}
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.4em', flexWrap: 'wrap', marginBottom: '1.2em' }}>
                  <button onClick={copyScanLink} className="pc-btn-ghost">{t("copyLink")}</button>
                  <button onClick={copyScanJSON} className="pc-btn-ghost">{t("copyJson")}</button>
                  <button onClick={() => downloadExport('json')} className="pc-btn-ghost">{t("exportJson")}</button>
                  <button onClick={() => downloadExport('csv')} className="pc-btn-ghost">{t("exportCsv")}</button>
                  <button onClick={() => window.print()} className="pc-btn-ghost">{t("print")}</button>
                  <button onClick={() => result && downloadPDF(result)} className="pc-btn-ghost">{t("exportReport")}</button>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5, marginBottom: '1.2em' }} className="pc-mobile-stack">
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldUrl")}</span>
                    <p style={{ wordBreak: 'break-all', color: 'var(--text-primary)' }}>{result.url}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldDomain")}</span>
                    <p style={{ wordBreak: 'break-all', color: 'var(--text-primary)' }}>{result.domain}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldMode")}</span>
                    <p style={{ color: 'var(--text-primary)' }}>{modeLabel(result.mode)}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldStarted")}</span>
                    <p style={{ color: 'var(--text-primary)' }}>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldDomainAge")}</span>
                    <p style={{ color: 'var(--text-primary)' }}>{(() => { const da = (result.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.75em', color: 'var(--text-muted)', marginTop: '0.25em' }}>{t("newDomainWarning")}</div></>; })()}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldDuration")}</span>
                    <p style={{ color: 'var(--text-primary)' }}>{result.duration_ms != null ? `${result.duration_ms} ms` : '—'}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-subtle)', padding: '1em', borderRadius: 'var(--r-md)', gridColumn: '1 / -1' }}>
                    <span style={{ display: 'block', fontSize: '0.65em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '0.25em' }}>{t("fieldCertificate")}</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center', color: 'var(--text-primary)' }}>{(() => { const ssl = (result.details?.ssl || {}) as any; const grade = sslGrade(result.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return <><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>{t("copy")}</button></>; })()}</p>
                  </div>
                </div>

                {((result.details || {}) as any).score_math && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>{t("scoreBreakdown")}</summary>
                    <div style={{ marginTop: '0.8em', padding: '1em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--mapped-text-body)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.4em 1em', alignItems: 'center' }}>
                        <span>{t("baseScore")}</span><span style={{ fontWeight: 600 }}>100</span>
                        <span>{t("headersPenalty")}</span><span style={{ color: 'var(--pc-risk-high)' }}>-{((result.details as any)?.score_math as any)?.header_penalty}</span>
                        <span>{t("sslPenalty")}</span><span style={{ color: 'var(--pc-risk-high)' }}>-{((result.details as any)?.score_math as any)?.ssl_penalty}</span>
                        <span>{t("threatIntelPenalty")}</span><span style={{ color: 'var(--pc-risk-high)' }}>-{((result.details as any)?.score_math as any)?.threat_intel_penalty}</span>
                        <span>{t("domainShapePenalty")}</span><span style={{ color: 'var(--pc-risk-high)' }}>-{((result.details as any)?.score_math as any)?.domain_penalty}</span>
                        <span style={{ fontWeight: 600, borderTop: '1px solid var(--mapped-border-default)', paddingTop: '0.4em' }}>{t("finalScore")}</span><span style={{ fontWeight: 700, color: scoreColor(currentScore) }}>{((result.details as any)?.score_math as any)?.final_score}</span>
                      </div>
                    </div>
                  </details>
                )}

                {(((result.details || {}) as any).redirect_chain?.length || 0) > 1 && (
                  <div style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.4em' }}>{t("redirectChain")}</div>
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
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>{t("riskLevel")}</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: riskColor(currentRisk) }}>{currentRisk || '—'}</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${riskPct}%`, background: riskColor(currentRisk), transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                  <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>{t("scoreLabel")}</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: 'var(--mapped-text-headings)' }}>{currentScore ?? '—'}/100</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--brand-grey-200)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${Math.max(0, Math.min(100, currentScore ?? 0))}%`, background: 'var(--mapped-text-action)', transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                </div>

                {result.reasons && result.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.6em' }}>{t("findings")}</h3>
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
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', fontSize: '0.8em' }}>{t("rawDetails")}</summary>
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
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>{t("scanReport")}</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="pc-btn-ghost">{t("back")}</button>
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
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>{t("riskScore")}</div>
                    <div style={{ fontSize: '0.85em', fontWeight: 600, color: riskColor(report.risk) }}>{report.risk ? report.risk.toUpperCase() : '—'}</div>
                    {confidence && (
                      <div style={{ fontSize: '0.65em', color: confidence.color, fontWeight: 600 }}>{confidence.label}</div>
                    )}
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1.2em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldUrl")}</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.url}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldDomain")}</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.domain}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldMode")}</span>
                    <p>{modeLabel(report.mode)}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldStarted")}</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldDomainAge")}</span>
                    <p>{(() => { const da = (report.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', marginTop: '0.25em' }}>{t("newDomainWarning")}</div></>; })()}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldDuration")}</span>
                    <p>{report.duration_ms != null ? `${report.duration_ms} ms` : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldCertificate")}</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center' }}>{(() => { const ssl = (report.details?.ssl || {}) as any; const grade = sslGrade(report.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return (<><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>{t("copy")}</button></>); })()}</p>
                  </div>
                </div>

                {report.reasons && report.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.6em' }}>{t("findings")}</h3>
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
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em', color: 'var(--mapped-text-body)' }}>{t("loadingReport")}</div>
            </section>
          )}

          {showHistory && (
            <section style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <div>
                    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)', margin: 0 }}>{t("recentScans")}</h2>
                    <div style={{ fontSize: '0.75em', color: 'var(--mapped-text-body)', marginTop: '0.35em' }}>{t("historyNote")}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap', alignItems: 'center' }}>
                    <input value={historySearch} onChange={e => setHistorySearch(e.target.value)} placeholder={t("historySearchPlaceholder")} className="pc-input" style={{ padding: '0.55em 0.7em', fontSize: '0.8em', minWidth: '14em' }} />
                    <button onClick={() => loadHistory()} className="pc-btn-ghost" style={{ color: 'var(--mapped-text-action)' }}>{t("refresh")}</button>
                  </div>
                </div>

                {history.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(12em, 1fr))', gap: '0.8em', marginBottom: '1.2em' }}>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("total")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--mapped-text-headings)' }}>{historyStats.total}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("high")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--pc-risk-high)' }}>{historyStats.high}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("suspicious")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--pc-risk-suspicious)' }}>{historyStats.suspicious}</div>
                    </div>
                    <div style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1em' }}>
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("low")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--pc-risk-low)' }}>{historyStats.low}</div>
                    </div>
                  </div>
                )}

                {history.length === 0 && <div className="pc-empty" aria-live="polite"><div className="pc-empty-icon" aria-hidden="true">🕰️</div><div className="pc-empty-title">{t("noScansTitle")}</div><div className="pc-empty-body">{t("recentEmpty")}</div></div>}
                {history.length > 0 && visibleHistory.length === 0 && <div className="pc-empty" aria-live="polite"><div className="pc-empty-icon" aria-hidden="true">🔎</div><div className="pc-empty-title">{t("noMatchingScans")}</div><div className="pc-empty-body">{t("noMatchingHint")}</div></div>}

                {visibleHistory.length > 0 && (
                  <div style={{ display: 'grid', gap: '0.6em' }}>
                    {visibleHistory.slice(0, historyPageSize).map(h => {
                      const badge = h.risk === 'high' ? 'pc-risk-high' : h.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low';
                      const itemScoreColor = scoreColor(h.score);
                      return (
                        <div key={h.id} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.6em', alignItems: 'center', padding: '0.9em 1em', background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)' }}>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5em', marginBottom: '0.3em', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.8em', fontWeight: 700, color: 'var(--mapped-text-headings)', wordBreak: 'break-all' }}>{h.domain || h.url}</span>
                              <span className={badge} style={{ fontSize: '0.65em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', padding: '0.25em 0.5em', borderRadius: '0.35em' }}>{h.risk}</span>
                            </div>
                            <div style={{ fontSize: '0.8em', color: 'var(--mapped-text-body)', display: 'flex', gap: '0.8em', flexWrap: 'wrap' }}>
                              <span style={{ color: itemScoreColor, fontWeight: 600 }}>{h.score}/100</span>
                              <span>{modeLabel(h.mode)}</span>
                              <span>{h.duration_ms != null ? `${h.duration_ms} ms` : ''}</span>
                              <span>{relativeTime(h.started_at)}</span>
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: '0.4em', justifyContent: 'flex-end' }}>
                            <button className="pc-btn-ghost" style={{ fontSize: '0.7em', padding: '0.45em 0.7em' }} onClick={() => { setReportId(h.id); setReport(null); window.location.hash = `#/scan/${h.id}`; }}>{t("view")}</button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.8em', fontSize: '0.8em', color: 'var(--mapped-text-body)', flexWrap: 'wrap', gap: '0.5em' }}>
                  <span>{history.length ? `Page ${historyPage}` : ''}</span>
                  <div style={{ display: 'flex', gap: '0.4em' }}>
                    <button disabled={historyPage <= 1} onClick={() => setHistoryPage(p => p - 1)} className="pc-btn-ghost">{t("prev")}</button>
                    <button disabled={history.length < historyPageSize} onClick={() => setHistoryPage(p => p + 1)} className="pc-btn-ghost">{t("next")}</button>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showCompare && (
            <section className="pc-animate-in" style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--mapped-text-headings)' }}>{t("comparison")}</h2>
                  <button onClick={() => setShowCompare(false)} className="pc-btn-ghost">{t("close")}</button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em' }}>
                  {compareIds.map(id => {
                    const item = history.find(h => h.id === id);
                    if (!item) return null;
                    const riskColorVal = riskColor(item.risk);
                    return (
                      <div key={id} style={{ background: 'var(--mapped-surface-default)', border: '1px solid var(--mapped-border-default)', padding: '1.2em' }}>
                        <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.3em' }}>{t("fieldDomain")}</div>
                        <div style={{ wordBreak: 'break-all', marginBottom: '1em' }}>{item.domain}</div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6em', fontSize: '0.85em' }}>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>{t("riskLevel")}</div>
                            <div style={{ color: riskColorVal, fontWeight: 600 }}>{item.risk}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>{t("scoreLabel")}</div>
                            <div style={{ fontWeight: 600 }}>{item.score}/100</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>{t("fieldMode")}</div>
                            <div style={{ textTransform: 'capitalize' }}>{modeLabel(item.mode)}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--mapped-text-body)', marginBottom: '0.2em' }}>{t("fieldDuration")}</div>
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
              <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.1rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--mapped-text-headings)', marginBottom: '0.8em' }}>{t("howItWorks")}</h2>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }} className="pc-section pc-mobile-stack">
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>01 — Paste</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>{t("stepPasteBody")}</p>
                </div>
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>02 — Analyze</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>{t("stepAnalyzeBody")}</p>
                </div>
                <div style={{ padding: '1em', border: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)' }}>
                  <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--mapped-text-action)', marginBottom: '0.4em' }}>03 — Decide</div>
                  <p style={{ color: 'var(--mapped-text-body)' }}>{t("stepDecideBody")}</p>
                </div>
              </div>
            </div>
          </section>
        </main>

        <footer style={{ borderTop: '1px solid var(--mapped-border-default)', background: 'var(--mapped-surface-default)', marginTop: '2em' }}>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.5em', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5em', fontSize: '0.75em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--mapped-text-body)' }}>
            <span>PhishChecker</span>
            <span>{t("privacyBadge")}</span>
            <span>{status?.version ? `v${status.version}` : ''}</span>
          </div>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '0 1.5em 1.5em', display: 'flex', gap: '1em', flexWrap: 'wrap', fontSize: '0.7em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
            <a href="/privacy" style={{ color: 'var(--gold)', textDecoration: 'none' }}>{t("privacy")}</a>
            <a href="/terms" style={{ color: 'var(--gold)', textDecoration: 'none' }}>{t("terms")}</a>
            <a href="/changelog" style={{ color: 'var(--gold)', textDecoration: 'none' }}>{t("changelog")}</a>
            <span>© {new Date().getFullYear()} PhishChecker</span>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
