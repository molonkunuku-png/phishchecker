import { useState, useEffect, useRef } from 'react';
import { ThemeContext, Theme } from './lib/ThemeContext';
import { submitScan, fetchHistory, downloadExport, getStatus, fetchScanDetail, submitBulk, submitScreenshotScan, submitQRScan, submitFlag, fetchFlags, createScheduledCheck, fetchScheduledChecks } from './lib/api';
import type { ScanResult, HistoryItem, StatusResponse } from './lib/types';
import { LANG, type Lang } from './lib/i18n';
import { UI } from './lib/ui-i18n';
import { Icon } from './lib/icons';

function ShieldLogo({ size = 26 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="shieldGrad" x1="0" y1="0" x2="64" y2="64" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#D4AF37" />
          <stop offset="100%" stopColor="#bfa030" />
        </linearGradient>
      </defs>
      <path d="M32 4L8 14v14c0 16 10.4 28.8 24 34 13.6-5.2 24-18 24-34V14L32 4z" fill="url(#shieldGrad)" opacity="0.15" />
      <path d="M32 8L12 16.5V30c0 14.3 9.2 26 20 30.5C42.8 56 52 44.3 52 30V16.5L32 8z" fill="url(#shieldGrad)" opacity="0.25" />
      <path d="M32 12L16 19v11c0 12.5 8 22.8 16 26.5 8-3.7 16-14 16-26.5V19L32 12z" fill="url(#shieldGrad)" />
      <path d="M24 34l6 6 10-12" stroke="#0D1B2A" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" fill="none" />
    </svg>
  );
}

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
  if (score == null) return 'var(--text-secondary)';
  if (score < 50) return 'var(--risk-safe)';
  if (score < 80) return 'var(--risk-caution)';
  return 'var(--risk-danger)';
}

function riskColor(risk?: string): string {
  if (risk === 'high') return 'var(--risk-danger)';
  if (risk === 'suspicious') return 'var(--risk-caution)';
  if (risk === 'clean') return 'var(--risk-safe)';
  return 'var(--text-secondary)';
}

function confidenceMeta(score?: number | null): { label: string; color: string } | null {
  if (score == null) return null;
  if (score < 50) return { label: 'Low risk', color: 'var(--risk-safe)' };
  if (score < 80) return { label: 'Elevated risk', color: 'var(--risk-caution)' };
  return { label: 'High risk', color: 'var(--risk-danger)' };
}

function riskVerdict(risk?: string): { label: string; className: string } {
  const r = (risk || '').toLowerCase();
  if (r === 'high') return { label: 'Danger', className: 'pc-verdict-danger' };
  if (r === 'suspicious') return { label: 'Caution', className: 'pc-verdict-caution' };
  if (r === 'clean') return { label: 'Safe', className: 'pc-verdict-safe' };
  return { label: 'Unknown', className: 'pc-verdict' };
}

function riskAction(result: ScanResult | null): string {
  if (!result) return '';
  const risk = (result.risk || '').toLowerCase();
  if (risk === 'high') return "Don't enter your password or card details here.";
  if (risk === 'suspicious') return 'Proceed with caution. Avoid signing in or sharing sensitive details.';
  return 'No strong phishing indicators were detected in the checked URL.';
}

function sslGrade(details?: Record<string, unknown>): { grade: string; color: string } | null {
  const ssl = (details?.ssl || {}) as any;
  if (!ssl || !ssl.valid) return { grade: 'F', color: 'var(--risk-danger)' };
  const age = ssl.age_days as number | undefined;
  if (age == null) return { grade: 'A', color: 'var(--risk-safe)' };
  if (age < 30) return { grade: 'A+', color: 'var(--risk-safe)' };
  if (age < 180) return { grade: 'A', color: 'var(--risk-safe)' };
  if (age < 365) return { grade: 'B', color: 'var(--risk-caution)' };
  return { grade: 'C', color: 'var(--risk-danger)' };
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
  if (s === 'high') return { bg: 'var(--risk-danger)', text: 'var(--text-inverse)' };
  if (s === 'medium') return { bg: 'var(--risk-caution)', text: 'var(--text-inverse)' };
  return { bg: 'var(--risk-safe)', text: 'var(--text-inverse)' };
}

function confidenceLabel(result: ScanResult | null): string {
  if (!result) return 'Low';
  const c = result.confidence;
  if (typeof c === 'number') {
    if (c >= 5) return 'High';
    if (c >= 3) return 'Medium';
    return 'Low';
  }
  const n = (result.reasons?.length || 0) + (result.details?.tld ? 1 : 0) + (result.details?.brand_hits ? 1 : 0);
  if (n >= 5) return 'High';
  if (n >= 3) return 'Medium';
  return 'Low';
}

export default function App() {
  const [theme, setTheme] = useState<Theme>(loadInitialTheme);
  const [url, setUrl] = useState('');
  const [mode, setMode] = useState<'quick' | 'standard' | 'it'>('standard');
  const [familyMode, setFamilyMode] = useState(false);
  const [simpleMode, setSimpleMode] = useState<boolean>(() => {
    try { const v = localStorage.getItem('phishchecker-simple'); return v === '1'; } catch { return false; }
  });
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [showAwareness, setShowAwareness] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [awarenessMode, setAwarenessMode] = useState<'simple' | 'detailed'>('simple');
  const [showApi, setShowApi] = useState(false);
  const [showFeatures, setShowFeatures] = useState(false);
  const [showAbout, setShowAbout] = useState(false);
  const [showBlog, setShowBlog] = useState(false);
  const [reportId, setReportId] = useState<string | null>(null);
  const [report, setReport] = useState<ScanResult | null>(null);
  const [status, setStatus] = useState<StatusResponse | null>(null);
  const [showStatus, setShowStatus] = useState(false);
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [showCompare, setShowCompare] = useState(false);
  const [historyFilter, setHistoryFilter] = useState<string>('all');
  const [exportOpen, setExportOpen] = useState(false);
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
  const [showDashboard, setShowDashboard] = useState(false);
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
    try { localStorage.setItem('phishchecker-simple', simpleMode ? '1' : '0'); } catch { }
  }, [simpleMode]);

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
    clean: visibleHistory.filter(h => h.risk === 'clean').length,
  };

  const currentScore = result?.score ?? report?.score ?? null;
  const currentRisk = result?.risk ?? report?.risk ?? undefined;
  const riskPct = riskPercent(currentRisk);
  const confidence = confidenceMeta(currentScore);

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <div className="min-h-screen" style={{ background: 'var(--bg-canvas)', color: 'var(--text-secondary)' }}>
        <nav className={`pc-nav ${navShadow ? 'pc-nav-scrolled' : ''}`}>
          <a href="#main" className="pc-skip-link">{t("skipToContent")}</a>
          <div className="pc-nav-inner">
            <a href="/" className="pc-nav-brand" aria-label={t("ariaHome")}>
              <ShieldLogo size={26} />
              {t("brand")}
            </a>
            <button onClick={() => setNavOpen(v => !v)} className="pc-nav-hamburger" aria-label={t("toggleNav")} aria-expanded={navOpen} style={{ background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', padding: '0 1em', lineHeight: 1, minWidth: '44px', minHeight: '44px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
              <Icon name="menu" size={22} />
            </button>
          <div id="pc-nav-items" className={`pc-nav-links ${navOpen ? 'pc-nav-open' : ''}`}>
            <button onClick={() => { setShowHistory(v => !v); if (!showHistory) loadHistory(); }} className={`pc-nav-link ${showHistory ? 'pc-nav-item-active' : ''} `}>{LANG[lang].nav.history}</button>
            <button onClick={() => { setShowDashboard(v => !v); }} className={`pc-nav-link ${showDashboard ? 'pc-nav-item-active' : ''} `}>{showDashboard ? LANG[lang].scan : 'Dashboard'}</button>
            <button onClick={() => { setShowFeatures(v => !v); }} className={`pc-nav-link ${showFeatures ? 'pc-nav-item-active' : ''} `}>{showFeatures ? LANG[lang].scan : 'Features'}</button>
            <button onClick={() => { setShowAwareness(v => !v); }} className={`pc-nav-link ${showAwareness ? 'pc-nav-item-active' : ''} `}>{showAwareness ? LANG[lang].scan : LANG[lang].nav.awareness}</button>
            <button onClick={() => { setShowApi(v => !v); }} className={`pc-nav-link ${showApi ? 'pc-nav-item-active' : ''} `}>{showApi ? LANG[lang].scan : 'API'}</button>
            <button onClick={() => { setShowAbout(v => !v); }} className={`pc-nav-link ${showAbout ? 'pc-nav-item-active' : ''} `}>{showAbout ? LANG[lang].scan : 'About'}</button>
            <button onClick={() => { setShowStatus(v => !v); if (!showStatus) getStatus().then(setStatus).catch(() => setStatus(null)); }} className={`pc-nav-link ${showStatus ? 'pc-nav-item-active' : ''} `}>{showStatus ? LANG[lang].scan : LANG[lang].nav.status}</button>
            <button onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')} className={`pc-nav-link ${theme === 'dark' ? 'pc-nav-item-active' : ''}`} aria-current={theme === 'dark' ? 'page' : undefined} aria-label={t("toggleTheme")}>{theme === 'dark' ? '☀ Light' : '☾ Dark'}</button>
            <button onClick={() => setSimpleMode(v => !v)} className={`pc-nav-link ${simpleMode ? 'pc-nav-item-active' : ''} `} aria-label="Simple mode">{simpleMode ? 'Simple: ON' : 'Simple: OFF'}</button>
            <span style={{ display: 'inline-flex', gap: '0.3em', alignItems: 'center', marginLeft: '0.4em' }}>
              {(Object.keys(LANG) as Lang[]).map(k => (
                <button key={k} onClick={changeLang(k)} aria-label={k} className={`pc-nav-link ${lang === k ? 'pc-nav-item-active' : ''}`} aria-current={lang === k ? 'page' : undefined} style={{ padding: '0.3em 0.5em', fontSize: '0.75em', borderRadius: '999px' }}>{k.toUpperCase()}</button>
              ))}
            </span>
          </div>
          <button onClick={() => { document.getElementById('scan')?.scrollIntoView({ behavior: 'smooth' }); }} className="pc-nav-cta" style={{ marginLeft: 'auto', flexShrink: 0 }}>{t("scanNow")}</button>
          </div>
        </nav>

        <main id="main" style={{ paddingTop: '4.5em' }}>
          <section className="pc-panel pc-hero" style={{ borderTop: 'none', borderRadius: 0, borderLeft: 'none', borderRight: 'none' }}>
            <div style={{ maxWidth: '56em', margin: '0 auto', padding: '3.5em 1.5em' }} className="pc-section">
              <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em', padding: '0.35em 0.8em', borderRadius: '9999px', background: 'var(--brand-muted)', border: '1px solid var(--border-brand)', color: 'var(--brand-500)', fontSize: '0.7rem', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: '1.2em' }}>
                <Icon name="shield" size={14} />
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
                      <button type="button" onClick={() => setUrl('')} disabled={loading} aria-label={t("clearUrl")} style={{ position: 'absolute', right: '0.6em', top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: '0.9em', padding: '0.6em', lineHeight: 1, minWidth: '44px', minHeight: '44px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>
                        <Icon name="x" size={16} />
                      </button>
                    )}
                  </div>
                  <select value={mode} onChange={e => setMode(e.target.value as 'quick' | 'standard' | 'it')} className="pc-select" disabled={loading || familyMode} aria-label={t("fieldMode")} style={{ minWidth: '10em' }}>
                    <option value="quick">{t("quick")}</option>
                    <option value="standard">{t("standard")}</option>
                    <option value="it">{t("itMode")}</option>
                  </select>
                  <button type="submit" disabled={loading} className={`pc-btn-primary ${loading ? 'pc-btn-loading' : ''}`} style={{ whiteSpace: 'nowrap', minHeight: '44px', borderRadius: 'var(--r-md)' }}>
                    {loading ? (<span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5em' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />{LANG[lang].scanning}</span>) : LANG[lang].scan}
                  </button>
                </div>
                {mode && (
                  <span id="url-hint" style={{ fontSize: '0.75em', color: 'var(--text-secondary)', padding: '0.2em 0' }}>
                    {LANG[lang].urlHint[mode]}
                  </span>
                )}
              </form>
              <div style={{ marginTop: '0.8em', display: 'flex', alignItems: 'center', gap: '0.6em', flexWrap: 'wrap' }}>
                <button type="button" onClick={() => setFamilyMode(v => !v)} className="pc-btn-ghost" style={{ fontSize: '0.85em', color: familyMode ? 'var(--text-inverse)' : 'var(--brand-500)', background: familyMode ? 'var(--brand-500)' : 'transparent', border: '1px solid', borderColor: familyMode ? 'var(--brand-500)' : 'var(--border-hairline)' }}>{t("familyMode")}</button>
                {familyMode ? LANG[lang].familyMode.on : LANG[lang].familyMode.off}
                {familyMode && (
                  <span style={{ fontSize: '0.8em', color: 'var(--text-secondary)' }}>{LANG[lang].familyMode.helper}</span>
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
                <div style={{ fontSize: '0.75em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>{t("moreTools")}</div>
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
                <div style={{ fontSize: '0.75em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>{t("communityTitle")}</div>
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
                <div aria-live="polite" style={{ marginTop: '1.2em', padding: '1.6em', border: '1px dashed var(--border-subtle)', background: 'var(--bg-surface-raised)', color: 'var(--text-tertiary)', fontSize: '0.95em', textAlign: 'center', borderRadius: 'var(--r-lg)' }}>
                  <div style={{ fontSize: '2.4em', marginBottom: '0.6em', opacity: 0.9 }} aria-hidden="true"><Icon name="shield" size={28} /></div>
                  <div style={{ color: 'var(--text-primary)', fontWeight: 600, marginBottom: '0.3em' }}>{t("noScansTitle")}</div>
                  <div>{t("noScansBody")}</div>
                  <div style={{ marginTop: '0.4em', fontSize: '0.8em', opacity: 0.8 }}>{t("noScansShortcut")}</div>
                </div>
              )}

              <div className="pc-how-it-works" style={{ marginTop: '2.4em' }}>
                <div className="pc-step">
                  <div className="pc-step-icon">1</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Paste</div>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>Drop a link into the scanner</div>
                </div>
                <div className="pc-step">
                  <div className="pc-step-icon">2</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Scan</div>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>We check TLDs, keywords, brand mimicry, and structure</div>
                </div>
                <div className="pc-step">
                  <div className="pc-step-icon">3</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>Decide</div>
                  <div style={{ fontSize: '0.85em', color: 'var(--text-secondary)' }}>Get a plain-language risk result in seconds</div>
                </div>
              </div>

              <div className="pc-trust-bar" style={{ marginTop: '2em', fontSize: '0.8em', color: 'var(--text-tertiary)', textAlign: 'center' }} aria-label={t("serviceStats")}>
                {(showHistory && historyStats.total != null) ? (
                  <>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--brand-500)', fontFamily: 'var(--font-display)' }}>{historyStats.total}</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("total")}</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--risk-danger)', fontFamily: 'var(--font-display)' }}>{historyStats.high}</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("high")}</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--risk-caution)', fontFamily: 'var(--font-display)' }}>{historyStats.suspicious}</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("suspicious")}</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--risk-safe)', fontFamily: 'var(--font-display)' }}>{historyStats.low}</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("low")}</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-display)' }}>{historyStats.clean}</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Clean</span>
                    </div>
                  </>
                ) : (
                  <>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--brand-500)', fontFamily: 'var(--font-display)' }}>Free</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Now</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--brand-500)', fontFamily: 'var(--font-display)' }}>No account</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Required</span>
                    </div>
                    <div className="pc-trust-item">
                      <span style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--brand-500)', fontFamily: 'var(--font-display)' }}>No tracking</span>
                      <span style={{ fontSize: '0.7em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>By design</span>
                    </div>
                  </>
                )}
              </div>
              <div style={{ marginTop: '0.8em', display: 'inline-flex', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>
                <Icon name="lock" size={14} />
                <span>{t("noPersonalData")}</span>
              </div>
              {error && (
                <div role="alert" aria-live="assertive" className="pc-toast">
                  <span style={{ fontWeight: 600 }}>{t("errorTitle")}</span>
                  <span>{error}</span>
                  <button type="button" onClick={doScan} className="pc-btn-ghost pc-btn-sm" style={{ borderColor: 'rgba(255,255,255,0.35)', color: 'inherit' }}>{t("retry")}</button>
                </div>
              )}
            </div>
          </section>

          <section className="pc-section" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
            <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '1.6em 1.5em' }}>
              <div className="pc-stack pc-gap-3" style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                <h2 className="pc-section-title">{t("batchTitle")}</h2>
                <button type="button" onClick={() => { setBatchMode(v => !v); setBatchResults(null); setBatchError(null); }} className="pc-btn-ghost pc-btn-sm">{batchMode ? 'Close batch' : 'Open batch'}</button>
              </div>
              {batchMode && (
                <form onSubmit={handleBatch} className="pc-stack pc-gap-3" style={{ maxWidth: '42em' }}>
                  <label htmlFor="batch-input" style={{ position: 'absolute', overflow: 'hidden', clip: 'rect(0 0 0 0)', whiteSpace: 'nowrap', width: '1px', height: '1px' }}>{t("batchLabel")}</label>
                  <textarea id="batch-input" value={batchInput} onChange={e => setBatchInput(e.target.value)} placeholder={t("batchPlaceholder")} className="pc-input pc-placeholder" disabled={batchRunning} rows={6} style={{ resize: 'vertical' }} />
                  <div className="pc-stack pc-gap-2" style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
                    <button type="submit" disabled={batchRunning} className="pc-btn-primary" style={{ whiteSpace: 'nowrap' }}>
                      {batchRunning ? (<span className="pc-center pc-gap-2" style={{ display: 'inline-flex' }}><span className="pc-spinner" style={{ width: '1em', height: '1em', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'pc-spin 0.8s linear infinite' }} />{t("scanning")}</span>) : 'Scan batch'}
                    </button>
                    <span className="pc-section" style={{ fontSize: '0.7em', color: 'var(--text-secondary)', alignSelf: 'center' }}>{t("maxUrls")}</span>
                  </div>
                  {batchError && (
                    <p className="pc-center pc-gap-2" style={{ color: 'var(--risk-danger)', fontSize: '0.85em', flexWrap: 'wrap' }}>
                      {batchError}
                      <button type="button" onClick={() => setBatchError(null)} className="pc-btn-ghost pc-btn-sm">{t("retry")}</button>
                    </p>
                  )}
                  {batchResults && (
                    <div className="pc-reveal-stagger pc-results-grid">
                      {batchResults.filter((r, i, arr) => arr.findIndex(x => (x.domain || x.url) === (r.domain || r.url)) === i).map(r => (
                        <div key={r.id || r.url} className="pc-results-card">
                          <div className="pc-results-score" style={{ color: scoreColor(r.score) }}>{r.score}/100</div>
                          <div style={{ minWidth: 0 }}>
                            <div className="pc-results-domain">{r.domain || r.url}</div>
                            <div className="pc-results-meta">{modeLabel(r.mode)} · {r.duration_ms != null ? `${r.duration_ms} ms` : '—'}</div>
                          </div>
                          <span className={`${r.risk === 'high' ? 'pc-risk-high' : r.risk === 'suspicious' ? 'pc-risk-suspicious' : 'pc-risk-low'}`} style={{ marginLeft: 'auto', fontSize: '0.75em', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>{r.risk}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </form>
              )}
            </div>
          </section>

          {!result && !loading && !reportId && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '72em', margin: '0 auto', padding: '1.8em 1.5em', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em' }} className="pc-section">
                {history.slice(0, 3).map((h) => (
                  <div key={h.id} className="pc-panel pc-history-card">
                    <div className="pc-stack pc-gap-2" style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span className="pc-history-domain">{h.domain}</span>
                      <span className={`pc-badge ${h.risk === 'high' ? 'pc-badge-high' : h.risk === 'suspicious' ? 'pc-badge-suspicious' : 'pc-badge-low'}`}>{h.risk}</span>
                    </div>
                    <div className="pc-history-score">{h.score}/100</div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {showAwareness && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
                <div className="pc-stack pc-gap-3" style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap' }}>
                  <h2 className="pc-section-title">{t("awarenessTitle")}</h2>
                  <div style={{ display: 'inline-flex', gap: '0.4em', background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '0.3em', borderRadius: 'var(--r-pill)' }}>
                    <button type="button" onClick={() => setAwarenessMode('simple')} className="pc-btn-ghost pc-btn-sm" style={{ borderRadius: 'var(--r-pill)', background: awarenessMode === 'simple' ? 'var(--brand-500)' : 'transparent', color: awarenessMode === 'simple' ? 'var(--text-inverse)' : 'var(--text-secondary)' }}>{t("simpleMode")}</button>
                    <button type="button" onClick={() => setAwarenessMode('detailed')} className="pc-btn-ghost pc-btn-sm" style={{ borderRadius: 'var(--r-pill)', background: awarenessMode === 'detailed' ? 'var(--brand-500)' : 'transparent', color: awarenessMode === 'detailed' ? 'var(--text-inverse)' : 'var(--text-secondary)' }}>{t("detailedMode")}</button>
                  </div>
                </div>

                {awarenessMode === 'simple' && (
                  <div className="pc-stack pc-gap-4" style={{ fontSize: '1.05em', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                    <div className="pc-example-card">
                      <p style={{ margin: 0, fontSize: '1.05em', color: 'var(--text-primary)' }}>{t("awarenessLead")}</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em', color: 'var(--text-primary)' }}>They want your password, OTP, or payment.</p>
                      <p style={{ margin: '0.6em 0 0', fontSize: '1.05em', color: 'var(--text-primary)' }}>{t("awarenessLine2")}</p>
                    </div>

                    <div className="pc-example-card">
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true"><Icon name="smartphone" size={18} /></span> Example 1: Fake bank text
                      </h3>
                      <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '22em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("smsLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: 'var(--risk-danger)' }}>{t("alertLabel")}</strong> Your bank account is locked.<br/>
                          <span style={{ color: 'var(--brand-300)' }}>{t("tapHere")}</span><br/>
                          <span style={{ color: 'var(--risk-danger)', textDecoration: 'underline' }}>http://bank-secure.xyz/login</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 'var(--r-md)', fontSize: '0.85em', color: 'var(--risk-danger)' }}>
                          <Icon name="alert-triangle" size={14} /> Red flags: fear words, strange address, asks for login by text
                        </div>
                      </div>
                    </div>

                    <div className="pc-example-card">
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true"><Icon name="mail" size={18} /></span> Example 2: Fake delivery notification
                      </h3>
                      <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '24em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("emailLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: 'var(--risk-danger)' }}>{t("actionRequired")}</strong> Your parcel cannot be delivered.<br/>
                          Open the label: <span style={{ color: 'var(--brand-300)' }}>https://delivery-tracking.info/parcel</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 'var(--r-md)', fontSize: '0.85em', color: 'var(--risk-danger)' }}>
                          <Icon name="alert-triangle" size={14} /> Red flags: no tracking number, wrong domain, asks to download file
                        </div>
                      </div>
                    </div>

                    <div className="pc-example-card">
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true"><Icon name="lock" size={18} /></span> Example 3: Fake account alert
                      </h3>
                      <div style={{ background: 'var(--bg-canvas)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--r-md)', padding: '1.2em', maxWidth: '24em' }}>
                        <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', marginBottom: '0.6em', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{t("emailLabel")}</div>
                        <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          <strong style={{ color: 'var(--risk-danger)' }}>{t("securityNotice")}</strong> Someone logged into your account.<br/>
                          Secure it now: <span style={{ color: 'var(--brand-300)' }}>https://account-security-alert.xyz/reset</span>
                        </div>
                        <div style={{ marginTop: '0.8em', padding: '0.6em', background: 'rgba(220,38,38,0.1)', border: '1px solid rgba(220,38,38,0.25)', borderRadius: 'var(--r-md)', fontSize: '0.85em', color: 'var(--risk-danger)' }}>
                          <Icon name="alert-triangle" size={14} /> Red flags: urgent tone, generic greeting, link to lookalike domain
                        </div>
                      </div>
                    </div>

                    <div className="pc-example-card" style={{ borderColor: 'var(--border-brand)', background: 'linear-gradient(135deg, var(--bg-surface) 0%, var(--brand-muted) 100%)' }}>
                      <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--brand-500)', margin: '0 0 0.8em', display: 'flex', alignItems: 'center', gap: '0.4em' }}>
                        <span aria-hidden="true"><Icon name="check-circle" size={18} /></span> Quick checks
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
                  <div style={{ fontSize: '0.9em', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                    <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-primary)', marginBottom: '0.4em' }}>{t("redFlags")}</h3>
                      <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                        <li>{t("detailUnexpected")}</li>
                        <li>{t("detailImpersonate")}</li>
                        <li>Requests for credentials, OTPs, or payments via email/SMS</li>
                        <li>{t("detailShortened")}</li>
                      </ul>
                    </div>
                    <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)', marginBottom: '1em' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-primary)', marginBottom: '0.4em' }}>{t("howToCheck")}</h3>
                      <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em' }}>
                        <li>{t("howHover")}</li>
                        <li>{t("howScanner")}</li>
                        <li>{t("howSsl")}</li>
                        <li>{t("howOfficial")}</li>
                      </ul>
                    </div>
                    <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                      <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-primary)', marginBottom: '0.4em' }}>{t("understandingRisk")}</h3>
                      <p>{t("riskHigh")} {t("riskSuspicious")} {t("riskClean")}</p>
                    </div>
                  </div>
                )}
              </div>
            </section>
          )}

          {showApi && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-primary)', marginBottom: '0.8em' }}>{t("apiTitle")}</h2>
                <div style={{ display: 'grid', gap: '1em', fontSize: '0.9em', lineHeight: 1.6 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>POST</span>
                      <code style={{ background: 'var(--bg-canvas)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans</code>
                    </div>
                    <p>{t("apiScanPost")} <code>/api/csrf</code>.</p>
                    <pre style={{ marginTop: '0.6em', whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '1em', background: 'var(--bg-surface)', fontSize: '0.8em', lineHeight: 1.6, border: '1px solid var(--border-hairline)' }}>{`{
  "url": "https://example.com",
  "mode": "standard"
}`}</pre>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>GET</span>
                      <code style={{ background: 'var(--bg-canvas)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans/history</code>
                    </div>
                    <p>{t("apiHistory")} <code>page</code> {t("and")} <code>page_size</code> {t("queryParams")}.</p>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>GET</span>
                      <code style={{ background: 'var(--bg-canvas)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/status</code>
                    </div>
                    <p>{t("apiStatus")}</p>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6em', marginBottom: '0.4em', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>GET</span>
                      <code style={{ background: 'var(--bg-canvas)', padding: '0.2em 0.4em', fontSize: '0.85em' }}>/api/v2/scans/export</code>
                    </div>
                    <p>{t("apiExport")} <code>?format=json</code> {t("or")} <code>?format=csv</code>.</p>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showStatus && status && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-primary)' }}>{t("statusTitle")}</h2>
                  <span className="pc-badge pc-badge-low">{t("operational")}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("statusService")}</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{status.service || 'PhishChecker'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("statusVersion")}</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{status.version || '—'}</div>
                  </div>
                  <div style={{ padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("apiAccess")}</div>
                    <div style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{status.features?.publicScanning ? 'Open' : 'Restricted'}</div>
                  </div>
                </div>
                <div style={{ marginTop: '1.2em', padding: '1em', border: '1px solid var(--border-hairline)', background: 'var(--bg-surface-raised)', fontSize: '0.85em', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  Scanner availability: use the form above for direct scans. This panel shows service health and access mode only.
                  <div style={{ marginTop: '0.6em' }}>
                    <strong>{t("supportText")}</strong> use the in-app contact or <a href="mailto:molonkunuku@gmail.com" style={{ color: 'var(--brand-500)', textDecoration: 'underline' }}>molonkunuku@gmail.com</a>.
                  </div>
                </div>
              </div>
            </section>
          )}

          {showDashboard && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-primary)' }}>Dashboard</h2>
                  <span className="pc-badge pc-badge-low">Local only</span>
                </div>
                <div className="pc-reveal-stagger" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5, marginBottom: '1.2em' }}>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("total")}</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{historyStats.total}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("high")}</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-danger)' }}>{historyStats.high}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("suspicious")}</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-caution)' }}>{historyStats.suspicious}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("low")}</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-safe)' }}>{historyStats.low}</div>
                  </div>
                  <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>Clean</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{historyStats.clean}</div>
                  </div>
                </div>
                <div style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1em', borderRadius: 'var(--r-lg)', fontSize: '0.85em', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                  This dashboard reflects your current local scan history for this browser. It is not an account and is not synced remotely.
                </div>
              </div>
            </section>
          )}

          {!reportId && result && (
            <section className={`pc-animate-in pc-section-enter ${familyMode ? 'pc-family-mode' : ''}`} style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
                <div className="pc-stack pc-gap-3" style={{ flexDirection: 'column', alignItems: 'center', gap: '1em', marginBottom: '1.6em' }}>
                  <div className={`pc-verdict pc-verdict-enter ${riskVerdict(currentRisk).className}`}>{riskVerdict(currentRisk).label}</div>
                  <div style={{ fontSize: '0.95em', color: 'var(--text-secondary)', textAlign: 'center', lineHeight: 1.6 }}>{riskAction(result)}</div>
                  <div className="pc-gauge" role="img" aria-label={`Risk score: ${currentScore ?? '—'} out of 100, ${currentRisk || 'unknown'} risk`}>
                    <svg viewBox="0 0 100 100" style={{ width: '100%', height: '100%', transform: 'rotate(-90deg)' }}>
                      <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
                      <circle cx="50" cy="50" r="42" fill="none" stroke={scoreColor(currentScore)} strokeWidth="10" strokeLinecap="round" strokeDasharray={`${(Math.max(0, Math.min(100, currentScore ?? 0)) / 100) * 264} 264`} style={{ transition: 'stroke-dasharray 1s cubic-bezier(0.4, 0, 0.2, 1)' }} />
                    </svg>
                    <div className="pc-gauge-text">
                      <div className="pc-gauge-score" style={{ color: scoreColor(currentScore) }}>{currentScore ?? '—'}</div>
                      <div className="pc-gauge-label">of 100</div>
                    </div>
                  </div>
                  <div className="pc-confidence-meter">
                    <span style={{ fontSize: '0.7em', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-secondary)' }}>Confidence</span>
                    <div className="pc-confidence-bar"><div className="pc-confidence-fill" style={{ width: `${Math.min(100, (result.confidence ?? ((result.reasons?.length || 0) + (result.details?.tld ? 1 : 0) + (result.details?.brand_hits ? 1 : 0)) * 18))}%` }} /></div>
                    <span style={{ fontSize: '0.75em', fontWeight: 700, color: 'var(--brand-500)' }}>{confidenceLabel(result)}</span>
                  </div>
                </div>

                {familyMode && result && (
                  <div className="pc-example-card" style={{ borderColor: 'var(--border-brand)', background: 'linear-gradient(135deg, var(--bg-surface) 0%, var(--brand-muted) 100%)' }}>
                    <div className="pc-stack pc-gap-2" style={{ flexDirection: 'row', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--brand-500)', marginBottom: '0.4em' }}>
                      <Icon name="shield-check" size={16} /> Family Mode
                    </div>
                    {familySummary(result)}
                  </div>
                )}

                {simpleMode && result && (
                  <div className="pc-example-card" style={{ borderColor: 'var(--border-brand)', background: 'linear-gradient(135deg, var(--bg-surface) 0%, var(--brand-muted) 100%)' }}>
                    <div className="pc-stack pc-gap-2" style={{ flexDirection: 'row', alignItems: 'center', gap: '0.4em', fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--brand-500)', marginBottom: '0.4em' }}>
                      <Icon name="shield-check" size={16} /> Simple Mode
                    </div>
                    {familySummary(result)}
                    <div style={{ marginTop: '0.6em', fontSize: '0.95em', color: 'var(--text-secondary)' }}>
                      {currentRisk === 'high' ? 'Avoid this site. Do not enter passwords, OTPs, or card details.' : currentRisk === 'suspicious' ? 'Be careful here. If something feels off, close the page and open the official app or website instead.' : 'No strong danger signs were found, but always double-check before trusting any site.'}
                    </div>
                  </div>
                )}

                {result.details?.checks && (
                  <div className="pc-example-card">
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-primary)', marginBottom: '0.4em' }}>What we checked</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4em' }}>
                      {Object.entries(result.details.checks).map(([key, val]) => (
                        <span key={key} className="pc-badge pc-badge-low" style={{ background: val ? 'rgba(11,133,96,0.12)' : 'rgba(220,38,38,0.12)', color: val ? 'var(--risk-safe)' : 'var(--risk-danger)' }}>{key}</span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '0.6em', flexWrap: 'wrap', marginBottom: '1.4em', justifyContent: 'center', alignItems: 'center' }}>
                  <button onClick={copyScanLink} className="pc-btn-primary" style={{ boxShadow: '0 4px 18px rgba(227,174,55,.25)' }}>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45em' }}>
                      <Icon name="copy" size={16} />
                      {t("copyLink")}
                    </span>
                  </button>

                  <div style={{ position: 'relative', display: 'inline-flex' }}>
                    <button onClick={() => setExportOpen(v => !v)} className="pc-btn-secondary" style={{ padding: '14px 20px', borderRadius: 'var(--r-lg)' }}>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.45em' }}>
                        <Icon name="download" size={16} />
                        {t("exportMenu")}
                        <Icon name="chevron-down" size={16} />
                      </span>
                    </button>
                    {exportOpen && (
                      <div style={{ position: 'absolute', top: 'calc(100% + 0.4em)', right: 0, background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--r-lg)', boxShadow: '0 8px 24px rgba(0,0,0,.35)', minWidth: '14em', zIndex: 50, overflow: 'hidden' }} className="pc-animate-in">
                        <button onClick={() => { downloadExport('json'); setExportOpen(false); }} className="pc-btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '0.75em 1em', borderRadius: 0, borderBottom: '1px solid var(--border-hairline)' }}>{t("exportJson")}</button>
                        <button onClick={() => { downloadExport('csv'); setExportOpen(false); }} className="pc-btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '0.75em 1em', borderRadius: 0, borderBottom: '1px solid var(--border-hairline)' }}>{t("exportCsv")}</button>
                        <button onClick={() => { copyScanJSON(); setExportOpen(false); }} className="pc-btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '0.75em 1em', borderRadius: 0, borderBottom: '1px solid var(--border-hairline)' }}>{t("copyJson")}</button>
                        <button onClick={() => { result && downloadPDF(result); setExportOpen(false); }} className="pc-btn-ghost" style={{ width: '100%', justifyContent: 'flex-start', padding: '0.75em 1em', borderRadius: 0 }}>{t("exportReport")}</button>
                      </div>
                    )}
                  </div>

                  <button onClick={() => window.print()} className="pc-btn-secondary" style={{ padding: '14px 14px', borderRadius: 'var(--r-lg)', minWidth: '44px', minHeight: '44px' }} aria-label={t("print")}>
                    <Icon name="printer" size={18} />
                  </button>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1em', fontSize: '0.9em', lineHeight: 1.5, marginBottom: '1.2em' }} className="pc-mobile-stack">
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldUrl")}</span>
                    <p style={{ wordBreak: 'break-all', color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{result.url}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldDomain")}</span>
                    <p style={{ wordBreak: 'break-all', color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{result.domain}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldMode")}</span>
                    <p style={{ color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{modeLabel(result.mode)}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldStarted")}</span>
                    <p style={{ color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{result.started_at ? new Date(result.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldDomainAge")}</span>
                    <p style={{ color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{(() => { const da = (result.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.85em', color: 'var(--text-tertiary)', marginTop: '0.35em' }}>{t("newDomainWarning")}</div></>; })()}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldDuration")}</span>
                    <p style={{ color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{result.duration_ms != null ? `${result.duration_ms} ms` : '—'}</p>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.25em', borderRadius: 'var(--r-lg)', gridColumn: '1 / -1' }}>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.4em' }}>{t("fieldCertificate")}</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center', color: 'var(--text-primary)', fontSize: '1.0625rem', fontWeight: 500 }}>{(() => { const ssl = (result.details?.ssl || {}) as any; const grade = sslGrade(result.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return <><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>{t("copy")}</button></>; })()}</p>
                  </div>
                </div>

                {((result.details || {}) as any).score_math && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-primary)', fontSize: '0.8em' }}>{t("scoreBreakdown")}</summary>
                    <div style={{ marginTop: '0.8em', padding: '1em', background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', borderRadius: 'var(--r-lg)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '0.4em 1em', alignItems: 'center' }}>
                        <span>{t("baseScore")}</span><span style={{ fontWeight: 600 }}>100</span>
                        <span>{t("headersPenalty")}</span><span style={{ color: 'var(--risk-danger)' }}>-{((result.details as any)?.score_math as any)?.header_penalty}</span>
                        <span>{t("sslPenalty")}</span><span style={{ color: 'var(--risk-danger)' }}>-{((result.details as any)?.score_math as any)?.ssl_penalty}</span>
                        <span>{t("threatIntelPenalty")}</span><span style={{ color: 'var(--risk-danger)' }}>-{((result.details as any)?.score_math as any)?.threat_intel_penalty}</span>
                        <span>{t("domainShapePenalty")}</span><span style={{ color: 'var(--risk-danger)' }}>-{((result.details as any)?.score_math as any)?.domain_penalty}</span>
                        <span style={{ fontWeight: 600, borderTop: '1px solid var(--border-hairline)', paddingTop: '0.4em' }}>{t("finalScore")}</span><span style={{ fontWeight: 700, color: scoreColor(currentScore) }}>{((result.details as any)?.score_math as any)?.final_score}</span>
                      </div>
                    </div>
                  </details>
                )}

                {(((result.details || {}) as any).redirect_chain?.length || 0) > 1 && (
                  <div style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.4em' }}>{t("redirectChain")}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.4em', color: 'var(--text-secondary)', lineHeight: 1.6, wordBreak: 'break-all' }}>
                      {(((result.details || {}) as any).redirect_chain as string[]).map((u: string, i: number, arr: string[]) => (
                        <span key={i} style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4em' }}>
                          <span style={{ fontSize: '0.8em', fontWeight: 600, color: 'var(--brand-500)' }}>{i + 1}</span>
                          <span>{u}</span>
                          {i < arr.length - 1 && <span style={{ color: 'var(--text-secondary)', opacity: 0.7 }}>→</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em', marginBottom: '1.4em' }}>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>{t("riskLevel")}</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: riskColor(currentRisk) }}>{currentRisk || '—'}</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--bg-canvas)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${riskPct}%`, background: riskColor(currentRisk), transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', padding: '1.2em' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6em' }}>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>{t("scoreLabel")}</span>
                      <span style={{ fontSize: '0.7em', fontWeight: 600, color: 'var(--text-primary)' }}>{currentScore ?? '—'}/100</span>
                    </div>
                    <div style={{ height: '6px', background: 'var(--bg-canvas)', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${Math.max(0, Math.min(100, currentScore ?? 0))}%`, background: 'var(--brand-500)', transition: 'width 420ms ease' }} />
                    </div>
                  </div>
                </div>

                {(result.findings?.length ? result.findings : (result.reasons || []).map(r => ({
                  id: r.toLowerCase().replace(/[^a-z0-9]+/g, '_'),
                  severity: severityOf(r),
                  text: r,
                  action: findingSummary(r),
                  raw: r,
                }))).filter((f: any) => findingFilter === 'all' || f.severity === findingFilter).map((f: any, i: number) => {
                  const st = severityStyle(f.severity);
                  return (
                    <li key={i} className="pc-finding-item">
                      <details style={{ display: 'inline-block', width: '100%' }}>
                        <summary style={{ cursor: 'pointer', fontWeight: 600, color: 'var(--text-primary)', listStyle: 'none', display: 'inline-flex', alignItems: 'center', gap: '0.4em', flexWrap: 'wrap' }}>
                          <span style={{ fontSize: '0.65em', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', background: st.bg, color: st.text, padding: '0.2em 0.45em', borderRadius: '0.25em' }}>{f.severity}</span>
                          <span>{f.text}</span>
                        </summary>
                        <div style={{ marginTop: '0.5em', padding: '0.8em', background: 'var(--bg-surface)', border: '1px solid var(--border-hairline)', fontSize: '0.85em', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
                          <strong style={{ color: 'var(--text-primary)' }}>What to do:</strong> {f.action}
                        </div>
                      </details>
                    </li>
                  );
                })}

                {result.details && (
                  <details style={{ marginTop: '1.2em', fontSize: '0.9em' }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-secondary)', fontSize: '0.8em' }}>{t("rawDetails")}</summary>
                    <pre style={{ marginTop: '0.8em', whiteSpace: 'pre-wrap', wordBreak: 'break-word', padding: '1em', background: 'var(--bg-surface)', fontSize: '0.8em', lineHeight: 1.6, border: '1px solid var(--border-hairline)' }}>{JSON.stringify(result.details, null, 2)}</pre>
                  </details>
                )}
              </div>
            </section>
          )}

          {reportId && report && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.4rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>{t("scanReport")}</h2>
                  <button onClick={() => { setReportId(null); setReport(null); window.location.hash = ''; }} className="pc-btn-ghost">{t("back")}</button>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.8em', marginBottom: '1.2em', flexWrap: 'wrap' }}>
                  <div style={{ position: 'relative', width: '3.2em', height: '3.2em' }}>
                    <svg viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)', width: '100%', height: '100%' }}>
                      <circle cx="18" cy="18" r="15.5" fill="none" stroke="var(--bg-canvas)" strokeWidth="3" />
                      <circle cx="18" cy="18" r="15.5" fill="none" stroke={riskColor(report.risk)} strokeWidth="3" strokeDasharray={`${riskPercent(report.risk) / 100 * 97.39} 97.39`} strokeLinecap="round" style={{ transition: 'stroke-dasharray 420ms ease, stroke 420ms ease' }} />
                    </svg>
                    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75em', fontWeight: 700, color: 'var(--text-primary)', transform: 'none' }}>{report.score ?? '—'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.2em' }}>{t("riskScore")}</div>
                    <div style={{ fontSize: '0.85em', fontWeight: 600, color: riskColor(report.risk) }}>{report.risk ? report.risk.toUpperCase() : '—'}</div>
                    {confidence && (
                      <div style={{ fontSize: '0.65em', color: confidence.color, fontWeight: 600 }}>{confidence.label}</div>
                    )}
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(14em, 1fr))', gap: '1.2em', fontSize: '0.9em', lineHeight: 1.5 }}>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldUrl")}</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.url}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldDomain")}</span>
                    <p style={{ wordBreak: 'break-all' }}>{report.domain}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldMode")}</span>
                    <p>{modeLabel(report.mode)}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldStarted")}</span>
                    <p>{report.started_at ? new Date(report.started_at).toLocaleString() : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldDomainAge")}</span>
                    <p>{(() => { const da = (report.details?.domain_age || {}) as any; const days = da?.age_days; const created = da?.created_at; if (days == null && !created) return '—'; const text = days != null ? `${days} days` : `created ${created || 'unknown'}`; const flagged = typeof days === 'number' && days < 30 ? ' - flagged' : ''; return <><span>{text}{flagged}</span><div style={{ fontSize: '0.75em', color: 'var(--text-secondary)', marginTop: '0.25em' }}>{t("newDomainWarning")}</div></>; })()}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldDuration")}</span>
                    <p>{report.duration_ms != null ? `${report.duration_ms} ms` : '—'}</p>
                  </div>
                  <div>
                    <span style={{ display: 'block', fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.3em' }}>{t("fieldCertificate")}</span>
                    <p style={{ wordBreak: 'break-all', display: 'flex', flexWrap: 'wrap', gap: '0.6em', alignItems: 'center' }}>{(() => { const ssl = (report.details?.ssl || {}) as any; const grade = sslGrade(report.details); const issuer = ssl?.issuer || '—'; const valid = ssl?.valid ? 'Valid' : 'Invalid or untrusted'; const age = ssl?.age_days != null ? `${ssl.age_days} days` : ''; const text = `${valid}${grade && ssl?.valid ? ' · ' + grade.grade : ''}${age ? ' · ' + age : ''} · ${issuer}`; return (<><span style={{ flex: '1 1 auto', minWidth: '0' }}>{text}</span><button type="button" onClick={() => { navigator.clipboard.writeText(text).catch(() => {}); }} className="pc-btn-ghost" style={{ flex: '0 0 auto' }}>{t("copy")}</button></>); })()}</p>
                  </div>
                </div>

                {report.reasons && report.reasons.length > 0 && (
                  <div className="pc-divider" style={{ marginTop: '1.4em', paddingTop: '1.2em' }}>
                    <h3 style={{ fontSize: '0.75em', fontWeight: 600, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.6em' }}>{t("findings")}</h3>
                    <ul style={{ listStyle: 'disc', paddingLeft: '1.2em', display: 'grid', gap: '0.35em', fontSize: '0.9em', lineHeight: 1.5 }}>
                      {report.reasons.map((r, i) => <li key={i}>{r}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </section>
          )}

          {reportId && !report && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em', color: 'var(--text-secondary)' }}>{t("loadingReport")}</div>
            </section>
          )}

          {showHistory && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <div>
                    <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-primary)', margin: 0 }}>{t("recentScans")}</h2>
                    <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', marginTop: '0.35em' }}>{t("historyNote")}</div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5em', flexWrap: 'wrap', alignItems: 'center' }}>
                    <input value={historySearch} onChange={e => setHistorySearch(e.target.value)} placeholder={t("historySearchPlaceholder")} className="pc-input" style={{ padding: '0.55em 0.7em', fontSize: '0.8em', minWidth: '14em' }} />
                    <button onClick={() => loadHistory()} className="pc-btn-ghost" style={{ color: 'var(--brand-500)' }}>{t("refresh")}</button>
                  </div>
                </div>

                {history.length > 0 && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(12em, 1fr))', gap: '0.8em', marginBottom: '1.2em' }}>
                    <div className="pc-dashboard-card">
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("total")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{historyStats.total}</div>
                    </div>
                    <div className="pc-dashboard-card">
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("high")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-danger)' }}>{historyStats.high}</div>
                    </div>
                    <div className="pc-dashboard-card">
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("suspicious")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-caution)' }}>{historyStats.suspicious}</div>
                    </div>
                    <div className="pc-dashboard-card">
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("low")}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--risk-safe)' }}>{historyStats.low}</div>
                    </div>
                    <div className="pc-dashboard-card">
                      <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>Clean</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 600, color: 'var(--text-primary)' }}>{historyStats.clean}</div>
                    </div>
                  </div>
                )}

                {history.length === 0 && <div className="pc-empty" aria-live="polite"><div className="pc-empty-icon" aria-hidden="true"><Icon name="clock" size={28} /></div><div className="pc-empty-title">{t("noScansTitle")}</div><div className="pc-empty-body">{t("recentEmpty")}</div></div>}
                {history.length > 0 && visibleHistory.length === 0 && <div className="pc-empty" aria-live="polite"><div className="pc-empty-icon" aria-hidden="true"><Icon name="search" size={28} /></div><div className="pc-empty-title">{t("noMatchingScans")}</div><div className="pc-empty-body">{t("noMatchingHint")}</div></div>}

                {visibleHistory.length > 0 && (
                  <div style={{ display: 'grid', gap: '0.6em' }}>
                    {visibleHistory.slice(0, historyPageSize).map(h => {
                      const badge = h.risk === 'high' ? 'pc-badge-high' : h.risk === 'suspicious' ? 'pc-badge-suspicious' : 'pc-badge-low';
                      const itemScoreColor = scoreColor(h.score);
                      return (
                        <div key={h.id} className="pc-panel pc-history-item-enter" style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '0.6em', alignItems: 'center', padding: '0.9em 1em' }}>
                          <div style={{ minWidth: 0 }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5em', marginBottom: '0.3em', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.85em', fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{h.domain || h.url}</span>
                              <span className={badge} style={{ fontSize: '0.65em', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', padding: '0.25em 0.5em' }}>{h.risk}</span>
                            </div>
                            <div style={{ fontSize: '0.8em', color: 'var(--text-secondary)', display: 'flex', gap: '0.8em', flexWrap: 'wrap' }}>
                              <span style={{ color: itemScoreColor, fontWeight: 600 }}>{h.score}/100</span>
                              <span>{modeLabel(h.mode)}</span>
                              <span>{h.duration_ms != null ? `${h.duration_ms} ms` : ''}</span>
                              <span>{relativeTime(h.started_at)}</span>
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: '0.4em', justifyContent: 'flex-end' }}>
                            <button className="pc-btn-secondary" style={{ fontSize: '0.7em', padding: '0.45em 0.7em', minHeight: '32px' }} onClick={() => { setReportId(h.id); setReport(null); window.location.hash = `#/scan/${h.id}`; }}>{t("view")}</button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '0.8em', fontSize: '0.8em', color: 'var(--text-tertiary)', flexWrap: 'wrap', gap: '0.5em' }}>
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
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div style={{ maxWidth: '56em', margin: '0 auto', padding: '2em 1.5em' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1em', flexWrap: 'wrap', gap: '0.5em' }}>
                  <h2 style={{ fontFamily: 'var(--font-display)', fontSize: '1.25rem', fontWeight: 600, letterSpacing: '-0.01em', color: 'var(--text-primary)' }}>{t("comparison")}</h2>
                  <button onClick={() => setShowCompare(false)} className="pc-btn-ghost">{t("close")}</button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(16em, 1fr))', gap: '1.2em' }}>
                  {compareIds.map(id => {
                    const item = history.find(h => h.id === id);
                    if (!item) return null;
                    const riskColorVal = riskColor(item.risk);
                    return (
                      <div key={id} style={{ background: 'var(--bg-surface-raised)', border: '1px solid var(--border-hairline)', padding: '1.2em', borderRadius: 'var(--r-lg)' }}>
                        <div style={{ fontSize: '0.7em', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.3em' }}>{t("fieldDomain")}</div>
                        <div style={{ wordBreak: 'break-all', marginBottom: '1em', color: 'var(--text-primary)', fontWeight: 500 }}>{item.domain}</div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6em', fontSize: '0.85em' }}>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.2em' }}>{t("riskLevel")}</div>
                            <div style={{ color: riskColorVal, fontWeight: 600 }}>{item.risk}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.2em' }}>{t("scoreLabel")}</div>
                            <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{item.score}/100</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.2em' }}>{t("fieldMode")}</div>
                            <div style={{ textTransform: 'capitalize', color: 'var(--text-primary)' }}>{modeLabel(item.mode)}</div>
                          </div>
                          <div>
                            <div style={{ fontSize: '0.7em', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)', marginBottom: '0.2em' }}>{t("fieldDuration")}</div>
                            <div style={{ color: 'var(--text-primary)' }}>{item.duration_ms != null ? `${item.duration_ms} ms` : '—'}</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </section>
          )}

          {showAbout && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
                <h2 className="pc-section-title">About</h2>
                <div className="pc-stack pc-gap-4" style={{ fontSize: '0.95em', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
                  <p>PhishChecker is a free, privacy-first URL risk checker built to help everyday users — especially elderly or less tech-literate people — spot suspicious links before they tap or click.</p>
                  <p>It does not require accounts, does not track users, and does not store scanned URLs longer than necessary. The goal is simple: make phishing detection understandable, fast, and available to everyone.</p>
                  <div className="pc-features-grid" style={{ marginTop: '0.6em' }}>
                    <div className="pc-feature-card">
                      <div className="pc-feature-title">Mission</div>
                      <p style={{ margin: 0 }}>Reduce phishing harm through plain-language results, not jargon.</p>
                    </div>
                    <div className="pc-feature-card">
                      <div className="pc-feature-title">Privacy</div>
                      <p style={{ margin: 0 }}>No accounts, no ad tracking, no unnecessary data retention.</p>
                    </div>
                    <div className="pc-feature-card">
                      <div className="pc-feature-title">Accessibility</div>
                      <p style={{ margin: 0 }}>High-contrast UI, multilingual support, and simple-mode guidance.</p>
                    </div>
                  </div>
                </div>
              </div>
            </section>
          )}

          {showBlog && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
                <h2 className="pc-section-title">Blog</h2>
                <div className="pc-stack pc-gap-4">
                  <article className="pc-example-card">
                    <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.4em' }}>Guide</div>
                    <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.4em' }}>How to spot a fake bank link in 30 seconds</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.95em' }}>Look for mismatched domains, urgency tactics, and login forms on unfamiliar sites. When unsure, open the official app instead of tapping the link.</p>
                  </article>
                  <article className="pc-example-card">
                    <div style={{ fontSize: '0.75em', color: 'var(--text-tertiary)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.4em' }}>Education</div>
                    <h3 style={{ fontSize: '1.05em', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 0.4em' }}>Why QR code phishing is rising</h3>
                    <p style={{ color: 'var(--text-secondary)', fontSize: '0.95em' }}>QR codes hide the destination URL until after you scan. Treat unexpected QR stickers or messages with the same caution as any unknown link.</p>
                  </article>
                </div>
              </div>
            </section>
          )}

          {showFeatures && (
            <section className="pc-animate-in pc-section-enter" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)' }}>
              <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
                <h2 className="pc-section-title">Features</h2>
                <div className="pc-features-grid">
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="search" size={18} /></div>
                    <div className="pc-feature-title">Real-Time URL Scanner</div>
                    <div className="pc-feature-body">Checks URLs quickly and returns a plain-language risk result you can act on.</div>
                  </div>
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="bar-chart" size={18} /></div>
                    <div className="pc-feature-title">Preview & Analysis</div>
                    <div className="pc-feature-body">Domain age, SSL status, reputation, and one-line explanations for non-technical users.</div>
                  </div>
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="book-open" size={18} /></div>
                    <div className="pc-feature-title">Phishing Education</div>
                    <div className="pc-feature-body">Simple and detailed awareness content, with multilingual support.</div>
                  </div>
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="clock" size={18} /></div>
                    <div className="pc-feature-title">Scan History</div>
                    <div className="pc-feature-body">Review recent scans locally with clear risk labels, scores, and timestamps.</div>
                  </div>
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="image" size={18} /></div>
                    <div className="pc-feature-title">Screenscan & QR</div>
                    <div className="pc-feature-body">Upload a screenshot or QR image to extract and check links automatically.</div>
                  </div>
                  <div className="pc-feature-card">
                    <div className="pc-feature-icon"><Icon name="lock" size={18} /></div>
                    <div className="pc-feature-title">Privacy First</div>
                    <div className="pc-feature-body">No accounts, no tracking, and no personal data collection by design.</div>
                  </div>
                </div>
                <div className="pc-features-grid" style={{ marginTop: '1em' }}>
                  <div className="pc-feature-card" style={{ border: '1px dashed var(--border-hairline)' }}>
                    <div className="pc-feature-icon"><Icon name="sparkles" size={18} /></div>
                    <div className="pc-feature-title">Browser Extension</div>
                    <div className="pc-feature-body">In-browser checks without leaving the page. Manifest and popup are ready for Chrome, Firefox, and Edge.</div>
                  </div>
                  <div className="pc-feature-card" style={{ border: '1px dashed var(--border-hairline)' }}>
                    <div className="pc-feature-icon"><Icon name="code" size={18} /></div>
                    <div className="pc-feature-title">API Access</div>
                    <div className="pc-feature-body">Programmatic scanning for teams and integrations. Live endpoints at /api/v2 with JSON responses.</div>
                  </div>
                  <div className="pc-feature-card" style={{ border: '1px dashed var(--border-hairline)' }}>
                    <div className="pc-feature-icon"><Icon name="users" size={18} /></div>
                    <div className="pc-feature-title">Community Reports</div>
                    <div className="pc-feature-body">Community signals with moderation and transparency. Flag and review suspicious URLs from the dashboard.</div>
                  </div>
                </div>
              </div>
            </section>
          )}

          <section className="pc-animate-in" style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)', marginTop: '2em' }}>
            <div className="pc-section pc-max-width pc-gap-4" style={{ padding: '2em 1.5em' }}>
              <h2 className="pc-section-title">{t("howItWorks")}</h2>
              <div className="pc-how-it-works">
                <div className="pc-step">
                  <div className="pc-step-icon">01</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("stepPaste")}</div>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>{t("stepPasteBody")}</p>
                </div>
                <div className="pc-step">
                  <div className="pc-step-icon">02</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("stepAnalyze")}</div>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>{t("stepAnalyzeBody")}</p>
                </div>
                <div className="pc-step">
                  <div className="pc-step-icon">03</div>
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{t("stepDecide")}</div>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9em' }}>{t("stepDecideBody")}</p>
                </div>
              </div>
            </div>
          </section>
        </main>

        <footer style={{ borderTop: '1px solid var(--border-hairline)', background: 'var(--bg-surface)', marginTop: '2em' }}>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '1.5em', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5em', fontSize: '0.75em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
            <span>{t("brand")}</span>
            <span>{t("privacyBadge")}</span>
            <span>{status?.version ? `v${status.version}` : ''}</span>
          </div>
          <div style={{ maxWidth: '56em', margin: '0 auto', padding: '0 1.5em 1.5em', display: 'flex', gap: '1em', flexWrap: 'wrap', fontSize: '0.7em', letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-tertiary)' }}>
            <a href="/privacy" style={{ color: 'var(--brand-500)', textDecoration: 'none' }}>{t("privacy")}</a>
            <a href="/terms" style={{ color: 'var(--brand-500)', textDecoration: 'none' }}>{t("terms")}</a>
            <a href="/changelog" style={{ color: 'var(--brand-500)', textDecoration: 'none' }}>{t("changelog")}</a>
            <span>© {new Date().getFullYear()} {t("brand")}</span>
          </div>
        </footer>
      </div>
    </ThemeContext.Provider>
  );
}
