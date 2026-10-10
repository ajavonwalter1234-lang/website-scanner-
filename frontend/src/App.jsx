import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, ArrowDownToLine, ArrowRight, BadgeCheck, Check, CheckCircle2,
  ChevronRight, CircleAlert, Clock3, Copy, FileJson2, FileText, Globe2,
  LockKeyhole, LogOut, Play, Plus, RefreshCw, ScanSearch, Shield,
  ShieldCheck, ShieldEllipsis, Trash2, TriangleAlert, Wifi, X,
} from 'lucide-react';
import { api, getToken, setToken } from './api.js';

const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const statusLabel = { queued: 'Queued', running: 'Running', completed: 'Completed', failed: 'Failed' };

function shortDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}

function hostFromUrl(value) {
  try { return new URL(value).hostname; } catch { return ''; }
}

function StatusPill({ status }) {
  return <span className={`status-pill status-${status || 'queued'}`}><i />{statusLabel[status] || status || 'Unknown'}</span>;
}

function SeverityPill({ severity }) {
  return <span className={`severity-pill severity-${severity || 'info'}`}>{severity || 'info'}</span>;
}

function EmptyState({ icon: Icon = ShieldCheck, title, description }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={21} /></div><strong>{title}</strong><p>{description}</p></div>;
}

function App() {
  const [tokenDraft, setTokenDraft] = useState(getToken());
  const [connected, setConnected] = useState(Boolean(getToken()));
  const [showToken, setShowToken] = useState(false);
  const [connectionError, setConnectionError] = useState('');
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [url, setUrl] = useState('');
  const [pathScope, setPathScope] = useState('/');
  const [mode, setMode] = useState('basic');
  const [maxPages, setMaxPages] = useState(8);
  const [authorized, setAuthorized] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [filter, setFilter] = useState('all');
  const [domainInput, setDomainInput] = useState('');
  const [challenge, setChallenge] = useState(null);
  const [verifiedDomain, setVerifiedDomain] = useState('');
  const [ownershipBusy, setOwnershipBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const currentHost = hostFromUrl(url);
  const ownershipHost = (domainInput || currentHost).trim().toLowerCase();
  const activeCount = scans.filter((scan) => ['queued', 'running'].includes(scan.status)).length;
  const totalFindings = scans.reduce((sum, scan) => sum + Number(scan.summary?.finding_count || 0), 0);
  const findingsBySeverity = useMemo(() => {
    const counts = Object.fromEntries(severityOrder.map((level) => [level, 0]));
    for (const finding of findings) if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
    return counts;
  }, [findings]);
  const shownFindings = filter === 'all' ? findings : findings.filter((finding) => finding.severity === filter);

  const refresh = useCallback(async (selectId = null) => {
    const items = await api.listScans();
    setScans(items);
    const next = items.find((item) => item.id === (selectId || selectedScan?.id)) || items[0] || null;
    if (!next) {
      setSelectedScan(null);
      setFindings([]);
      return;
    }
    const detail = await api.getScan(next.id);
    setSelectedScan(detail);
    if (detail.status === 'completed' || detail.status === 'failed') {
      const results = await api.getFindings(detail.id);
      setFindings(results);
    } else {
      setFindings([]);
    }
  }, [selectedScan?.id]);

  const connectWithToken = async () => {
    const value = tokenDraft.trim();
    if (!value) {
      setConnectionError('Paste your API token to connect.');
      return;
    }
    setBusy(true);
    setConnectionError('');
    setToken(value);
    try {
      const items = await api.listScans();
      setScans(items);
      setConnected(true);
      setShowToken(false);
      const first = items[0] || null;
      if (first) {
        const detail = await api.getScan(first.id);
        setSelectedScan(detail);
        if (detail.status === 'completed' || detail.status === 'failed') setFindings(await api.getFindings(detail.id));
      } else {
        setSelectedScan(null);
        setFindings([]);
      }
      setNotice({ type: 'success', text: 'Connected securely. Scan records are private to this account.' });
    } catch (error) {
      setToken('');
      setConnected(false);
      setConnectionError(error.message);
    } finally {
      setBusy(false);
    }
  };

  const disconnect = () => {
    setToken('');
    setTokenDraft('');
    setConnected(false);
    setScans([]);
    setSelectedScan(null);
    setFindings([]);
    setChallenge(null);
    setVerifiedDomain('');
    setShowToken(true);
  };

  useEffect(() => {
    if (!connected) return undefined;
    let cancelled = false;
    const refreshQuietly = async () => {
      try {
        const items = await api.listScans();
        if (cancelled) return;
        setScans(items);
        const next = items.find((item) => item.id === selectedScan?.id) || items[0] || null;
        if (!next) {
          setSelectedScan(null);
          setFindings([]);
          return;
        }
        const detail = await api.getScan(next.id);
        if (cancelled) return;
        setSelectedScan(detail);
        if (detail.status === 'completed' || detail.status === 'failed') setFindings(await api.getFindings(detail.id));
        else setFindings([]);
      } catch (error) {
        if (!cancelled && error.message.includes('bearer')) {
          setConnectionError(error.message);
          setConnected(false);
        }
      }
    };
    refreshQuietly();
    const interval = window.setInterval(refreshQuietly, selectedScan && ['queued', 'running'].includes(selectedScan.status) ? 2500 : 12000);
    return () => { cancelled = true; window.clearInterval(interval); };
  }, [connected, selectedScan?.id, selectedScan?.status]);

  useEffect(() => {
    if (currentHost && !domainInput) setDomainInput(currentHost);
  }, [currentHost, domainInput]);

  useEffect(() => {
    if (!connected || !ownershipHost) return undefined;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const state = await api.ownershipStatus(ownershipHost);
        if (!cancelled) setVerifiedDomain(state.verified ? state.hostname : '');
      } catch {
        if (!cancelled) setVerifiedDomain('');
      }
    }, 350);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [connected, ownershipHost]);

  const handleCreateScan = async (event) => {
    event.preventDefault();
    setNotice(null);
    if (!connected) {
      setNotice({ type: 'error', text: 'Connect an API token before starting a scan.' });
      setShowToken(true);
      return;
    }
    if (!authorized) {
      setNotice({ type: 'error', text: 'Confirm authorization before starting a scan.' });
      return;
    }
    setSubmitting(true);
    try {
      const created = await api.createScan({
        url: url.trim(),
        path_scope: pathScope.trim() || '/',
        mode,
        max_pages: Number(maxPages),
        authorized,
      });
      setSelectedScan(created);
      setFindings([]);
      await refresh(created.id);
      setNotice({ type: 'success', text: 'Scan queued. It will run in an isolated worker using safe, unauthenticated checks.' });
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
      if (error.message.toLowerCase().includes('verify ownership')) {
        setNotice({ type: 'warning', text: `${error.message}. Add a DNS TXT record from the ownership panel.` });
      }
    } finally {
      setSubmitting(false);
    }
  };

  const createChallenge = async () => {
    if (!connected) { setNotice({ type: 'error', text: 'Connect an API token before verifying a domain.' }); return; }
    if (!ownershipHost) { setNotice({ type: 'error', text: 'Enter a public hostname first.' }); return; }
    setOwnershipBusy(true);
    setNotice(null);
    try {
      const result = await api.createChallenge(ownershipHost);
      setChallenge(result);
      setVerifiedDomain('');
      setNotice({ type: 'success', text: 'DNS challenge created. Add the TXT record exactly as shown below.' });
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    } finally {
      setOwnershipBusy(false);
    }
  };

  const verifyDomain = async () => {
    if (!challenge) return;
    setOwnershipBusy(true);
    setNotice(null);
    try {
      const result = await api.verifyOwnership(challenge.hostname);
      if (result.verified) {
        setVerifiedDomain(result.hostname);
        setChallenge(null);
        setNotice({ type: 'success', text: `Ownership verified for ${result.hostname}. Deep scans are now available for this account.` });
      }
    } catch (error) {
      setNotice({ type: 'warning', text: error.message });
    } finally {
      setOwnershipBusy(false);
    }
  };

  const copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setNotice({ type: 'warning', text: 'Clipboard access was unavailable. Select and copy the record manually.' });
    }
  };

  const chooseScan = async (scan) => {
    setSelectedScan(scan);
    setNotice(null);
    try {
      const detail = await api.getScan(scan.id);
      setSelectedScan(detail);
      setFindings(detail.status === 'completed' || detail.status === 'failed' ? await api.getFindings(detail.id) : []);
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    }
  };

  const deleteScan = async (scan) => {
    if (!window.confirm(`Delete scan ${scan.id.slice(0, 8)} and all associated findings? This cannot be undone.`)) return;
    try {
      await api.deleteScan(scan.id);
      const next = scans.filter((item) => item.id !== scan.id);
      setScans(next);
      if (selectedScan?.id === scan.id) {
        setSelectedScan(null);
        setFindings([]);
      }
      setNotice({ type: 'success', text: 'Scan and related findings deleted.' });
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    }
  };

  const downloadReport = async (format) => {
    if (!selectedScan) return;
    try {
      const blob = await api.downloadReport(selectedScan.id, format);
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = `safe-scan-${selectedScan.id.slice(0, 8)}.${format}`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
    } catch (error) {
      setNotice({ type: 'error', text: error.message });
    }
  };

  const statusText = connected ? 'Workspace connected' : 'Authentication required';

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={21} strokeWidth={2.2} /></div>
          <div><div className="brand-name">sentinel<span>.</span></div><div className="brand-caption">WEBSITE SECURITY</div></div>
        </div>
        <div className="side-divider" />
        <div className="nav-label">WORKSPACE</div>
        <button className="nav-item active"><ScanSearch size={17} /><span>Scan overview</span><span className="nav-dot" /></button>
        <button className="nav-item" onClick={() => document.getElementById('history')?.scrollIntoView({ behavior: 'smooth' })}><Activity size={17} /><span>Scan history</span></button>
        <div className="side-spacer" />
        <div className="sidebar-safety">
          <div className="safety-icon"><LockKeyhole size={16} /></div>
          <strong>Safe by design</strong>
          <p>Passive checks only. No exploit attempts, credentials or data changes.</p>
          <div className="safety-rule"><Check size={13} /> Host-scoped</div>
          <div className="safety-rule"><Check size={13} /> Rate-limited</div>
          <div className="safety-rule"><Check size={13} /> Secret-redacted</div>
        </div>
        <div className="sidebar-foot"><span className={`connection-dot ${connected ? 'online' : ''}`} />{statusText}<span className="build-label">v1.0</span></div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="mobile-brand"><div className="brand-mark"><ShieldCheck size={19} /></div><span>sentinel<span>.</span></span></div>
          <div className="breadcrumbs"><span>Workspace</span><ChevronRight size={14} /><strong>Scan overview</strong></div>
          <div className="top-actions">
            <span className={`connection-label ${connected ? 'connected' : ''}`}><i />{connected ? 'Connected' : 'Not connected'}</span>
            {connected ? <button className="ghost-button" onClick={disconnect} title="Disconnect API token"><LogOut size={15} /><span>Disconnect</span></button> : <button className="primary-small" onClick={() => setShowToken((value) => !value)}><LockKeyhole size={14} /> Connect token</button>}
          </div>
        </header>

        {(showToken || !connected) && <section className="token-banner">
          <div className="token-banner-icon"><LockKeyhole size={20} /></div>
          <div className="token-copy"><strong>Connect to your private workspace</strong><p>Use the bearer token configured by your administrator. For local Docker development, see the README for the development-only token.</p>
            <div className="token-entry"><input type="password" autoComplete="off" placeholder="Paste API token" value={tokenDraft} onChange={(event) => setTokenDraft(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && connectWithToken()} /><button className="primary-button" onClick={connectWithToken} disabled={busy}>{busy ? <RefreshCw className="spin" size={15} /> : <Wifi size={15} />}{busy ? 'Connecting' : 'Connect'}</button></div>
            {connectionError && <div className="inline-error"><CircleAlert size={14} />{connectionError}</div>}
          </div>
          {connected && <button className="icon-button close-token" onClick={() => setShowToken(false)} aria-label="Close"><X size={17} /></button>}
        </section>}

        <section className="page-heading">
          <div><div className="eyebrow"><span className="eyebrow-line" />DEFENSIVE SECURITY TOOLING</div><h1>Scan overview</h1><p>Review public-facing security signals on websites you’re authorized to assess.</p></div>
          <div className="heading-meta"><div className="scan-engine"><span className="engine-pulse" /><span><b>Passive engine</b><small>Safe checks enabled</small></span></div><div className="heading-separator" /><div className="meta-chip"><Shield size={14} /> No active exploitation</div></div>
        </section>

        {notice && <div className={`notice notice-${notice.type}`} role="status"><span className="notice-icon">{notice.type === 'success' ? <CheckCircle2 size={17} /> : notice.type === 'warning' ? <TriangleAlert size={17} /> : <CircleAlert size={17} />}</span><span>{notice.text}</span><button onClick={() => setNotice(null)} aria-label="Dismiss"><X size={15} /></button></div>}

        <section className="metric-grid">
          <div className="metric-card"><div className="metric-top"><span>Total scans</span><span className="metric-icon indigo"><ScanSearch size={16} /></span></div><strong>{scans.length}</strong><small>In your private workspace</small></div>
          <div className="metric-card"><div className="metric-top"><span>In progress</span><span className="metric-icon amber"><Activity size={16} /></span></div><strong>{activeCount}</strong><small>Queued or currently running</small></div>
          <div className="metric-card"><div className="metric-top"><span>Findings stored</span><span className="metric-icon blue"><ShieldEllipsis size={17} /></span></div><strong>{totalFindings}</strong><small>Across completed scans</small></div>
          <div className="metric-card"><div className="metric-top"><span>Ownership checks</span><span className="metric-icon green"><BadgeCheck size={16} /></span></div><strong>{verifiedDomain ? '1' : '—'}</strong><small>{verifiedDomain ? `${verifiedDomain} verified` : 'Optional for basic scans'}</small></div>
        </section>

        <div className="work-grid">
          <section className="card scan-card">
            <div className="card-heading"><div className="section-icon"><Plus size={17} /></div><div><h2>Start a new scan</h2><p>Only scan a website you have permission to assess.</p></div><span className="card-step">01</span></div>
            <form onSubmit={handleCreateScan}>
              <label className="field-label" htmlFor="target-url">Website URL <span className="required">*</span></label>
              <div className="url-input-wrap"><Globe2 size={17} /><input id="target-url" type="url" placeholder="https://your-authorized-site.com" value={url} onChange={(event) => { const nextUrl = event.target.value; const previousHost = hostFromUrl(url); const nextHost = hostFromUrl(nextUrl); setUrl(nextUrl); if (!domainInput || domainInput === previousHost) setDomainInput(nextHost); }} required maxLength={2048} autoComplete="url" /><span className="url-scheme-note">HTTP(S) only</span></div>
              <div className="field-hint"><LockKeyhole size={13} /> No credentials, query strings, or fragments. Public hosts only.</div>
              <div className="field-row">
                <div className="field field-scope"><label className="field-label" htmlFor="path-scope">Path scope</label><input id="path-scope" type="text" value={pathScope} onChange={(event) => setPathScope(event.target.value)} placeholder="/" maxLength={2048} /><div className="field-hint">Only this path prefix and its child paths</div></div>
                <div className="field field-pages"><label className="field-label" htmlFor="page-limit">Page limit</label><div className="number-input"><button type="button" aria-label="Decrease page limit" onClick={() => setMaxPages((value) => Math.max(1, value - 1))}>−</button><input id="page-limit" type="number" min="1" max={mode === 'basic' ? 10 : 30} value={maxPages} onChange={(event) => setMaxPages(Number(event.target.value))} /><button type="button" aria-label="Increase page limit" onClick={() => setMaxPages((value) => Math.min(mode === 'basic' ? 10 : 30, value + 1))}>+</button></div><div className="field-hint">Up to {mode === 'basic' ? '10' : '30'} pages</div></div>
              </div>

              <div className="mode-label-row"><label className="field-label">Scan depth</label><span className="mode-note">Deeper scans require DNS ownership verification</span></div>
              <div className="mode-options">
                <button type="button" className={`mode-option ${mode === 'basic' ? 'selected' : ''}`} onClick={() => { setMode('basic'); setMaxPages((value) => Math.min(value, 10)); }}>
                  <span className="mode-radio" /> <span className="mode-copy"><b>Basic</b><small>Public entry point + shallow crawl</small></span><span className="mode-limit">10 pages</span>
                </button>
                <button type="button" className={`mode-option ${mode === 'deep' ? 'selected' : ''}`} onClick={() => { setMode('deep'); setMaxPages((value) => Math.min(30, Math.max(12, value))); }}>
                  <span className="mode-radio" /> <span className="mode-copy"><b>Deep</b><small>Wider in-scope crawl, owner verified</small></span><span className="mode-limit">30 pages</span>
                </button>
              </div>

              <label className={`authorization-check ${authorized ? 'checked' : ''}`}>
                <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} />
                <span className="custom-check">{authorized && <Check size={13} />}</span>
                <span><b>I confirm I’m authorized to scan this website.</b><small>Only safe public GET requests are used. No login, exploitation, uploads or data changes.</small></span>
              </label>
              <button className="start-button" type="submit" disabled={submitting || !connected || !authorized}>
                {submitting ? <RefreshCw className="spin" size={16} /> : <Play size={15} fill="currentColor" />}{submitting ? 'Queueing scan…' : 'Queue safe scan'}<ArrowRight size={16} />
              </button>
              {!connected && <div className="form-footnote"><LockKeyhole size={13} /> Connect an API token to queue scans.</div>}
            </form>
          </section>

          <div className="right-column">
            <section className="card ownership-card">
              <div className="card-heading compact"><div className="section-icon green-bg"><BadgeCheck size={17} /></div><div><h2>Domain ownership</h2><p>Required for deep scans and hosted deployments.</p></div></div>
              <label className="field-label" htmlFor="ownership-host">Public hostname</label>
              <div className="ownership-input"><Globe2 size={15} /><input id="ownership-host" value={domainInput || currentHost} onChange={(event) => { setDomainInput(event.target.value); setChallenge(null); setVerifiedDomain(''); }} placeholder="example.com" /></div>
              {verifiedDomain && verifiedDomain === ownershipHost ? <div className="verification-success"><CheckCircle2 size={15} /><span><b>Verified</b><small>Valid for 180 days · {verifiedDomain}</small></span></div> : challenge ? <div className="challenge-box">
                <div className="challenge-top"><span><Clock3 size={13} /> Expires {shortDate(challenge.expires_at)}</span><span>TXT record</span></div>
                <div className="challenge-value"><small>HOST / NAME</small><div className="copy-line"><code>{challenge.txt_name}</code><button className="icon-button" onClick={() => copyText(challenge.txt_name)} title="Copy record name"><Copy size={14} /></button></div></div>
                <div className="challenge-value"><small>VALUE</small><div className="copy-line"><code>{challenge.txt_value}</code><button className="icon-button" onClick={() => copyText(challenge.txt_value)} title="Copy record value"><Copy size={14} /></button></div></div>
                <button className="verify-button" onClick={verifyDomain} disabled={ownershipBusy}>{ownershipBusy ? <RefreshCw className="spin" size={14} /> : <BadgeCheck size={15} />}{ownershipBusy ? 'Checking DNS…' : 'Verify TXT record'}</button>
                {copied && <small className="copied-label">Copied to clipboard</small>}
              </div> : <>
                <p className="ownership-note">Prove control by publishing a temporary TXT record. The challenge expires in 30 minutes; verification lasts 180 days.</p>
                <button className="outline-button full-width" onClick={createChallenge} disabled={ownershipBusy || !connected}>{ownershipBusy ? <RefreshCw className="spin" size={14} /> : <Plus size={15} />}Create DNS challenge</button>
              </>}
              <div className="ownership-foot"><LockKeyhole size={13} /> TXT values are stored as a hash and never appear in scan reports.</div>
            </section>

            <section className="safety-card">
              <div className="safety-card-head"><div className="safe-shield"><ShieldCheck size={18} /></div><div><strong>Safety envelope</strong><span>Enforced server-side on every request</span></div><span className="safe-tag">ACTIVE</span></div>
              <div className="safety-list"><div><CheckCircle2 size={14} /><span>HTTP(S) only · public IPs only</span></div><div><CheckCircle2 size={14} /><span>Exact host + path scope · redirects revalidated</span></div><div><CheckCircle2 size={14} /><span>GET-only · 0.75s pacing · bounded responses</span></div><div><CheckCircle2 size={14} /><span>Isolated worker · controlled egress proxy</span></div></div>
              <div className="safety-footer"><TriangleAlert size={13} /> Results are signals, not a guarantee of security.</div>
            </section>
          </div>
        </div>

        <section className="card history-card" id="history">
          <div className="history-header"><div className="card-heading compact"><div className="section-icon"><Activity size={17} /></div><div><h2>Recent scans</h2><p>Your latest authorized assessments</p></div></div><button className="icon-button refresh-button" onClick={() => refresh()} title="Refresh history"><RefreshCw size={15} /></button></div>
          {scans.length ? <div className="table-wrap"><table><thead><tr><th>Target</th><th>Scope</th><th>Created</th><th>Status</th><th>Findings</th><th aria-label="Actions" /></tr></thead><tbody>
            {scans.map((scan) => <tr key={scan.id} className={selectedScan?.id === scan.id ? 'row-selected' : ''} onClick={() => chooseScan(scan)}>
              <td><div className="target-cell"><span className="target-icon"><Globe2 size={15} /></span><span><b>{scan.hostname}</b><small>{scan.mode} · {scan.id.slice(0, 8)}</small></span></div></td>
              <td><code className="scope-code">{scan.path_scope}</code></td><td>{shortDate(scan.created_at)}</td><td><StatusPill status={scan.status} /></td><td><span className="finding-count">{Number(scan.summary?.finding_count || 0)}</span></td>
              <td><button className="icon-button delete-button" title="Delete scan" onClick={(event) => { event.stopPropagation(); deleteScan(scan); }}><Trash2 size={15} /></button></td>
            </tr>)}
          </tbody></table></div> : <EmptyState icon={ScanSearch} title="No scans yet" description="Queue your first authorized scan. The worker will only check public, in-scope pages." />}
        </section>

        {selectedScan && <section className="card results-card">
          <div className="results-header">
            <div className="results-title"><div className={`result-symbol ${selectedScan.status}`}>
              {selectedScan.status === 'completed' ? <ShieldCheck size={20} /> : selectedScan.status === 'failed' ? <CircleAlert size={20} /> : <Activity className={selectedScan.status === 'running' ? 'pulse' : ''} size={19} />}
            </div><div><div className="result-eyebrow">SCAN DETAIL · {selectedScan.id.slice(0, 8)}</div><h2>{selectedScan.hostname}</h2><p>{selectedScan.target_url} <span>·</span> Scope {selectedScan.path_scope}</p></div></div>
            <div className="results-actions"><StatusPill status={selectedScan.status} />{selectedScan.status === 'completed' && <><button className="outline-button" onClick={() => downloadReport('html')}><FileText size={14} />HTML</button><button className="outline-button" onClick={() => downloadReport('json')}><FileJson2 size={14} />JSON</button></>}</div>
          </div>
          {['queued', 'running'].includes(selectedScan.status) ? <div className="progress-panel"><div className="progress-copy"><span>{selectedScan.progress_message || 'Waiting for an isolated worker'}</span><b>{selectedScan.progress}%</b></div><div className="progress-track"><span style={{ width: `${Math.max(2, selectedScan.progress)}%` }} /></div><div className="progress-foot"><span><Clock3 size={13} /> Started {shortDate(selectedScan.started_at || selectedScan.created_at)}</span><span>Bounded · unauthenticated · passive</span></div></div> : selectedScan.status === 'failed' ? <div className="failed-panel"><TriangleAlert size={17} /><div><b>Scan could not be completed</b><p>{selectedScan.warnings?.join(' ') || 'The target could not be reached safely. Check the URL and try again.'}</p></div></div> : <>
            <div className="result-summary">
              <div className="summary-total"><span>OBSERVATIONS</span><b>{findings.length}</b><small>Potential and confirmed signals</small></div>
              {severityOrder.map((level) => <div className={`summary-severity ${level}`} key={level}><span>{level}</span><b>{findingsBySeverity[level]}</b></div>)}
            </div>
            {selectedScan.warnings?.length > 0 && <div className="warning-list"><div className="warning-title"><TriangleAlert size={15} /> Coverage notes</div>{selectedScan.warnings.map((warning, index) => <div className="warning-item" key={`${index}-${warning}`}><span />{warning}</div>)}</div>}
            <div className="findings-heading"><div><h3>Findings</h3><p>Evidence is non-sensitive; review potential observations manually.</p></div><div className="filter-wrap"><label htmlFor="finding-filter">Severity</label><select id="finding-filter" value={filter} onChange={(event) => setFilter(event.target.value)}><option value="all">All severities</option>{severityOrder.map((level) => <option key={level} value={level}>{level[0].toUpperCase() + level.slice(1)}</option>)}</select></div></div>
            {shownFindings.length ? <div className="finding-list">{shownFindings.map((finding) => <article className="finding-item" key={finding.id}>
              <div className="finding-accent"><SeverityPill severity={finding.severity} /></div><div className="finding-main"><div className="finding-title-row"><h4>{finding.title}</h4><span className={`finding-kind kind-${finding.status}`}>{finding.status === 'confirmed' ? <CheckCircle2 size={12} /> : <TriangleAlert size={12} />}{finding.status}</span></div>
                <div className="finding-url"><Globe2 size={12} />{finding.affected_url}</div>
                <div className="finding-meta"><span>{finding.confidence}% confidence</span><span>Observed {shortDate(finding.observed_at)}</span></div>
                <details><summary>Details and remediation <ChevronRight size={14} /></summary><div className="finding-details"><div><b>Evidence</b><p>{finding.evidence}</p></div><div><b>Possible impact</b><p>{finding.impact}</p></div><div><b>Remediation</b><p>{finding.remediation}</p></div></div></details>
              </div>
            </article>)}</div> : <EmptyState icon={ShieldCheck} title={filter === 'all' ? 'No reportable findings observed' : `No ${filter} findings`} description="This is not proof that the website is vulnerability-free. Review coverage notes and manually verify areas that matter to your deployment." />}
            <div className="tested-area"><div className="tested-heading"><CheckCircle2 size={15} /><b>Checks performed</b></div><div className="tested-chips">{(selectedScan.tested_areas || []).map((area) => <span key={area}>{area}</span>)}</div></div>
          </>}
        </section>}

        <footer className="page-footer"><span>Sentinel · Safe Website Scanner</span><span>OWASP Top 10:2025 used as a risk reference · Passive checks only</span><a href="https://owasp.org/Top10/2025/" target="_blank" rel="noreferrer">Risk reference <ArrowRight size={12} /></a></footer>
      </main>
    </div>
  );
}

export default App;
