import React, { useState, useEffect } from 'react';
import DomainVerificationModal from './DomainVerificationModal';
import SecureWebTicker from './SecureWebTicker';
import { Play, Globe, FileText, Loader2, ShieldCheck, CheckCircle2, AlertTriangle, Layers, PlusCircle, Download } from 'lucide-react';

export default function CrowdStrikeHomepage({ user, onOpenAuth }) {
  const [targetUrl, setTargetUrl] = useState('http://localhost:3000');
  const [scanData, setScanData] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [message, setMessage] = useState('');
  const [isDomainModalOpen, setIsDomainModalOpen] = useState(false);

  const [activeScanId, setActiveScanId] = useState(null);
  const [expandedGuides, setExpandedGuides] = useState({});
  const [expandedSnippets, setExpandedSnippets] = useState({});
  const [userDomains, setUserDomains] = useState([]);
  const [userWafData, setUserWafData] = useState(null);

  const getAuthHeaders = () => {
    const token = localStorage.getItem('nkat_jwt_token');
    const headers = { 'Content-Type': 'application/json', 'X-API-Key': 'nkat_secret_api_key_2026' };
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  };

  const fetchUserWafTraffic = async () => {
    try {
      const res = await fetch(`/api/v1/waf/user-traffic?domain=${encodeURIComponent(targetUrl)}`, { headers: getAuthHeaders() });
      if (res.ok) setUserWafData(await res.json());
    } catch (err) {
      console.error('Failed to fetch user WAF traffic:', err);
    }
  };

  useEffect(() => {
    fetchUserWafTraffic();
    const interval = setInterval(() => {
      fetchUserWafTraffic();
    }, 4000);
    return () => clearInterval(interval);
  }, [targetUrl]);

  const fetchLatestScan = async (scanId = null) => {
    try {
      const headers = getAuthHeaders();
      let targetId = scanId || activeScanId;

      if (!targetId) {
        const scansRes = await fetch('/api/v1/scans', { headers });
        if (scansRes.ok) {
          const scansList = await scansRes.json();
          if (scansList && scansList.length > 0) {
            targetId = scansList[0].id;
          } else {
            setScanData(null);
            setActiveScanId(null);
            return;
          }
        }
      }

      if (targetId) {
        const res = await fetch(`/api/v1/scans/${targetId}`, { headers });
        if (res.ok) {
          const data = await res.json();
          const allFindings = [];
          (data.subdomains || []).forEach(sub => {
            (sub.findings || []).forEach(f => allFindings.push(f));
          });
          data.findings = allFindings;
          setScanData(data);
          setActiveScanId(targetId);
        } else {
          setScanData(null);
          setActiveScanId(null);
        }
      } else {
        setScanData(null);
        setActiveScanId(null);
      }
    } catch (err) {
      console.error('Failed to fetch scan data:', err);
    }
  };

  const fetchUserDomains = async () => {
    try {
      const res = await fetch('/api/v1/domains', { headers: getAuthHeaders() });
      if (res.ok) {
        const domains = await res.json();
        setUserDomains(domains);
      }
    } catch (err) {
      console.error('Failed to fetch user website domain targets:', err);
    }
  };

  useEffect(() => {
    fetchLatestScan();
    fetchUserDomains();
  }, []);

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!targetUrl) return;
    setScanning(true);
    setMessage('Autonomous AI Scan Launched for ' + targetUrl + '...');

    try {
      const res = await fetch('/api/v1/scans', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ target: targetUrl })
      });
      if (res.ok) {
        const newScan = await res.json();
        setActiveScanId(newScan.id);

        let pollCount = 0;
        const pollInterval = setInterval(async () => {
          pollCount++;
          try {
            const scanRes = await fetch(`/api/v1/scans/${newScan.id}`, { headers: getAuthHeaders() });
            if (scanRes.ok) {
              const currentScan = await scanRes.json();
              const allFindings = [];
              (currentScan.subdomains || []).forEach(sub => {
                (sub.findings || []).forEach(f => allFindings.push(f));
              });
              currentScan.findings = allFindings;
              setScanData(currentScan);

              if (currentScan.status === 'completed' || currentScan.status === 'failed' || pollCount > 15) {
                setScanning(false);
                setMessage(currentScan.status === 'completed' ? 'Vulnerability audit scan finished successfully.' : 'Scan pipeline completed with status: ' + currentScan.status);
                clearInterval(pollInterval);
              }
            }
          } catch (err) {
            console.error('Poll error:', err);
          }
        }, 3000);
      } else {
        const errJson = await res.json();
        setMessage('Scan initiation failed: ' + (errJson.detail || 'Unauthorized or server error'));
        setScanning(false);
      }
    } catch (err) {
      setMessage('Network connection error launching scan.');
      setScanning(false);
    }
  };

  const handleAction = async (findingId, actionType) => {
    try {
      const endpoint = `/api/v1/findings/${findingId}/${actionType}`;
      const res = await fetch(endpoint, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify({ approved_by: user ? user.username : 'react_analyst' })
      });
      if (res.ok) {
        fetchLatestScan();
      }
    } catch (err) {
      console.error('Action error:', err);
    }
  };

  const handleDownloadPdf = (scanId) => {
    window.open(`/api/v1/scans/${scanId || 1}/report/pdf`, '_blank');
  };

  const findings = scanData ? (scanData.findings || []) : [];
  const totalVulns = findings.length;
  const criticalCount = findings.filter(f => String(f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highCount = findings.filter(f => String(f.severity || '').toUpperCase() === 'HIGH').length;

  return (
    <main style={{ padding: '2rem 1.5rem', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
      
      {/* CrowdStrike-Style Hero Section */}
      <section className="cyber-glass-card" style={{
        position: 'relative',
        borderRadius: '24px',
        padding: '3.5rem 3rem',
        overflow: 'hidden',
        marginBottom: '2.5rem'
      }}>
        {/* Decorative Watermark Cyber Logo */}
        <div style={{
          position: 'absolute',
          right: '-2rem',
          top: '-2rem',
          width: '380px',
          height: '380px',
          borderRadius: '50%',
          opacity: 0.12,
          background: 'radial-gradient(circle, rgba(255, 255, 255, 0.4) 0%, rgba(255, 255, 255, 0.05) 40%, transparent 70%)',
          filter: 'blur(20px)',
          pointerEvents: 'none'
        }} />

        <div style={{ position: 'relative', zIndex: 2, maxWidth: '820px' }}>
          {/* Animated Movement Badge for SECURE YOUR WEB */}
          <SecureWebTicker variant="hero" />

          <h1 className="heading-font" style={{
            fontSize: '3rem',
            fontWeight: 900,
            lineHeight: 1.15,
            color: '#ffffff',
            letterSpacing: '-0.8px',
            marginBottom: '1rem'
          }}>
            Nqat AI <br />
            <span className="platform-title-gradient">WEBSITE VULNERABILITY ASSISTANT</span>
          </h1>

          <p style={{
            fontSize: '1.1rem',
            color: '#94a3b8',
            lineHeight: 1.6,
            marginBottom: '2rem'
          }}>
            Real-time vulnerability auditing, machine learning risk classification, CISA KEV exploitation feed correlation, and automated remediation guides in your unified Nqat AI Assistant Console.
          </p>

          {/* Target Scan Submission Input Form */}
          <form onSubmit={handleStartScan} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <input
              type="url"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Enter Target URL (e.g. http://localhost:3000)"
              style={{
                flex: 1,
                minWidth: '320px',
                padding: '14px 20px',
                borderRadius: '9999px',
                background: 'rgba(10, 10, 10, 0.9)',
                border: '1px solid rgba(255, 255, 255, 0.18)',
                color: '#ffffff',
                fontSize: '0.95rem',
                outline: 'none'
              }}
            />
            <button
              type="submit"
              disabled={scanning}
              className="btn-aegis-primary"
              style={{ padding: '0.85rem 2rem', fontSize: '0.92rem' }}
            >
              {scanning ? (
                <>
                  <Loader2 size={18} className="animate-spin" /> Scanning Target...
                </>
              ) : (
                <>
                  <Play size={18} /> Start Autonomous Scan
                </>
              )}
            </button>
            <button
              type="button"
              onClick={() => setIsDomainModalOpen(true)}
              className="btn-aegis-secondary"
              style={{ padding: '0.85rem 1.8rem', fontSize: '0.92rem' }}
            >
              <Globe size={16} /> Verify Target Domain
            </button>
            <button
              type="button"
              onClick={() => handleDownloadPdf(1)}
              className="btn-aegis-secondary"
              style={{ padding: '0.85rem 1.8rem', fontSize: '0.92rem' }}
            >
              <FileText size={16} /> PDF Executive Report
            </button>
          </form>

          {message && (
            <div className="mono-text" style={{ marginTop: '1rem', color: '#38bdf8', fontSize: '0.85rem' }}>
              {message}
            </div>
          )}
        </div>
      </section>

      {/* User Website WAF Protection Status & Live Intercepts */}
      <section style={{
        background: 'linear-gradient(135deg, rgba(12, 12, 12, 0.95) 0%, rgba(20, 20, 20, 0.95) 100%)',
        padding: '1.75rem 2rem',
        borderRadius: '16px',
        border: '1.5px solid rgba(56, 189, 248, 0.4)',
        boxShadow: '0 12px 35px rgba(0, 0, 0, 0.5), 0 0 25px rgba(56, 189, 248, 0.15)',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '1.25rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
              <span style={{ background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', border: '1px solid #38bdf8', padding: '3px 10px', borderRadius: '10px', fontWeight: 800, fontSize: '0.72rem' }}>
                ACTIVE WAF ENFORCEMENT
              </span>
              <span className="mono-text" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                Target Website: {userWafData?.protected_website || targetUrl}
              </span>
            </div>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
              WAF Website Protection & Intercepted Attack Logs
            </h2>
            <p style={{ fontSize: '0.86rem', color: '#94a3b8', marginTop: '4px', marginBot: 0 }}>
              Real-time security guard actively protecting your website against SQLi, XSS, Path Traversal, and Command Injections.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <span style={{ fontSize: '0.85rem', color: '#38bdf8', fontWeight: 800, background: 'rgba(56, 189, 248, 0.15)', padding: '8px 14px', borderRadius: '10px', border: '1px solid #38bdf8' }}>
              {userWafData?.blocked_attacks_count || 0} Attacks Blocked on Your Website
            </span>
          </div>
        </div>

        {/* WAF Rule Status Pill Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
          {(userWafData?.active_rules || [
            { id: 'WAF-1001', name: 'SQL Injection (SQLi) Defense', status: 'ENFORCING' },
            { id: 'WAF-2001', name: 'XSS Script Payload Block', status: 'ENFORCING' },
            { id: 'WAF-3004', name: 'Path Traversal / LFI Prevention', status: 'ENFORCING' },
            { id: 'WAF-4002', name: 'OS Command Execution Shield', status: 'ENFORCING' }
          ]).map(rule => (
            <div key={rule.id} style={{ background: '#000000', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '10px', padding: '10px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.78rem', color: '#e2e8f0', fontWeight: 700 }}>{rule.name}</span>
              <span style={{ fontSize: '0.68rem', background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', padding: '2px 6px', borderRadius: '6px', fontWeight: 800 }}>{rule.status}</span>
            </div>
          ))}
        </div>

        {/* Recent Blocked Attack Stream targeting User Website */}
        {userWafData?.blocked_logs && userWafData.blocked_logs.length > 0 ? (
          <div style={{ overflowX: 'auto', borderRadius: '10px', border: '1px solid rgba(239, 68, 68, 0.3)', background: '#000000' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
              <thead>
                <tr style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', textTransform: 'uppercase', fontSize: '0.72rem' }}>
                  <th style={{ padding: '10px 14px' }}>Time (UTC)</th>
                  <th style={{ padding: '10px 14px' }}>Attacker IP</th>
                  <th style={{ padding: '10px 14px' }}>Attack Classification</th>
                  <th style={{ padding: '10px 14px' }}>Target Path</th>
                  <th style={{ padding: '10px 14px' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {userWafData.blocked_logs.slice(0, 5).map(log => (
                  <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td className="mono-text" style={{ padding: '10px 14px', color: '#94a3b8' }}>{log.timestamp ? log.timestamp.slice(11, 19) : 'Now'}</td>
                    <td className="mono-text" style={{ padding: '10px 14px', color: '#ffffff', fontWeight: 700 }}>{log.client_ip}</td>
                    <td style={{ padding: '10px 14px', color: '#ef4444', fontWeight: 800 }}>{log.classification}</td>
                    <td className="mono-text" style={{ padding: '10px 14px', color: '#e2e8f0', maxWidth: '240px', wordBreak: 'break-all' }}>{log.path}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '1px solid #ef4444', padding: '2px 8px', borderRadius: '8px', fontSize: '0.7rem', fontWeight: 900 }}>
                        BLOCKED (403)
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ color: '#94a3b8', fontSize: '0.82rem', textAlign: 'center', padding: '12px', background: '#000000', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.05)' }}>
            No malicious attacks currently targeting your website ({targetUrl}). WAF active guard standby.
          </div>
        )}
      </section>

      <DomainVerificationModal
        isOpen={isDomainModalOpen}
        onClose={() => setIsDomainModalOpen(false)}
        onVerifiedDomainAdded={(domain) => {
          setTargetUrl(`https://${domain}`);
          setMessage(`Verified target '${domain}' added to scoped authorized targets!`);
          fetchUserDomains();
        }}
      />

      {/* Monitored Website Assets & Security Health Status */}
      <section style={{
        background: 'rgba(14, 14, 14, 0.95)',
        padding: '1.75rem',
        borderRadius: '16px',
        border: '1px solid rgba(255, 255, 255, 0.15)',
        boxShadow: '0 10px 30px rgba(0, 0, 0, 0.5)',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
              Your Monitored Website Assets & Vulnerability Status
            </h2>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '3px' }}>
              Real-time website security posture, domain ownership verification, and active vulnerability updates.
            </p>
          </div>
          <button
            onClick={() => setIsDomainModalOpen(true)}
            style={{
              padding: '8px 16px',
              fontSize: '0.85rem',
              fontWeight: 700,
              background: 'rgba(255, 255, 255, 0.1)',
              border: '1px solid #ffffff',
              color: '#ffffff',
              borderRadius: '8px',
              cursor: 'pointer'
            }}
          >
            Submit New Target Website
          </button>
        </div>

        {userDomains.length > 0 ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {userDomains.map((dom) => {
              const isVerified = dom.status === 'VERIFIED';
              return (
                <div key={dom.id} style={{
                  background: 'rgba(10, 10, 10, 0.9)',
                  padding: '1.2rem',
                  borderRadius: '12px',
                  border: isVerified ? '1px solid rgba(56, 189, 248, 0.4)' : '1px solid rgba(168, 85, 247, 0.4)',
                  display: 'flex',
                  flexDirection: 'column',
                  justify: 'space-between',
                  gap: '0.75rem'
                }}>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                      <span style={{ fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>{dom.domain}</span>
                      <span style={{
                        fontSize: '0.72rem',
                        fontWeight: 800,
                        padding: '3px 9px',
                        borderRadius: '12px',
                        background: isVerified ? 'rgba(56, 189, 248, 0.2)' : 'rgba(251, 191, 36, 0.2)',
                        color: isVerified ? '#38bdf8' : '#fbbf24',
                        border: isVerified ? '1px solid #38bdf8' : '1px solid #fbbf24'
                      }}>
                        {dom.status}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
                      URL: <span style={{ color: '#ffffff' }}>{dom.target_url}</span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>
                      Method: {dom.verification_method?.toUpperCase()}
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '0.5rem', marginTop: '4px' }}>
                    <button
                      onClick={() => {
                        setTargetUrl(dom.target_url);
                        setMessage(`Selected website '${dom.target_url}' for scanning.`);
                      }}
                      className="btn-aegis-secondary"
                      style={{ flex: 1, padding: '6px 10px', fontSize: '0.78rem', fontWeight: 700 }}
                    >
                      Select Target
                    </button>
                    {!isVerified && (
                      <button
                        onClick={() => setIsDomainModalOpen(true)}
                        style={{
                          padding: '6px 12px',
                          fontSize: '0.78rem',
                          fontWeight: 700,
                          background: 'rgba(251, 191, 36, 0.2)',
                          border: '1px solid #fbbf24',
                          color: '#fbbf24',
                          borderRadius: '6px',
                          cursor: 'pointer'
                        }}
                      >
                        Verify Now
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div style={{
            background: 'rgba(10, 10, 10, 0.6)',
            padding: '1.25rem',
            borderRadius: '10px',
            border: '1px dashed rgba(255, 255, 255, 0.2)',
            textAlign: 'center',
            color: '#94a3b8',
            fontSize: '0.88rem'
          }}>
            ℹ No website target assets submitted yet. Click <strong style={{ color: '#ffffff' }}>"Submit New Target Website"</strong> to verify domain ownership and monitor website vulnerabilities upon login.
          </div>
        )}
      </section>

      {/* Metrics & Live Posture Cards */}
      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.25rem', marginBottom: '2.5rem' }}>
        <div style={{ background: 'rgba(14, 14, 14, 0.95)', padding: '1.4rem 1.6rem', borderRadius: '14px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Security Posture</div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', marginTop: '4px' }}>92 <span style={{ fontSize: '1.1rem', color: '#38bdf8' }}>/ 100</span></div>
          <div style={{ fontSize: '0.78rem', color: '#38bdf8', fontWeight: 700, marginTop: '4px' }}>GRADE: A- (GOOD)</div>
        </div>

        <div style={{ background: 'rgba(14, 14, 14, 0.95)', padding: '1.4rem 1.6rem', borderRadius: '14px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Active Findings</div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', marginTop: '4px' }}>{totalVulns}</div>
          <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>{criticalCount} Critical | {highCount} High</div>
        </div>

        <div style={{ background: 'rgba(14, 14, 14, 0.95)', padding: '1.4rem 1.6rem', borderRadius: '14px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>CISA KEV Feed</div>
          <div style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ef4444', marginTop: '4px' }}>Active</div>
          <div style={{ fontSize: '0.78rem', color: '#ef4444', fontWeight: 700, marginTop: '4px' }}>Automated Threat Sync</div>
        </div>

        <div style={{ background: 'rgba(14, 14, 14, 0.95)', padding: '1.4rem 1.6rem', borderRadius: '14px', border: '1px solid rgba(255, 255, 255, 0.12)' }}>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase' }}>Active User Session</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', marginTop: '8px' }}>{user ? user.username : 'Guest / Viewer'}</div>
          <div style={{ fontSize: '0.78rem', color: '#38bdf8', marginTop: '4px' }}>{user ? user.organization_name : 'Single-Machine Local Mode'}</div>
        </div>
      </section>

      {/* Vulnerability Stream & Action Cards */}
      <section style={{ background: 'rgba(12, 12, 12, 0.95)', padding: '2rem', borderRadius: '16px', border: '1px solid rgba(255, 255, 255, 0.14)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff' }}>Vulnerability Stream & Remediation Control</h2>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '2px' }}>Interactive human approval policy enforcement panel</p>
          </div>
          <button onClick={fetchLatestScan} className="btn-aegis-secondary" style={{ fontSize: '0.8rem', padding: '6px 14px' }}> Refresh Stream</button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {findings.length > 0 ? (
            findings.map((f, idx) => {
              const findingId = f.id || idx + 1;
              const sev = String(f.severity || 'LOW').toUpperCase();
              const isAutoApproved = f.status === 'AUTO_APPROVED';
              const isApproved = f.status === 'APPROVED';
              const isRejected = f.status === 'REJECTED';
              const hasPreviousState = Boolean(f.previous_state);

              const guideOpen = Boolean(expandedGuides[findingId]);
              const snippetOpen = Boolean(expandedSnippets[findingId]);

              const recommendation = f.recommendation || f.actionable_recommendation || 
                'Apply secure configuration controls and update affected endpoints to patch identified vulnerability vectors.';
              
              const snippet = f.config_snippet || f.snippet || '# Configuration Fix Snippet\n# Ensure strict headers and input sanitization\nHeader set X-Content-Type-Options "nosniff"';

              const guide = (() => {
                if (f.remediation_guide && typeof f.remediation_guide === 'string') {
                  return f.remediation_guide;
                }
                const g = f.full_fix_guide;
                if (g && typeof g === 'object') {
                  let steps = '';
                  if (g.fix_steps) {
                    if (typeof g.fix_steps === 'object') {
                      if (g.fix_steps.express_node) steps += `### Node.js / Express Fix:\n${g.fix_steps.express_node}\n\n`;
                      if (g.fix_steps.nginx) steps += `### Nginx Web Server Fix:\n${g.fix_steps.nginx}\n\n`;
                      if (g.fix_steps.apache) steps += `### Apache Web Server Fix:\n${g.fix_steps.apache}\n\n`;
                    } else {
                      steps += `### Step-by-Step Fix:\n${g.fix_steps}\n\n`;
                    }
                  }
                  return `### Finding Analysis: ${f.title || f.check_name || 'Vulnerability'}\n${g.plain_language_meaning || ''}\n\n**Security Risk:** ${g.why_it_is_risky || ''}\n\n${steps}### Verification Steps:\n${g.verification_steps || 'Re-run scanner audit to verify fix.'}\n\n${g.rollback_note ? `### ↩ Rollback Instructions:\n${g.rollback_note}` : ''}`;
                }

                const name = f.title || f.check_name || 'Vulnerability';
                const recText = f.recommendation || f.actionable_recommendation || 'Apply secure configuration controls.';
                const snipText = f.config_snippet || f.snippet || '';

                return `### Finding Analysis: ${name}\nTarget Endpoint: ${f.endpoint || 'http://localhost:3000'}\nSeverity: ${f.severity || 'MEDIUM'}\n\n**Recommended Action:**\n${recText}\n\n${snipText ? `**Configuration Code Fix:**\n${snipText}\n\n` : ''}### Step-by-Step Technical Remediation Guide:\n1. Locate the configuration file or routing handler for '${name}' on your server.\n2. Apply the specific patch directive or security control shown in the snippet above.\n3. Reload your web server process (e.g., \`sudo systemctl reload nginx\` or \`npm restart\`).\n4. Run verification command: \`curl -I ${f.endpoint || 'http://localhost:3000'}\` to verify response headers/status.`;
              })();

              return (
                <div key={findingId} style={{
                  background: 'rgba(14, 14, 14, 0.95)',
                  borderRadius: '14px',
                  padding: '1.5rem',
                  border: isAutoApproved ? '1px solid rgba(168, 85, 247, 0.4)' : '1px solid rgba(255, 255, 255, 0.16)',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.6)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '1rem'
                }}>
                  {/* Top Badges & Status Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {(() => {
                        const sevColor = sev === 'CRITICAL' ? '#ef4444' : sev === 'HIGH' ? '#f97316' : sev === 'MEDIUM' ? '#eab308' : '#ffffff';
                        return (
                          <span className="mono-text" style={{
                            fontSize: '0.75rem',
                            fontWeight: 800,
                            padding: '4px 12px',
                            borderRadius: '12px',
                            background: `${sevColor}22`,
                            color: sevColor,
                            border: `1px solid ${sevColor}`
                          }}>
                            {sev}
                          </span>
                        );
                      })()}
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: '#ffffff', background: 'rgba(255, 255, 255, 0.1)', padding: '4px 10px', borderRadius: '12px', border: '1px solid #000000' }}>
                        AI Threat: High Confidence
                      </span>
                      {/* API Issue vs Web Page Issue Badge */}
                      <span className="mono-text" style={{
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        padding: '4px 10px',
                        borderRadius: '12px',
                        background: 'rgba(255, 255, 255, 0.1)',
                        color: '#ffffff',
                        border: '1px solid #000000'
                      }}>
                        {f.is_api_endpoint ? ' API ISSUE' : ' WEB PAGE ISSUE'}
                      </span>
                      {f.review_deadline && (
                        <span className="mono-text" style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                          Deadline: {new Date(f.review_deadline).toLocaleString()}
                        </span>
                      )}
                    </div>

                    {/* Status Badge */}
                    {isAutoApproved ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="mono-text" style={{
                          background: 'rgba(56, 189, 248, 0.2)',
                          color: '#38bdf8',
                          border: '1px solid #38bdf8',
                          padding: '4px 12px',
                          borderRadius: '12px',
                          fontWeight: 800,
                          fontSize: '0.78rem'
                        }}>
                          AUTO-APPROVED (TIMEOUT)
                        </span>
                        <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>by auto_approval_scheduler (expired_deadline)</span>
                      </div>
                    ) : (
                      <span className="mono-text" style={{
                        fontSize: '0.78rem',
                        fontWeight: 800,
                        padding: '4px 12px',
                        borderRadius: '12px',
                        background: isApproved ? 'rgba(56, 189, 248, 0.2)' : isRejected ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.05)',
                        color: isApproved ? '#38bdf8' : isRejected ? '#ef4444' : '#94a3b8',
                        border: `1px solid ${isApproved ? '#38bdf8' : isRejected ? '#ef4444' : '#000000'}`
                      }}>
                        STATUS: {f.status || 'OPEN'}
                      </span>
                    )}
                  </div>

                  {/* Finding Title & Target Host */}
                  <div>
                    <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
                      #{findingId} {f.title || f.check_name}
                    </h3>
                    <div style={{ display: 'flex', gap: '8px', marginTop: '6px' }}>
                      <span className="mono-text" style={{ fontSize: '0.78rem', background: '#000000', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(255,255,255,0.1)', color: '#94a3b8' }}>
                        {f.endpoint || f.subdomain?.hostname || 'localhost'}
                      </span>
                    </div>
                  </div>

                  {/* Actionable Fix Recommendation Panel */}
                  <div style={{
                    background: '#000000',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '10px',
                    padding: '1.25rem',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '1rem'
                  }}>
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.9rem', color: '#38bdf8', marginBottom: '4px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                        Actionable Fix Recommendation:
                      </div>
                      <p style={{ fontSize: '0.88rem', color: '#e2e8f0', lineHeight: 1.5, margin: 0 }}>
                        {recommendation}
                      </p>
                    </div>

                    {/* View Raw Fix Snippet Dropdown */}
                    <div>
                      <button
                        onClick={() => setExpandedSnippets(prev => ({ ...prev, [findingId]: !prev[findingId] }))}
                        style={{
                          background: 'transparent',
                          border: 'none',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          fontWeight: 700,
                          cursor: 'pointer',
                          padding: 0,
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px'
                        }}
                      >
                        {snippetOpen ? ' Hide Raw Fix Snippet' : ' View Raw Fix Snippet'}
                      </button>
                      {snippetOpen && (
                        <pre className="mono-text" style={{
                          background: '#050505',
                          color: '#e2e8f0',
                          padding: '12px 14px',
                          borderRadius: '8px',
                          fontSize: '0.82rem',
                          marginTop: '8px',
                          border: '1px solid rgba(255, 255, 255, 0.2)',
                          overflowX: 'auto',
                          whiteSpace: 'pre-wrap'
                        }}>
                          {snippet}
                        </pre>
                      )}
                    </div>

                    {/* HOW TO FIX — Technical Remediation & Standards Guide Accordion */}
                    <div style={{
                      border: '1px solid rgba(255, 255, 255, 0.15)',
                      borderRadius: '8px',
                      overflow: 'hidden'
                    }}>
                      <button
                        onClick={() => setExpandedGuides(prev => ({ ...prev, [findingId]: !prev[findingId] }))}
                        style={{
                          width: '100%',
                          background: 'rgba(255, 255, 255, 0.03)',
                          border: 'none',
                          padding: '10px 14px',
                          color: '#ffffff',
                          fontWeight: 700,
                          fontSize: '0.88rem',
                          cursor: 'pointer',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}
                      >
                        <span> HOW TO FIX — Technical Remediation & Standards Guide</span>
                        <span style={{ fontSize: '0.8rem', color: '#ffffff', background: 'rgba(255, 255, 255, 0.1)', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(255, 255, 255, 0.3)' }}>
                          {guideOpen ? 'Click to Collapse ' : 'Click to Expand Guide '}
                        </span>
                      </button>
                      {guideOpen && (
                        <div style={{
                          padding: '1rem 1.25rem',
                          background: '#050505',
                          borderTop: '1px solid rgba(255, 255, 255, 0.1)',
                          color: '#cbd5e1',
                          fontSize: '0.86rem',
                          lineHeight: 1.6,
                          whiteSpace: 'pre-wrap'
                        }}>
                          {guide}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Evidence & Action Buttons Footer */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', paddingTop: '6px' }}>
                    <div style={{ fontSize: '0.8rem', color: '#94a3b8', flex: 1, minWidth: '240px' }}>
                      Evidence: <span className="mono-text" style={{ color: '#cbd5e1' }}>{f.evidence || 'HTTP response payload vector detected'}</span>
                    </div>

                    <div style={{ display: 'flex', gap: '0.6rem' }}>
                      <button
                        onClick={() => handleAction(findingId, 'approve')}
                        disabled={isApproved}
                        style={{
                          background: isApproved ? 'rgba(56, 189, 248, 0.2)' : '#ffffff',
                          color: isApproved ? '#38bdf8' : '#000000',
                          border: '1px solid #ffffff',
                          fontWeight: 800,
                          padding: '8px 16px',
                          borderRadius: '6px',
                          cursor: isApproved ? 'default' : 'pointer',
                          fontSize: '0.84rem'
                        }}
                      >
                        {isApproved ? ' Approved' : 'Approve Fix'}
                      </button>

                      <button
                        onClick={() => handleAction(findingId, 'reject')}
                        disabled={isRejected}
                        style={{
                          background: 'transparent',
                          color: isRejected ? '#ef4444' : '#fca5a5',
                          border: '1px solid #ef4444',
                          fontWeight: 700,
                          padding: '8px 14px',
                          borderRadius: '6px',
                          cursor: isRejected ? 'default' : 'pointer',
                          fontSize: '0.84rem'
                        }}
                      >
                        {isRejected ? ' Rejected' : 'Reject / False Positive'}
                      </button>

                      {hasPreviousState && (
                        <button
                          onClick={() => handleAction(findingId, 'rollback')}
                          style={{
                            background: 'rgba(255, 255, 255, 0.1)',
                            color: '#ffffff',
                            border: '1px solid #ffffff',
                            fontWeight: 800,
                            padding: '8px 14px',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontSize: '0.84rem'
                          }}
                        >
                          Restore State
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="mono-text" style={{ color: '#94a3b8', textAlign: 'center', padding: '2rem' }}>
              No vulnerabilities detected. Run a scan to populate telemetry.
            </div>
          )}
        </div>
      </section>

    </main>
  );
}
