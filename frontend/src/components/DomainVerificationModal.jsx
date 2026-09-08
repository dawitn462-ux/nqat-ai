import React, { useState, useEffect } from 'react';

export default function DomainVerificationModal({ isOpen, onClose, onVerifiedDomainAdded }) {
  const [domainInput, setDomainInput] = useState('');
  const [verificationMethod, setVerificationMethod] = useState('file'); // Default to HTTP file for web apps
  const [submittedDomains, setSubmittedDomains] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('domains'); // 'domains' | 'audit'
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [copiedKey, setCopiedKey] = useState(null);

  const [quota, setQuota] = useState({ used_24h: 0, daily_limit: 3 });

  const token = localStorage.getItem('nkat_jwt_token');
  const authHeaders = token
    ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
    : { 'Content-Type': 'application/json' };

  const copyToClipboard = (text, key) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  const fetchQuota = async () => {
    try {
      const res = await fetch('/api/v1/domains/quota', { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setQuota(data);
      }
    } catch (err) {
      console.error('Failed to fetch quota:', err);
    }
  };

  const handleResetQuota = async () => {
    try {
      const res = await fetch('/api/v1/domains/quota/reset', {
        method: 'POST',
        headers: authHeaders
      });
      if (res.ok) {
        const data = await res.json();
        setQuota(data);
        setErrorMsg('');
        setSuccessMsg('Daily domain submission quota reset successfully (0/3 used)!');
        fetchAuditLogs();
      }
    } catch (err) {
      console.error('Failed to reset quota:', err);
    }
  };

  const fetchDomains = async (targetToSelect = null) => {
    try {
      const res = await fetch('/api/v1/domains', { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setSubmittedDomains(data);

        if (targetToSelect) {
          const found = data.find(d => d.id === targetToSelect.id || d.domain === targetToSelect.domain);
          if (found) {
            setSelectedDomain(found);
            return;
          }
        }

        // If no target selected yet, pick localhost/verified first or data[0]
        if (!selectedDomain && data.length > 0) {
          const defaultTarget = data.find(d => d.domain === 'localhost' || d.status === 'VERIFIED') || data[0];
          setSelectedDomain(defaultTarget);
        } else if (selectedDomain && data.length > 0) {
          const updatedSelected = data.find(d => d.id === selectedDomain.id);
          if (updatedSelected) {
            setSelectedDomain(updatedSelected);
          } else {
            setSelectedDomain(data[0]);
          }
        } else if (data.length === 0) {
          setSelectedDomain(null);
        }
      }
    } catch (err) {
      console.error('Failed to fetch domains:', err);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const res = await fetch('/api/v1/domains/audit-log', { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (err) {
      console.error('Failed to fetch audit logs:', err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      setErrorMsg('');
      setSuccessMsg('');
      fetchDomains();
      fetchAuditLogs();
      fetchQuota();
    }
  }, [isOpen]);

  const handleSubmitDomain = async (e) => {
    e.preventDefault();
    if (!domainInput.trim()) return;

    setLoading(true);
    setErrorMsg('');
    setSuccessMsg('');

    try {
      const res = await fetch('/api/v1/domains/submit', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          domain: domainInput.trim(),
          verification_method: verificationMethod
        })
      });

      const data = await res.json();
      if (res.ok) {
        const isVerified = data.status === 'VERIFIED';
        if (isVerified) {
          setSuccessMsg(`Target '${data.domain}' (${data.target_url}) added and automatically VERIFIED! Scoped for security testing.`);
          if (onVerifiedDomainAdded) {
            onVerifiedDomainAdded(data.target_url || data.domain);
          }
        } else {
          setSuccessMsg(`Target '${data.domain}' submitted successfully. Follow ownership instructions below.`);
        }
        setSelectedDomain(data);
        setDomainInput('');
        fetchDomains(data);
        fetchAuditLogs();
        fetchQuota();
      } else {
        setErrorMsg(data.detail || 'Failed to submit domain target.');
        fetchAuditLogs();
        fetchQuota();
      }
    } catch (err) {
      setErrorMsg('Error submitting domain target: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyNow = async (domainId) => {
    setLoading(true);
    setErrorMsg('');
    setSuccessMsg('');

    try {
      const res = await fetch(`/api/v1/domains/${domainId}/verify`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ verification_method: selectedDomain?.verification_method || verificationMethod })
      });

      const data = await res.json();
      if (res.ok) {
        if (data.status === 'VERIFIED') {
          setSuccessMsg(`Ownership VERIFIED for '${data.domain}'! Scoped authorized-target activated.`);
          if (onVerifiedDomainAdded) {
            onVerifiedDomainAdded(data.target_url || data.domain);
          }
        } else {
          setErrorMsg(`Verification Failed: ${data.last_error || 'Challenge token not found at target endpoints.'}`);
        }
        setSelectedDomain(data);
        fetchDomains(data);
        fetchAuditLogs();
      } else {
        setErrorMsg(data.detail || 'Verification request failed.');
      }
    } catch (err) {
      setErrorMsg('Error verifying domain: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteDomain = async (domainId) => {
    try {
      const res = await fetch(`/api/v1/domains/${domainId}`, {
        method: 'DELETE',
        headers: authHeaders
      });
      if (res.ok) {
        setErrorMsg('');
        setSuccessMsg('Target removed from authorized scope.');
        if (selectedDomain?.id === domainId) {
          setSelectedDomain(null);
        }
        fetchDomains();
        fetchAuditLogs();
      } else {
        setErrorMsg('Failed to remove target.');
      }
    } catch (err) {
      console.error('Delete error:', err);
      setErrorMsg('Error deleting target: ' + err.message);
    }
  };

  const handleSelectDomain = (domainObj) => {
    setSelectedDomain(domainObj);
    setErrorMsg('');
    setSuccessMsg('');
  };

  const handleUseTargetAndScan = (targetObj) => {
    const url = targetObj.target_url || (targetObj.domain === 'localhost' ? 'http://localhost:3000' : `https://${targetObj.domain}`);
    if (onVerifiedDomainAdded) {
      onVerifiedDomainAdded(url);
    }
    onClose();
  };

  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(5, 7, 10, 0.88)',
      backdropFilter: 'blur(10px)'
    }}>
      <div style={{
        width: '92%',
        maxWidth: '880px',
        maxHeight: '90vh',
        overflowY: 'auto',
        background: '#0d0f12',
        border: '1px solid rgba(255, 255, 255, 0.15)',
        borderRadius: '16px',
        padding: '2rem',
        boxShadow: '0 25px 60px rgba(0, 0, 0, 0.95)',
        color: '#ffffff'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '1.25rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '34px',
                height: '34px',
                borderRadius: '8px',
                background: '#000000',
                border: '1px solid #ffffff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0
              }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 4L20.5 19H3.5L12 4Z" fill="#FFFFFF" stroke="#FFFFFF" strokeWidth="0.5" strokeLinejoin="round"/>
                  <path d="M12 9.5L16.2 17H7.8L12 9.5Z" fill="#000000"/>
                </svg>
              </div>
              <h2 style={{ fontSize: '1.45rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
                Target Scope & Ownership Verification
              </h2>
            </div>
            <p style={{ color: '#94a3b8', fontSize: '0.86rem', margin: '6px 0 0 0' }}>
              Enterprise target authorization check. Local loopback environments (<code style={{ color: '#38bdf8' }}>localhost:3000</code>, <code style={{ color: '#38bdf8' }}>127.0.0.1</code>) are pre-authorized for immediate scanning.
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.2)',
              color: '#ffffff',
              borderRadius: '8px',
              padding: '6px 14px',
              cursor: 'pointer',
              fontSize: '0.88rem',
              fontWeight: 600
            }}
          >
            Close
          </button>
        </div>

        {/* View Mode Tabs */}
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <button
            onClick={() => { setActiveTab('domains'); setErrorMsg(''); setSuccessMsg(''); }}
            style={{
              background: activeTab === 'domains' ? '#ffffff' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${activeTab === 'domains' ? '#ffffff' : 'rgba(255, 255, 255, 0.1)'}`,
              color: activeTab === 'domains' ? '#000000' : '#94a3b8',
              borderRadius: '8px',
              padding: '8px 18px',
              fontWeight: 700,
              fontSize: '0.88rem',
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            Target Domains ({submittedDomains.length})
          </button>
          <button
            onClick={() => { setActiveTab('audit'); setErrorMsg(''); setSuccessMsg(''); }}
            style={{
              background: activeTab === 'audit' ? '#ffffff' : 'rgba(255, 255, 255, 0.05)',
              border: `1px solid ${activeTab === 'audit' ? '#ffffff' : 'rgba(255, 255, 255, 0.1)'}`,
              color: activeTab === 'audit' ? '#000000' : '#94a3b8',
              borderRadius: '8px',
              padding: '8px 18px',
              fontWeight: 700,
              fontSize: '0.88rem',
              cursor: 'pointer',
              transition: 'all 0.15s ease'
            }}
          >
            Audit Trail ({auditLogs.length})
          </button>
        </div>

        {/* Dynamic Alerts */}
        {errorMsg && (
          <div style={{
            background: 'rgba(239, 68, 68, 0.1)',
            border: '1px solid #ef4444',
            color: '#fca5a5',
            padding: '12px 16px',
            borderRadius: '10px',
            marginBottom: '1.25rem',
            fontSize: '0.88rem',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '12px'
          }}>
            <div>
              <strong>Error: </strong> {errorMsg}
            </div>
            {errorMsg.toLowerCase().includes('rate limit') && (
              <button
                type="button"
                onClick={handleResetQuota}
                style={{
                  background: '#ef4444',
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '6px 12px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap'
                }}
              >
                Reset Quota Now
              </button>
            )}
          </div>
        )}

        {successMsg && (
          <div style={{
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid #10b981',
            color: '#6ee7b7',
            padding: '12px 16px',
            borderRadius: '10px',
            marginBottom: '1.25rem',
            fontSize: '0.88rem'
          }}>
            <strong>Success: </strong> {successMsg}
          </div>
        )}

        {activeTab === 'domains' ? (
          <>
            {/* Submit Target Form */}
            <form
              onSubmit={handleSubmitDomain}
              style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.1)',
                borderRadius: '12px',
                padding: '1.25rem',
                marginBottom: '1.75rem'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.9rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                  Submit Target Website or Application
                </h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{
                    fontSize: '0.76rem',
                    fontWeight: 700,
                    padding: '3px 10px',
                    borderRadius: '12px',
                    background: quota.used_24h >= quota.daily_limit ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                    color: quota.used_24h >= quota.daily_limit ? '#fca5a5' : '#cbd5e1',
                    border: `1px solid ${quota.used_24h >= quota.daily_limit ? '#ef4444' : 'rgba(255, 255, 255, 0.2)'}`
                  }}>
                    External Quota: {quota.used_24h}/{quota.daily_limit} Used (Localhost exempt)
                  </span>
                  <button
                    type="button"
                    onClick={handleResetQuota}
                    title="Reset daily domain submission quota"
                    style={{
                      background: 'rgba(255, 255, 255, 0.08)',
                      border: '1px solid rgba(255, 255, 255, 0.25)',
                      color: '#ffffff',
                      borderRadius: '6px',
                      padding: '3px 8px',
                      fontSize: '0.74rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    Reset Quota
                  </button>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                <input
                  type="text"
                  required
                  placeholder="e.g. http://localhost:3000 or https://target-site.com"
                  value={domainInput}
                  onChange={(e) => setDomainInput(e.target.value)}
                  style={{
                    flex: '1 1 280px',
                    background: '#000000',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '8px',
                    padding: '10px 14px',
                    color: '#ffffff',
                    fontSize: '0.92rem',
                    outline: 'none'
                  }}
                />
                <select
                  value={verificationMethod}
                  onChange={(e) => setVerificationMethod(e.target.value)}
                  style={{
                    background: '#000000',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '8px',
                    padding: '10px 14px',
                    color: '#ffffff',
                    fontSize: '0.9rem',
                    outline: 'none'
                  }}
                >
                  <option value="file">File-Based HTTP Upload</option>
                  <option value="dns_txt">DNS TXT Record</option>
                </select>
                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    background: '#ffffff',
                    color: '#000000',
                    fontWeight: 800,
                    border: 'none',
                    borderRadius: '8px',
                    padding: '10px 20px',
                    cursor: loading ? 'not-allowed' : 'pointer',
                    fontSize: '0.92rem'
                  }}
                >
                  {loading ? 'Submitting...' : 'Add / Authorize Target'}
                </button>
              </div>
            </form>

            {/* List of Scoped Target Domains */}
            <div style={{ marginBottom: '1.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                  Scoped Target Domains ({submittedDomains.length})
                </h3>
                <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
                  Click a target to view details or trigger a scan
                </span>
              </div>

              {submittedDomains.length === 0 ? (
                <div style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px dashed rgba(255, 255, 255, 0.15)',
                  borderRadius: '10px',
                  padding: '1.5rem',
                  textAlign: 'center',
                  color: '#94a3b8',
                  fontSize: '0.88rem'
                }}>
                  No custom targets submitted yet. Enter your local or production URL above (e.g. <code>http://localhost:3000</code>) to begin.
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '0.75rem' }}>
                  {submittedDomains.map((d) => {
                    const isSelected = selectedDomain?.id === d.id;
                    const isVerified = d.status === 'VERIFIED';
                    const isFailed = d.status === 'FAILED';
                    return (
                      <div
                        key={d.id}
                        onClick={() => handleSelectDomain(d)}
                        style={{
                          background: isSelected ? 'rgba(255, 255, 255, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                          border: `1.5px solid ${isSelected ? '#ffffff' : 'rgba(255, 255, 255, 0.1)'}`,
                          borderRadius: '10px',
                          padding: '12px 14px',
                          cursor: 'pointer',
                          transition: 'all 0.15s ease',
                          position: 'relative'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <div>
                            <div style={{ fontWeight: 800, fontSize: '0.95rem', color: '#ffffff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                              {d.owner || d.domain}
                            </div>
                            {d.owner && d.owner !== d.domain && (
                              <div style={{ fontSize: '0.72rem', color: '#38bdf8', fontWeight: 600 }}>
                                {d.domain}
                              </div>
                            )}
                          </div>
                          <span style={{
                            fontSize: '0.72rem',
                            fontWeight: 800,
                            padding: '2px 8px',
                            borderRadius: '10px',
                            background: isVerified ? '#ffffff' : isFailed ? 'rgba(239, 68, 68, 0.2)' : 'rgba(251, 191, 36, 0.15)',
                            color: isVerified ? '#000000' : isFailed ? '#fca5a5' : '#fbbf24',
                            border: `1px solid ${isVerified ? '#ffffff' : isFailed ? '#ef4444' : '#fbbf24'}`
                          }}>
                            {d.status}
                          </span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem', color: '#94a3b8' }}>
                          <span>{d.target_url || d.domain}</span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDeleteDomain(d.id);
                            }}
                            title="Remove target"
                            style={{
                              background: 'transparent',
                              border: 'none',
                              color: '#64748b',
                              fontSize: '1rem',
                              cursor: 'pointer',
                              padding: '0 4px',
                              lineHeight: 1
                            }}
                            onMouseEnter={(e) => e.target.style.color = '#ef4444'}
                            onMouseLeave={(e) => e.target.style.color = '#64748b'}
                          >
                            &times;
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Selected Domain View */}
            {selectedDomain && (
              <div style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                borderRadius: '12px',
                padding: '1.5rem'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: '#94a3b8', fontWeight: 700 }}>
                      Active Selected Target
                    </span>
                    <h4 style={{ margin: '2px 0 0 0', color: '#ffffff', fontSize: '1.2rem', fontWeight: 800 }}>
                      {selectedDomain.owner ? `${selectedDomain.owner} (${selectedDomain.domain})` : selectedDomain.domain}
                    </h4>
                  </div>
                  <button
                    onClick={() => handleDeleteDomain(selectedDomain.id)}
                    style={{
                      background: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid #ef4444',
                      color: '#fca5a5',
                      borderRadius: '6px',
                      padding: '6px 12px',
                      cursor: 'pointer',
                      fontSize: '0.8rem',
                      fontWeight: 700
                    }}
                  >
                    Remove Target
                  </button>
                </div>

                {selectedDomain.status === 'VERIFIED' ? (
                  /* Verified Target Screen */
                  <div>
                    <div style={{
                      background: 'rgba(16, 185, 129, 0.08)',
                      border: '1px solid rgba(16, 185, 129, 0.4)',
                      borderRadius: '10px',
                      padding: '1.25rem',
                      marginBottom: '1.5rem'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                        <span style={{ background: '#10b981', color: '#000000', fontSize: '0.75rem', fontWeight: 800, padding: '3px 8px', borderRadius: '6px' }}>
                          VERIFIED & SCOPED
                        </span>
                        <span style={{ color: '#ffffff', fontWeight: 700, fontSize: '0.95rem' }}>
                          Target is Authorized for Security Scanning
                        </span>
                      </div>
                      <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.86rem', lineHeight: 1.5 }}>
                        This domain has fulfilled authorization verification (or is a pre-approved local development loopback). Full AST pipelines, SQLi/XSS checks, and AI threat graphs are ready to execute.
                      </p>
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
                      <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Target Application</div>
                        <div style={{ fontSize: '0.9rem', color: '#ffffff', fontWeight: 700, marginTop: '3px' }}>
                          {selectedDomain.owner || selectedDomain.domain}
                        </div>
                      </div>
                      <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Target URL</div>
                        <div style={{ fontSize: '0.9rem', color: '#38bdf8', fontWeight: 700, marginTop: '3px', wordBreak: 'break-all' }}>
                          {selectedDomain.target_url || `http://${selectedDomain.domain}`}
                        </div>
                      </div>
                      <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Verification Method</div>
                        <div style={{ fontSize: '0.9rem', color: '#ffffff', fontWeight: 700, marginTop: '3px' }}>
                          {['localhost', '127.0.0.1', '0.0.0.0', '::1'].includes(selectedDomain.domain)
                            ? 'Pre-Authorized Localhost'
                            : (selectedDomain.verification_method === 'file' ? 'HTTP File Upload' : 'DNS TXT Record')}
                        </div>
                      </div>
                      <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                        <div style={{ fontSize: '0.72rem', color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Authorization Status</div>
                        <div style={{ fontSize: '0.9rem', color: '#10b981', fontWeight: 700, marginTop: '3px' }}>
                          ACTIVE / SCOPED
                        </div>
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                      <button
                        onClick={() => handleUseTargetAndScan(selectedDomain)}
                        style={{
                          background: '#ffffff',
                          color: '#000000',
                          fontWeight: 800,
                          border: 'none',
                          borderRadius: '8px',
                          padding: '12px 24px',
                          cursor: 'pointer',
                          fontSize: '0.95rem'
                        }}
                      >
                        Set as Active Target & Start Scan
                      </button>
                    </div>
                  </div>
                ) : (
                  /* Unverified / Pending Instructions Screen */
                  <div>
                    <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.25rem' }}>
                      <button
                        onClick={() => setSelectedDomain({ ...selectedDomain, verification_method: 'file' })}
                        style={{
                          padding: '7px 16px',
                          borderRadius: '8px',
                          border: `1px solid ${selectedDomain.verification_method === 'file' ? '#ffffff' : 'rgba(255,255,255,0.2)'}`,
                          background: selectedDomain.verification_method === 'file' ? 'rgba(255, 255, 255, 0.12)' : 'transparent',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          fontWeight: 700,
                          cursor: 'pointer'
                        }}
                      >
                        Option A: HTTP File Upload (Recommended)
                      </button>
                      <button
                        onClick={() => setSelectedDomain({ ...selectedDomain, verification_method: 'dns_txt' })}
                        style={{
                          padding: '7px 16px',
                          borderRadius: '8px',
                          border: `1px solid ${selectedDomain.verification_method === 'dns_txt' ? '#ffffff' : 'rgba(255,255,255,0.2)'}`,
                          background: selectedDomain.verification_method === 'dns_txt' ? 'rgba(255, 255, 255, 0.12)' : 'transparent',
                          color: '#ffffff',
                          fontSize: '0.85rem',
                          fontWeight: 700,
                          cursor: 'pointer'
                        }}
                      >
                        Option B: DNS TXT Record
                      </button>
                    </div>

                    {selectedDomain.verification_method === 'file' ? (
                      <div style={{ fontSize: '0.88rem', lineHeight: 1.6, color: '#cbd5e1' }}>
                        <p style={{ margin: '0 0 6px 0' }}>1. Create a plain text file on your web server at the path:</p>
                        <div style={{
                          background: '#000000',
                          padding: '10px 14px',
                          borderRadius: '8px',
                          fontFamily: 'monospace',
                          marginBottom: '12px',
                          border: '1px solid rgba(255,255,255,0.1)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}>
                          <span>{selectedDomain.file_verification_url}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(selectedDomain.file_verification_url, 'file_url')}
                            style={{ background: 'rgba(255,255,255,0.1)', border: 'none', color: '#ffffff', borderRadius: '4px', padding: '4px 8px', fontSize: '0.74rem', cursor: 'pointer' }}
                          >
                            {copiedKey === 'file_url' ? 'Copied!' : 'Copy Path'}
                          </button>
                        </div>

                        <p style={{ margin: '0 0 6px 0' }}>2. Set the file contents to your challenge token:</p>
                        <div style={{
                          background: '#000000',
                          padding: '10px 14px',
                          borderRadius: '8px',
                          fontFamily: 'monospace',
                          marginBottom: '16px',
                          border: '1px solid rgba(255,255,255,0.1)',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center'
                        }}>
                          <span style={{ color: '#38bdf8' }}>{selectedDomain.file_verification_content}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(selectedDomain.file_verification_content, 'file_content')}
                            style={{ background: 'rgba(255,255,255,0.1)', border: 'none', color: '#ffffff', borderRadius: '4px', padding: '4px 8px', fontSize: '0.74rem', cursor: 'pointer' }}
                          >
                            {copiedKey === 'file_content' ? 'Copied!' : 'Copy Token'}
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.88rem', lineHeight: 1.6, color: '#cbd5e1' }}>
                        <p style={{ margin: '0 0 6px 0' }}>1. Access your DNS provider dashboard (Cloudflare, Route53, GoDaddy, etc.).</p>
                        <p style={{ margin: '0 0 6px 0' }}>2. Add a new <strong>TXT Record</strong> with the following details:</p>
                        <div style={{
                          background: '#000000',
                          padding: '12px 14px',
                          borderRadius: '8px',
                          fontFamily: 'monospace',
                          margin: '8px 0 16px 0',
                          border: '1px solid rgba(255,255,255,0.1)'
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                            <div><strong>Host / Name:</strong> {selectedDomain.dns_txt_record_name}</div>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(selectedDomain.dns_txt_record_name, 'txt_name')}
                              style={{ background: 'rgba(255,255,255,0.1)', border: 'none', color: '#ffffff', borderRadius: '4px', padding: '2px 8px', fontSize: '0.72rem', cursor: 'pointer' }}
                            >
                              {copiedKey === 'txt_name' ? 'Copied!' : 'Copy'}
                            </button>
                          </div>
                          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                            <div><strong>Value / Content:</strong> <span style={{ color: '#38bdf8' }}>{selectedDomain.dns_txt_record_value}</span></div>
                            <button
                              type="button"
                              onClick={() => copyToClipboard(selectedDomain.dns_txt_record_value, 'txt_val')}
                              style={{ background: 'rgba(255,255,255,0.1)', border: 'none', color: '#ffffff', borderRadius: '4px', padding: '2px 8px', fontSize: '0.72rem', cursor: 'pointer' }}
                            >
                              {copiedKey === 'txt_val' ? 'Copied!' : 'Copy'}
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    <div style={{ marginTop: '1.25rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
                      <button
                        onClick={() => handleVerifyNow(selectedDomain.id)}
                        disabled={loading}
                        style={{
                          background: '#ffffff',
                          color: '#000000',
                          fontWeight: 800,
                          border: 'none',
                          borderRadius: '8px',
                          padding: '11px 22px',
                          cursor: loading ? 'not-allowed' : 'pointer',
                          fontSize: '0.92rem'
                        }}
                      >
                        {loading ? 'Checking Ownership...' : 'Verify Ownership Now'}
                      </button>

                      <span style={{ fontSize: '0.85rem', color: selectedDomain.status === 'FAILED' ? '#ef4444' : '#94a3b8' }}>
                        Current Status: <strong>{selectedDomain.status}</strong>
                      </span>
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        ) : (
          /* Audit Trail Table View */
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
                Domain Verification Audit Trail Logs
              </h3>
              <button
                type="button"
                onClick={fetchAuditLogs}
                style={{
                  background: 'transparent',
                  border: '1px solid rgba(255,255,255,0.2)',
                  color: '#ffffff',
                  borderRadius: '6px',
                  padding: '4px 10px',
                  fontSize: '0.78rem',
                  cursor: 'pointer'
                }}
              >
                Refresh Logs
              </button>
            </div>
            {auditLogs.length === 0 ? (
              <p style={{ color: '#94a3b8', fontStyle: 'italic' }}>No audit log entries recorded yet.</p>
            ) : (
              <div style={{ overflowX: 'auto', background: 'rgba(0,0,0,0.5)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.82rem' }}>
                  <thead>
                    <tr style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                      <th style={{ padding: '10px 12px' }}>Timestamp</th>
                      <th style={{ padding: '10px 12px' }}>User ID</th>
                      <th style={{ padding: '10px 12px' }}>Domain</th>
                      <th style={{ padding: '10px 12px' }}>Method</th>
                      <th style={{ padding: '10px 12px' }}>Result</th>
                      <th style={{ padding: '10px 12px' }}>Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => {
                      const isPass = log.result === 'VERIFIED' || log.result === 'SUBMITTED' || log.result === 'SUBMITTED_EXISTING';
                      const isRateLim = log.result === 'RATE_LIMITED';
                      return (
                        <tr key={log.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                          <td style={{ padding: '10px 12px', color: '#cbd5e1', whiteSpace: 'nowrap' }}>
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td style={{ padding: '10px 12px', color: '#94a3b8', fontWeight: 600 }}>
                            #{log.user_id || 1}
                          </td>
                          <td style={{ padding: '10px 12px', fontWeight: 700, color: '#ffffff' }}>
                            {log.domain}
                          </td>
                          <td style={{ padding: '10px 12px', color: '#94a3b8' }}>
                            {log.method}
                          </td>
                          <td style={{ padding: '10px 12px' }}>
                            <span style={{
                              fontSize: '0.72rem',
                              fontWeight: 800,
                              padding: '2px 8px',
                              borderRadius: '10px',
                              background: isPass ? 'rgba(56, 189, 248, 0.15)' : isRateLim ? 'rgba(251, 191, 36, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                              color: isPass ? '#38bdf8' : isRateLim ? '#fbbf24' : '#ef4444',
                              border: `1px solid ${isPass ? '#38bdf8' : isRateLim ? '#fbbf24' : '#ef4444'}`
                            }}>
                              {log.result}
                            </span>
                          </td>
                          <td style={{ padding: '10px 12px', color: '#94a3b8', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {log.details || '-'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
