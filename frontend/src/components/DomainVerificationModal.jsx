import React, { useState, useEffect } from 'react';

export default function DomainVerificationModal({ isOpen, onClose, onVerifiedDomainAdded }) {
  const [domainInput, setDomainInput] = useState('');
  const [verificationMethod, setVerificationMethod] = useState('dns_txt');
  const [submittedDomains, setSubmittedDomains] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [activeTab, setActiveTab] = useState('domains'); // 'domains' | 'audit'
  const [selectedDomain, setSelectedDomain] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const token = localStorage.getItem('nkat_jwt_token');
  const authHeaders = token
    ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
    : { 'Content-Type': 'application/json' };

  const fetchDomains = async () => {
    try {
      const res = await fetch('/api/v1/domains', { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setSubmittedDomains(data);
        if (data.length > 0 && !selectedDomain) {
          setSelectedDomain(data[0]);
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
      fetchDomains();
      fetchAuditLogs();
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
        setSuccessMsg(`Domain '${data.domain}' submitted successfully. Follow ownership instructions below.`);
        setSelectedDomain(data);
        setDomainInput('');
        fetchDomains();
        fetchAuditLogs();
      } else {
        setErrorMsg(data.detail || 'Failed to submit domain target.');
        fetchAuditLogs();
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
          setSuccessMsg(` Ownership VERIFIED for '${data.domain}'! Scoped authorized-target activated.`);
          if (onVerifiedDomainAdded) onVerifiedDomainAdded(data.domain);
        } else {
          setErrorMsg(`Verification Failed: ${data.last_error || 'Token not found.'}`);
        }
        setSelectedDomain(data);
        fetchDomains();
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
        if (selectedDomain?.id === domainId) setSelectedDomain(null);
        fetchDomains();
      }
    } catch (err) {
      console.error('Delete error:', err);
    }
  };

  if (!isOpen) return null;

  // Calculate daily submission usage (attempts in past 24 hours)
  const past24hCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const submissions24h = auditLogs.filter(log => 
    new Date(log.timestamp) >= past24hCutoff && 
    ['SUBMITTED', 'VERIFIED', 'SUBMITTED_EXISTING'].includes(log.result)
  ).length;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(5, 7, 10, 0.85)',
      backdropFilter: 'blur(10px)'
    }}>
      <div style={{
        width: '90%',
        maxWidth: '880px',
        maxHeight: '90vh',
        overflowY: 'auto',
        background: 'rgba(10, 10, 10, 0.98)',
        border: '2px solid #000000',
        borderRadius: '16px',
        padding: '2.5rem',
        boxShadow: '0 20px 50px rgba(0,0,0,0.9)',
        color: '#ffffff'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div>
            <h2 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#ffffff', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: '#000000',
                border: '1px solid #333333',
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
              Domain Target Ownership Verification & Audit Log
            </h2>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', margin: '4px 0 0 0' }}>
              Mandatory legal & safety check before running scan pipelines on external websites.
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: '1px solid rgba(255,255,255,0.2)',
              color: '#ffffff',
              borderRadius: '8px',
              padding: '6px 12px',
              cursor: 'pointer'
            }}
          >
            Close
          </button>
        </div>

        {/* View Mode Tabs */}
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.75rem' }}>
          <button
            onClick={() => setActiveTab('domains')}
            style={{
              background: activeTab === 'domains' ? 'rgba(255, 255, 255, 0.12)' : 'transparent',
              border: `1px solid ${activeTab === 'domains' ? '#ffffff' : 'rgba(255,255,255,0.1)'}`,
              color: activeTab === 'domains' ? '#ffffff' : '#94a3b8',
              borderRadius: '8px',
              padding: '8px 16px',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: 'pointer'
            }}
          >
            Target Domains ({submittedDomains.length})
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            style={{
              background: activeTab === 'audit' ? 'rgba(255, 255, 255, 0.12)' : 'transparent',
              border: `1px solid ${activeTab === 'audit' ? '#ffffff' : 'rgba(255,255,255,0.1)'}`,
              color: activeTab === 'audit' ? '#ffffff' : '#94a3b8',
              borderRadius: '8px',
              padding: '8px 16px',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: 'pointer'
            }}
          >
            Audit Trail ({auditLogs.length})
          </button>
        </div>

        {errorMsg && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#fca5a5', padding: '12px 16px', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            {errorMsg}
          </div>
        )}

        {successMsg && (
          <div style={{ background: 'rgba(56, 189, 248, 0.15)', border: '1px solid #38bdf8', color: '#38bdf8', padding: '12px 16px', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            {successMsg}
          </div>
        )}

        {activeTab === 'domains' ? (
          <>
            {/* Submit Form */}
            <form onSubmit={handleSubmitDomain} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: '12px', padding: '1.25rem', marginBottom: '2rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: 0, color: '#ffffff' }}>
                  Submit Target Website Domain
                </h3>
                <span style={{
                  fontSize: '0.8rem',
                  fontWeight: 700,
                  padding: '4px 10px',
                  borderRadius: '12px',
                  background: submissions24h >= 3 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.1)',
                  color: submissions24h >= 3 ? '#fca5a5' : '#e2e8f0',
                  border: `1px solid ${submissions24h >= 3 ? '#ef4444' : 'rgba(255,255,255,0.2)'}`
                }}>
                  Daily Quota: {submissions24h}/3 Used
                </span>
              </div>
              <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <input
                  type="text"
                  required
                  placeholder="e.g. example.com or https://target-site.com"
                  value={domainInput}
                  onChange={(e) => setDomainInput(e.target.value)}
                  style={{
                    flex: '1 1 280px',
                    background: '#000000',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '8px',
                    padding: '10px 14px',
                    color: '#ffffff',
                    fontSize: '0.95rem'
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
                    fontSize: '0.95rem'
                  }}
                >
                  <option value="dns_txt">DNS TXT Record</option>
                  <option value="file">File-Based HTTP Upload</option>
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
                    cursor: 'pointer'
                  }}
                >
                  {loading ? 'Submitting...' : 'Generate Challenge Token'}
                </button>
              </div>
            </form>

            {/* List of Submitted Domains */}
            <div style={{ marginBottom: '2rem' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700, margin: '0 0 1rem 0', color: '#ffffff' }}>
                Scoped Target Domains ({submittedDomains.length})
              </h3>
              {submittedDomains.length === 0 ? (
                <p style={{ color: '#64748b', fontSize: '0.9rem', fontStyle: 'italic' }}>
                  No custom domain targets submitted yet. Local default policy targets (e.g. localhost:3000) remain pre-authorized.
                </p>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.75rem' }}>
                  {submittedDomains.map((d) => {
                    const isSelected = selectedDomain?.id === d.id;
                    const isVerified = d.status === 'VERIFIED';
                    const isFailed = d.status === 'FAILED';
                    return (
                      <div
                        key={d.id}
                        onClick={() => setSelectedDomain(d)}
                        style={{
                          background: isSelected ? 'rgba(255, 255, 255, 0.1)' : 'rgba(255,255,255,0.02)',
                          border: `1px solid ${isSelected ? '#ffffff' : 'rgba(255,255,255,0.1)'}`,
                          borderRadius: '10px',
                          padding: '12px',
                          cursor: 'pointer',
                          transition: 'all 0.2s ease'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                          <span style={{ fontWeight: 700, fontSize: '0.95rem', color: '#ffffff' }}>{d.domain}</span>
                          <span style={{
                            fontSize: '0.75rem',
                            fontWeight: 800,
                            padding: '2px 8px',
                            borderRadius: '12px',
                            background: isVerified ? 'rgba(56, 189, 248, 0.2)' : isFailed ? 'rgba(239, 68, 68, 0.2)' : 'rgba(251, 191, 36, 0.2)',
                            color: isVerified ? '#38bdf8' : isFailed ? '#ef4444' : '#fbbf24',
                            border: `1px solid ${isVerified ? '#38bdf8' : isFailed ? '#ef4444' : '#fbbf24'}`
                          }}>
                            {d.status}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                          Method: {d.verification_method === 'dns_txt' ? 'DNS TXT' : 'HTTP File'}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Active Domain Verification Step-by-Step Instructions */}
            {selectedDomain && (
              <div style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                borderRadius: '12px',
                padding: '1.5rem'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                  <h4 style={{ margin: 0, color: '#ffffff', fontSize: '1.1rem', fontWeight: 800 }}>
                    Verification Instructions for: {selectedDomain.domain}
                  </h4>
                  <button
                    onClick={() => handleDeleteDomain(selectedDomain.id)}
                    style={{ background: 'transparent', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '0.85rem' }}
                  >
                    Remove Target
                  </button>
                </div>

                <div style={{ display: 'flex', gap: '1rem', marginBottom: '1.25rem' }}>
                  <button
                    onClick={() => setSelectedDomain({ ...selectedDomain, verification_method: 'dns_txt' })}
                    style={{
                      padding: '6px 14px',
                      borderRadius: '6px',
                      border: '1px solid #ffffff',
                      background: selectedDomain.verification_method === 'dns_txt' ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      color: '#ffffff',
                      fontSize: '0.85rem',
                      cursor: 'pointer'
                    }}
                  >
                    Option A: DNS TXT
                  </button>
                  <button
                    onClick={() => setSelectedDomain({ ...selectedDomain, verification_method: 'file' })}
                    style={{
                      padding: '6px 14px',
                      borderRadius: '6px',
                      border: '1px solid #ffffff',
                      background: selectedDomain.verification_method === 'file' ? 'rgba(255, 255, 255, 0.15)' : 'transparent',
                      color: '#ffffff',
                      fontSize: '0.85rem',
                      cursor: 'pointer'
                    }}
                  >
                    Option B: HTTP File Upload
                  </button>
                </div>

                {selectedDomain.verification_method === 'dns_txt' ? (
                  <div style={{ fontSize: '0.9rem', lineHeight: 1.6, color: '#cbd5e1' }}>
                    <p>1. Access your DNS provider dashboard (Cloudflare, Route53, GoDaddy, etc.).</p>
                    <p>2. Add a new <strong>TXT Record</strong> with the following details:</p>
                    <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', fontFamily: 'monospace', margin: '8px 0' }}>
                      <strong>Record Name / Host:</strong> {selectedDomain.dns_txt_record_name}<br />
                      <strong>Record Value / Content:</strong> {selectedDomain.dns_txt_record_value}
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: '0.9rem', lineHeight: 1.6, color: '#cbd5e1' }}>
                    <p>1. Create a plain text file on your web server at the path:</p>
                    <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', fontFamily: 'monospace', margin: '8px 0' }}>
                      {selectedDomain.file_verification_url}
                    </div>
                    <p>2. Set the file contents to your challenge token:</p>
                    <div style={{ background: '#000000', padding: '10px 14px', borderRadius: '8px', fontFamily: 'monospace', margin: '8px 0' }}>
                      {selectedDomain.file_verification_content}
                    </div>
                  </div>
                )}

                <div style={{ marginTop: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
                  <button
                    onClick={() => handleVerifyNow(selectedDomain.id)}
                    disabled={loading}
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
                    {loading ? ' Checking Ownership...' : ' Verify Ownership Now'}
                  </button>

                  <span style={{ fontSize: '0.85rem', color: selectedDomain.status === 'VERIFIED' ? '#38bdf8' : '#94a3b8' }}>
                    Current Status: <strong>{selectedDomain.status}</strong>
                  </span>
                </div>
              </div>
            )}
          </>
        ) : (
          /* Audit Trail Table View */
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
              Domain Verification Audit Trail Logs
            </h3>
            {auditLogs.length === 0 ? (
              <p style={{ color: '#94a3b8', fontStyle: 'italic' }}>No audit log entries recorded yet.</p>
            ) : (
              <div style={{ overflowX: 'auto', background: 'rgba(0,0,0,0.4)', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
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
                      const isPass = log.result === 'VERIFIED' || log.result === 'SUBMITTED';
                      const isRateLim = log.result === 'RATE_LIMITED';
                      const isFail = log.result === 'FAILED';
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
                              fontSize: '0.75rem',
                              fontWeight: 800,
                              padding: '2px 8px',
                              borderRadius: '12px',
                              background: isPass ? 'rgba(56, 189, 248, 0.2)' : isRateLim ? 'rgba(251, 191, 36, 0.2)' : 'rgba(239, 68, 68, 0.2)',
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

