import React, { useState } from 'react';

export default function RemediationModal({ finding, onClose, onRefresh }) {
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(false);
  const [error, setError] = useState(null);

  const token = localStorage.getItem('nkat_token') || 'nkat_admin_secret_key_2026';

  const handleAnalyze = async () => {
    setLoading(true);
    setError(null);
    try:
      const res = await fetch(`/api/v1/remediations/analyze/${finding.id}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': token,
          'Authorization': `Bearer ${token}`
        }
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Failed to analyze finding remediation.');
      }
      const data = await res.json();
      setRemediation(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleApplyAndValidate = async () => {
    if (!remediation) return;
    setValidating(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/remediations/${remediation.id}/apply-and-validate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': token,
          'Authorization': `Bearer ${token}`
        }
      });
      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Validation failed.');
      }
      const data = await res.json();
      setRemediation(prev => ({ ...prev, status: data.status, validation_status: JSON.stringify(data.validation_results) }));
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setValidating(false);
    }
  };

  const handleRollback = async () => {
    if (!remediation) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/remediations/${remediation.id}/rollback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': token,
          'Authorization': `Bearer ${token}`
        }
      });
      const data = await res.json();
      setRemediation(prev => ({ ...prev, status: data.status }));
      if (onRefresh) onRefresh();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const valStatus = remediation?.validation_status ? JSON.parse(remediation.validation_status) : null;

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(5, 10, 20, 0.85)', backdropFilter: 'blur(10px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 10000
    }}>
      <div style={{
        width: '800px', maxHeight: '90vh', overflowY: 'auto',
        backgroundColor: '#0b1329', border: '1px solid #00f0ff', borderRadius: '12px',
        boxShadow: '0 0 30px rgba(0, 240, 255, 0.2)', padding: '24px', color: '#e0f7fc', fontFamily: 'monospace'
      }}>
        {/* Modal Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '16px' }}>
          <div>
            <h2 style={{ margin: 0, color: '#00f0ff', fontSize: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              🛡️ End-to-End Remediation & Security Verification
            </h2>
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
              Finding #{finding.id} — {finding.check_name}
            </div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '20px', cursor: 'pointer' }}>✕</button>
        </div>

        {error && (
          <div style={{ marginTop: '16px', padding: '12px', backgroundColor: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '6px', color: '#fca5a5' }}>
            ⚠️ Error: {error}
          </div>
        )}

        {/* State 1: Analysis Trigger */}
        {!remediation && (
          <div style={{ padding: '32px 0', textAlign: 'center' }}>
            <p style={{ color: '#cbd5e1', marginBottom: '20px' }}>
              Initiate structured root-cause analysis, source mapping, and Git patch generation for this finding.
            </p>
            <button
              onClick={handleAnalyze}
              disabled={loading}
              style={{
                backgroundColor: '#00f0ff', color: '#050b14', fontWeight: 'bold', padding: '12px 24px',
                border: 'none', borderRadius: '6px', cursor: 'pointer', boxShadow: '0 0 15px rgba(0,240,255,0.4)'
              }}
            >
              {loading ? 'Analyzing Source & Generating Patch...' : '⚡ Trigger AI Root-Cause Analysis'}
            </button>
          </div>
        )}

        {/* State 2: Remediation Details & Patch Diff */}
        {remediation && (
          <div style={{ marginTop: '20px' }}>
            {/* Metadata Card */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', backgroundColor: '#09090b', padding: '16px', borderRadius: '8px', border: '1px solid #27272a' }}>
              <div><strong style={{ color: '#ffffff' }}>Status:</strong> <span style={{ color: remediation.status === 'VERIFIED' ? '#ffffff' : '#eab308' }}>{remediation.status}</span></div>
              <div><strong style={{ color: '#ffffff' }}>Target File:</strong> {remediation.affected_file || 'Unmapped'}</div>
              <div><strong style={{ color: '#ffffff' }}>Target Function:</strong> {remediation.affected_function || 'N/A'}</div>
              <div><strong style={{ color: '#ffffff' }}>Vulnerable Line:</strong> #{remediation.vulnerable_line || 'N/A'}</div>
            </div>

            {/* Root Cause */}
            <div style={{ marginTop: '16px' }}>
              <h4 style={{ margin: '0 0 6px 0', color: '#ffffff' }}>Root Cause Analysis</h4>
              <p style={{ margin: 0, fontSize: '13px', color: '#cbd5e1', backgroundColor: '#09090b', padding: '10px', borderRadius: '6px', border: '1px solid #27272a' }}>
                {remediation.root_cause}
              </p>
            </div>

            {/* Patch Diff Viewer */}
            {remediation.patch && (
              <div style={{ marginTop: '16px' }}>
                <h4 style={{ margin: '0 0 6px 0', color: '#ffffff' }}>Generated Unified Git Diff Patch</h4>
                <pre style={{
                  backgroundColor: '#000000', border: '1px solid #27272a', borderRadius: '6px',
                  padding: '12px', fontSize: '12px', overflowX: 'auto', color: '#ffffff'
                }}>
                  {remediation.patch}
                </pre>
              </div>
            )}

            {/* Validation Matrix */}
            {valStatus && (
              <div style={{ marginTop: '16px', backgroundColor: '#09090b', padding: '16px', borderRadius: '8px', border: '1px solid #27272a' }}>
                <h4 style={{ margin: '0 0 10px 0', color: '#ffffff' }}>End-to-End Security Verification Matrix</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '13px' }}>
                  <div>Syntax Check: <span style={{ color: valStatus.syntax.includes('PASSED') ? '#ffffff' : '#ef4444' }}>{valStatus.syntax}</span></div>
                  <div>Unit Tests: <span style={{ color: valStatus.tests.includes('PASSED') ? '#ffffff' : '#ef4444' }}>{valStatus.tests}</span></div>
                  <div>SAST Scan: <span style={{ color: valStatus.sast.includes('PASSED') ? '#ffffff' : '#ef4444' }}>{valStatus.sast}</span></div>
                  <div>DAST Rescan: <span style={{ color: valStatus.dast.includes('PASSED') ? '#ffffff' : '#ef4444' }}>{valStatus.dast}</span></div>
                  <div style={{ gridColumn: 'span 2' }}>Regression Check: <span style={{ color: valStatus.regression.includes('PASSED') ? '#ffffff' : '#ef4444' }}>{valStatus.regression}</span></div>
                </div>
              </div>
            )}

            {/* Action Bar */}
            <div style={{ marginTop: '24px', display: 'flex', justifyContent: 'flex-end', gap: '12px', borderTop: '1px solid #1e293b', paddingTop: '16px' }}>
              {remediation.status !== 'VERIFIED' && (
                <button
                  onClick={handleApplyAndValidate}
                  disabled={validating}
                  style={{
                    backgroundColor: '#4ade80', color: '#050b14', fontWeight: 'bold', padding: '10px 20px',
                    border: 'none', borderRadius: '6px', cursor: 'pointer', boxShadow: '0 0 15px rgba(74,222,128,0.3)'
                  }}
                >
                  {validating ? 'Applying & Running Security Rescan...' : '🚀 Apply Patch & Execute DAST Rescan'}
                </button>
              )}

              {remediation.status === 'VERIFIED' && (
                <div style={{ backgroundColor: 'rgba(74, 222, 128, 0.15)', color: '#4ade80', border: '1px solid #4ade80', padding: '8px 16px', borderRadius: '6px', fontWeight: 'bold' }}>
                  ✓ VERIFIED & RESOLVED
                </div>
              )}

              <button
                onClick={handleRollback}
                disabled={loading}
                style={{ backgroundColor: '#334155', color: '#f1f5f9', padding: '10px 16px', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
              >
                ↩ Rollback Git State
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
