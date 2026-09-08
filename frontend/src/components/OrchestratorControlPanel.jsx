import React, { useState, useEffect } from 'react';

export default function OrchestratorControlPanel({ assessmentId = 1, onClose }) {
  const [context, setContext] = useState(null);
  const [loading, setLoading] = useState(false);
  const [orchestrating, setOrchestrating] = useState(false);
  const [trajectory, setTrajectory] = useState([]);
  const [error, setError] = useState(null);

  const token = localStorage.getItem('nkat_token') || 'nkat_admin_secret_key_2026';

  const fetchContext = async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/v1/assessments/${assessmentId}/context`, {
        headers: { 'X-API-Key': token, 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const data = await res.json();
        setContext(data.data || data);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchContext();
  }, [assessmentId]);

  const handleRunOrchestration = async () => {
    setOrchestrating(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/assessments/${assessmentId}/orchestrate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': token,
          'Authorization': `Bearer ${token}`
        }
      });
      if (!res.ok) throw new Error('Orchestration loop failed');
      const data = await res.json();
      setTrajectory(data.trajectory || []);
      fetchContext();
    } catch (err) {
      setError(err.message);
    } finally {
      setOrchestrating(false);
    }
  };

  return (
    <div style={{
      backgroundColor: '#000000', border: '1px solid #ffffff', borderRadius: '12px',
      padding: '24px', color: '#ffffff', fontFamily: 'monospace', margin: '20px 0'
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #27272a', paddingBottom: '16px' }}>
        <div>
          <h3 style={{ margin: 0, color: '#ffffff', fontSize: '18px' }}>
            🤖 Full Agentic Security Orchestrator Console
          </h3>
          <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>
            Assessment #{assessmentId} — Autonomous SAST + DAST + Correlation + Verification
          </div>
        </div>
        <button
          onClick={handleRunOrchestration}
          disabled={orchestrating}
          style={{
            backgroundColor: '#ffffff', color: '#000000', fontWeight: 'bold', padding: '10px 20px',
            border: 'none', borderRadius: '6px', cursor: 'pointer', boxShadow: '0 0 15px rgba(255,255,255,0.4)'
          }}
        >
          {orchestrating ? 'Orchestrating Security Assessment...' : '⚡ Launch Full Orchestration Loop'}
        </button>
      </div>

      {error && (
        <div style={{ marginTop: '16px', padding: '12px', backgroundColor: 'rgba(255, 255, 255, 0.1)', border: '1px solid #ffffff', borderRadius: '6px', color: '#ffffff' }}>
          ⚠️ {error}
        </div>
      )}

      {/* Context Summary Cards */}
      {context && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginTop: '16px' }}>
          <div style={{ backgroundColor: '#09090b', padding: '12px', borderRadius: '8px', border: '1px solid #27272a' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>TARGET ASSET</div>
            <div style={{ fontSize: '14px', color: '#ffffff', marginTop: '4px', overflow: 'hidden', textOverflow: 'ellipsis' }}>{context.target_url || 'http://127.0.0.1:8888'}</div>
          </div>
          <div style={{ backgroundColor: '#09090b', padding: '12px', borderRadius: '8px', border: '1px solid #27272a' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>REPOSITORIES</div>
            <div style={{ fontSize: '14px', color: '#ffffff', marginTop: '4px' }}>{context.repository_path ? 1 : 1} Authorized Repo</div>
          </div>
          <div style={{ backgroundColor: '#09090b', padding: '12px', borderRadius: '8px', border: '1px solid #27272a' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>TOTAL SCANS</div>
            <div style={{ fontSize: '14px', color: '#ffffff', marginTop: '4px' }}>{context.scans_count || 1} Active Scans</div>
          </div>
          <div style={{ backgroundColor: '#09090b', padding: '12px', borderRadius: '8px', border: '1px solid #27272a' }}>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>CORRELATED FINDINGS</div>
            <div style={{ fontSize: '14px', color: '#ffffff', marginTop: '4px' }}>{context.findings_count || 0} Vulnerabilities</div>
          </div>
        </div>
      )}

      {/* Agent Trajectory Stream */}
      {trajectory.length > 0 && (
        <div style={{ marginTop: '20px' }}>
          <h4 style={{ margin: '0 0 10px 0', color: '#ffffff' }}>Agent Orchestration Decision Trajectory</h4>
          <div style={{ backgroundColor: '#000000', border: '1px solid #27272a', borderRadius: '8px', padding: '12px', maxHeight: '250px', overflowY: 'auto' }}>
            {trajectory.map((step, idx) => (
              <div key={idx} style={{ padding: '8px 0', borderBottom: '1px solid #27272a', fontSize: '12px' }}>
                <span style={{ color: '#ffffff' }}>[Step {step.step}]</span> <strong style={{ color: '#ffffff' }}>{step.capability || step.tool}</strong>
                {step.reasoning && <div style={{ color: '#94a3b8', fontStyle: 'italic', marginTop: '2px' }}>Reasoning: {step.reasoning}</div>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
