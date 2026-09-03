import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, Database, Users, Trash2, CheckCircle, XCircle, 
  RotateCw, RefreshCw, Cpu, HardDrive, FileText, Server, AlertTriangle
} from 'lucide-react';

export default function AdminPanelModal({ isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('db_telemetry');
  const [stats, setStats] = useState(null);
  const [usersList, setUsersList] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const getHeaders = () => {
    const token = localStorage.getItem('nkat_jwt_token');
    return {
      'Content-Type': 'application/json',
      'X-API-Key': 'nkat_secret_api_key_2026',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    };
  };

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/admin/stats', { headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (err) {
      console.error('Failed to fetch admin stats:', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/v1/admin/users', { headers: getHeaders() });
      if (res.ok) {
        const data = await res.json();
        setUsersList(data);
      }
    } catch (err) {
      console.error('Failed to fetch platform users:', err);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchStats();
      fetchUsers();
    }
  }, [isOpen]);

  const handleRoleChange = async (userId, newRole) => {
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await fetch(`/api/v1/admin/users/${userId}/role`, {
        method: 'PATCH',
        headers: getHeaders(),
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        setSuccessMsg(`Updated user #${userId} role to '${newRole}'.`);
        fetchUsers();
      } else {
        const err = await res.json();
        setErrorMsg(err.detail || 'Failed to update user role.');
      }
    } catch (err) {
      setErrorMsg('Error updating role: ' + err.message);
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Are you sure you want to delete user account '${username}'?`)) return;
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await fetch(`/api/v1/admin/users/${userId}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        setSuccessMsg(`Deleted user '${username}' successfully.`);
        fetchUsers();
        fetchStats();
      } else {
        const err = await res.json();
        setErrorMsg(err.detail || 'Failed to delete user.');
      }
    } catch (err) {
      setErrorMsg('Error deleting user: ' + err.message);
    }
  };

  const handleBulkApprove = async () => {
    if (!window.confirm('Approve ALL open vulnerability findings across all scans?')) return;
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('/api/v1/admin/findings/bulk-approve', {
        method: 'POST',
        headers: getHeaders()
      });
      const data = await res.json();
      setSuccessMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrorMsg('Error executing bulk approval: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBulkReject = async () => {
    if (!window.confirm('Reject ALL open vulnerability findings?')) return;
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('/api/v1/admin/findings/bulk-reject', {
        method: 'POST',
        headers: getHeaders()
      });
      const data = await res.json();
      setSuccessMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrorMsg('Error executing bulk rejection: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePurgeScans = async () => {
    if (!window.confirm('Purge all old scan history (keeping only the latest scan)?')) return;
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('/api/v1/admin/scans/purge', {
        method: 'POST',
        headers: getHeaders()
      });
      const data = await res.json();
      setSuccessMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrorMsg('Error purging scans: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRetrainML = async () => {
    setLoading(true);
    setErrorMsg('');
    try {
      const res = await fetch('/api/v1/admin/ml/retrain', {
        method: 'POST',
        headers: getHeaders()
      });
      const data = await res.json();
      if (data.status === 'success') {
        setSuccessMsg(data.message);
      } else {
        setErrorMsg(data.message);
      }
      fetchStats();
    } catch (err) {
      setErrorMsg('Error triggering ML retraining: ' + err.message);
    } finally {
      setLoading(false);
    }
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
      background: 'rgba(4, 6, 10, 0.88)',
      backdropFilter: 'blur(12px)'
    }}>
      <div style={{
        width: '92%',
        maxWidth: '960px',
        maxHeight: '90vh',
        overflowY: 'auto',
        background: 'rgba(10, 10, 10, 0.98)',
        border: '2px solid #000000',
        borderRadius: '20px',
        padding: '2.5rem',
        boxShadow: '0 25px 60px rgba(0,0,0,0.9)',
        color: '#ffffff'
      }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <ShieldAlert size={26} color="#ef4444" />
              <h2 style={{ fontSize: '1.75rem', fontWeight: 900, color: '#ffffff', margin: 0, letterSpacing: '-0.4px' }}>
                NKAT Enterprise Admin Control Panel
              </h2>
            </div>
            <p style={{ color: '#94a3b8', fontSize: '0.9rem', margin: '4px 0 0 0' }}>
              Full platform governance, user access management, policy overrides & live database telemetry.
            </p>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: '2px solid #000000',
              color: '#ffffff',
              borderRadius: '8px',
              padding: '6px 14px',
              cursor: 'pointer',
              fontWeight: 700
            }}
          >
            Close
          </button>
        </div>

        {/* Tab Selection Navigation */}
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', borderBottom: '2px solid #000000', paddingBottom: '0.75rem' }}>
          <button
            onClick={() => setActiveTab('db_telemetry')}
            style={{
              background: activeTab === 'db_telemetry' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
              border: `2px solid ${activeTab === 'db_telemetry' ? '#ef4444' : '#000000'}`,
              color: activeTab === 'db_telemetry' ? '#ef4444' : '#ffffff',
              borderRadius: '8px',
              padding: '8px 16px',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Database size={16} /> Database & System Telemetry
          </button>
          <button
            onClick={() => setActiveTab('users')}
            style={{
              background: activeTab === 'users' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
              border: `2px solid ${activeTab === 'users' ? '#ef4444' : '#000000'}`,
              color: activeTab === 'users' ? '#ef4444' : '#ffffff',
              borderRadius: '8px',
              padding: '8px 16px',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <Users size={16} /> User Accounts ({usersList.length})
          </button>
          <button
            onClick={() => setActiveTab('overrides')}
            style={{
              background: activeTab === 'overrides' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
              border: `2px solid ${activeTab === 'overrides' ? '#ef4444' : '#000000'}`,
              color: activeTab === 'overrides' ? '#ef4444' : '#ffffff',
              borderRadius: '8px',
              padding: '8px 16px',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}
          >
            <ShieldAlert size={16} /> Policy & Bulk Controls
          </button>
        </div>

        {/* Feedback Notifications */}
        {errorMsg && (
          <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#fca5a5', padding: '12px 16px', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            {errorMsg}
          </div>
        )}
        {successMsg && (
          <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', color: '#6ee7b7', padding: '12px 16px', borderRadius: '8px', marginBottom: '1.25rem', fontSize: '0.9rem' }}>
            {successMsg}
          </div>
        )}

        {/* TAB 1: Database & System Telemetry */}
        {activeTab === 'db_telemetry' && (
          <div>
            <div style={{ background: 'rgba(10, 10, 10, 0.9)', border: '1px solid rgba(255, 255, 255, 0.15)', borderRadius: '14px', padding: '1.5rem', marginBottom: '1.5rem' }}>
              <h3 style={{ margin: '0 0 1rem 0', color: '#ffffff', fontSize: '1.1rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <HardDrive size={18} /> Active Database File & Location Settings
              </h3>
              
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', fontSize: '0.9rem' }}>
                <div style={{ background: '#000000', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 700 }}>DATABASE FILE PATH</div>
                  <div className="mono-text" style={{ color: '#ffffff', wordBreak: 'break-all', marginTop: '4px', fontWeight: 700 }}>
                    {stats ? stats.database_file_path : 'c:\\Users\\hp\\Downloads\\web-vuln-platform\\nkat_dev.db'}
                  </div>
                </div>

                <div style={{ background: '#000000', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 700 }}>ENGINE TYPE & PROTOCOL</div>
                  <div style={{ color: '#ffffff', marginTop: '4px', fontWeight: 700 }}>
                    {stats ? stats.database_type : 'SQLite Local / PostgreSQL Driver'}
                  </div>
                </div>

                <div style={{ background: '#000000', padding: '12px 16px', borderRadius: '10px', border: '1px solid rgba(255,255,255,0.08)' }}>
                  <div style={{ color: '#94a3b8', fontSize: '0.78rem', fontWeight: 700 }}>CURRENT DB DISK SIZE</div>
                  <div className="mono-text" style={{ color: '#34d399', marginTop: '4px', fontWeight: 800, fontSize: '1.1rem' }}>
                    {stats ? `${stats.database_size_mb} MB (${stats.database_size_bytes.toLocaleString()} bytes)` : '0.52 MB'}
                  </div>
                </div>
              </div>
            </div>

            {/* Live Database Record Metrics */}
            <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
              Database Table Telemetry & Record Counts
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.1)', padding: '1.2rem', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700 }}>TOTAL USERS</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff', marginTop: '4px' }}>{stats ? stats.total_users : 0}</div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.1)', padding: '1.2rem', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700 }}>TOTAL SCANS</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff', marginTop: '4px' }}>{stats ? stats.total_scans : 0}</div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '2px solid #000000', padding: '1.2rem', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700 }}>TOTAL FINDINGS</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ef4444', marginTop: '4px' }}>{stats ? stats.total_findings : 0}</div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '2px solid #000000', padding: '1.2rem', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700 }}>APPROVED FINDINGS</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#10b981', marginTop: '4px' }}>{stats ? stats.total_approved_findings : 0}</div>
              </div>

              <div style={{ background: 'rgba(255,255,255,0.03)', border: '2px solid #000000', padding: '1.2rem', borderRadius: '12px' }}>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700 }}>ML FEEDBACK LABELS</div>
                <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ffffff', marginTop: '4px' }}>{stats ? stats.total_feedback_labels : 0}</div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: User Account & Role Controls */}
        {activeTab === 'users' && (
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
              User Account Governance & Role Scoping
            </h3>

            <div style={{ overflowX: 'auto', background: '#000000', borderRadius: '12px', border: '2px solid #000000' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
                <thead>
                  <tr style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', borderBottom: '2px solid #000000' }}>
                    <th style={{ padding: '12px 16px' }}>User ID</th>
                    <th style={{ padding: '12px 16px' }}>Username</th>
                    <th style={{ padding: '12px 16px' }}>Email</th>
                    <th style={{ padding: '12px 16px' }}>Current Role</th>
                    <th style={{ padding: '12px 16px' }}>Organization</th>
                    <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {usersList.map(u => (
                    <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                      <td style={{ padding: '12px 16px', color: '#94a3b8' }}>#{u.id}</td>
                      <td style={{ padding: '12px 16px', fontWeight: 700, color: '#ffffff' }}>{u.username}</td>
                      <td style={{ padding: '12px 16px', color: '#cbd5e1' }}>{u.email || '-'}</td>
                      <td style={{ padding: '12px 16px' }}>
                        <span style={{
                          padding: '3px 10px',
                          borderRadius: '12px',
                          fontWeight: 800,
                          fontSize: '0.75rem',
                          background: u.role === 'admin' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255, 255, 255, 0.1)',
                          color: u.role === 'admin' ? '#ef4444' : '#ffffff',
                          border: `1px solid ${u.role === 'admin' ? '#ef4444' : 'rgba(255,255,255,0.2)'}`
                        }}>
                          {u.role.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', color: '#94a3b8' }}>{u.organization_name}</td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          {u.role === 'analyst' ? (
                            <button
                              onClick={() => handleRoleChange(u.id, 'admin')}
                              style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', color: '#ef4444', borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem', cursor: 'pointer', fontWeight: 700 }}
                            >
                              Promote Admin
                            </button>
                          ) : (
                            <button
                              onClick={() => handleRoleChange(u.id, 'analyst')}
                              style={{ background: 'rgba(255, 255, 255, 0.1)', border: '1px solid rgba(255,255,255,0.2)', color: '#ffffff', borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem', cursor: 'pointer', fontWeight: 700 }}
                            >
                              Set Analyst
                            </button>
                          )}
                          {u.username !== 'admin' && (
                            <button
                              onClick={() => handleDeleteUser(u.id, u.username)}
                              style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#fca5a5', borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem', cursor: 'pointer', fontWeight: 700 }}
                            >
                              <Trash2 size={13} style={{ display: 'inline', verticalAlign: 'middle' }} /> Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 3: Policy & Bulk Controls */}
        {activeTab === 'overrides' && (
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
              Global Administrative Actions & Policy Overrides
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
              <div style={{ background: '#000000', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: '12px', padding: '1.25rem' }}>
                <h4 style={{ color: '#34d399', margin: '0 0 8px 0', fontSize: '1rem', fontWeight: 800 }}> Bulk Approve All Findings</h4>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  Instantly approve all currently open vulnerability findings across all targets with admin override logging.
                </p>
                <button
                  onClick={handleBulkApprove}
                  disabled={loading}
                  style={{ background: '#10b981', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '8px 16px', fontWeight: 800, fontSize: '0.85rem', cursor: 'pointer', marginTop: '10px' }}
                >
                  Approve All Findings
                </button>
              </div>

              <div style={{ background: '#000000', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1.25rem' }}>
                <h4 style={{ color: '#fca5a5', margin: '0 0 8px 0', fontSize: '1rem', fontWeight: 800 }}> Bulk Reject All Findings</h4>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  Bulk reject all currently open findings to clear active telemetry stream.
                </p>
                <button
                  onClick={handleBulkReject}
                  disabled={loading}
                  style={{ background: '#ef4444', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '8px 16px', fontWeight: 800, fontSize: '0.85rem', cursor: 'pointer', marginTop: '10px' }}
                >
                  Reject All Findings
                </button>
              </div>

              <div style={{ background: '#000000', border: '1px solid rgba(255, 255, 255, 0.2)', borderRadius: '12px', padding: '1.25rem' }}>
                <h4 style={{ color: '#ffffff', margin: '0 0 8px 0', fontSize: '1rem', fontWeight: 800 }}> Purge Historical Scans</h4>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  Clean up database storage by purging past historical scan runs, keeping only the most recent scan.
                </p>
                <button
                  onClick={handlePurgeScans}
                  disabled={loading}
                  style={{ background: '#334155', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '8px 16px', fontWeight: 800, fontSize: '0.85rem', cursor: 'pointer', marginTop: '10px' }}
                >
                  Purge Old Scans
                </button>
              </div>

              <div style={{ background: '#090d16', border: '2px solid #000000', borderRadius: '12px', padding: '1.25rem' }}>
                <h4 style={{ color: '#ffffff', margin: '0 0 8px 0', fontSize: '1rem', fontWeight: 800 }}> Retrain ML Classifier</h4>
                <p style={{ fontSize: '0.82rem', color: '#94a3b8', lineHeight: 1.5 }}>
                  Execute automated machine learning retraining script (`retrain_from_feedback.py`) on human approvals.
                </p>
                <button
                  onClick={handleRetrainML}
                  disabled={loading}
                  style={{ background: '#ef4444', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '8px 16px', fontWeight: 800, fontSize: '0.85rem', cursor: 'pointer', marginTop: '10px' }}
                >
                  Retrain ML Model Now
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
