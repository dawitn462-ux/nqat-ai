import React, { useState, useEffect } from 'react';
import CrowdStrikeHomepage from './CrowdStrikeHomepage';
import { 
  ShieldAlert, Database, Users, Trash2, PlusCircle, Edit3, 
  CheckCircle, XCircle, HardDrive, RefreshCw, Layers, ShieldCheck,
  FileText, Cpu, AlertTriangle, Eye, ArrowRight, LayoutDashboard, Terminal,
  Image, Video, Upload, Zap
} from 'lucide-react';

export default function AdminDashboardPage({ user, onLogout }) {
  const [activeTab, setActiveTab] = useState('posts_manager');
  const [viewConsoleMode, setViewConsoleMode] = useState(false);

  // Stats & Users state
  const [stats, setStats] = useState(null);
  const [usersList, setUsersList] = useState([]);
  const [postsList, setPostsList] = useState([]);

  // Post creation / editing state
  const [editingPostId, setEditingPostId] = useState(null);
  const [postForm, setPostForm] = useState({
    title: '',
    tag: 'ZERO-DAY ALERT',
    tag_color: '#ef4444',
    author: 'NKAT Security Intelligence Labs',
    read_time: '4 min read',
    image_url: '',
    video_url: '',
    snippet: '',
    content: ''
  });

  const [feedStatus, setFeedStatus] = useState(null);
  const [uploadingMedia, setUploadingMedia] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [errMsg, setErrMsg] = useState('');

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
      if (res.ok) setStats(await res.json());
    } catch (err) {
      console.error('Failed to fetch admin stats:', err);
    }
  };

  const fetchUsers = async () => {
    try {
      const res = await fetch('/api/v1/admin/users', { headers: getHeaders() });
      if (res.ok) setUsersList(await res.json());
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
  };

  const fetchPosts = async () => {
    try {
      const res = await fetch('/api/v1/posts', { headers: getHeaders() });
      if (res.ok) setPostsList(await res.json());
    } catch (err) {
      console.error('Failed to fetch posts:', err);
    }
  };

  const fetchFeedStatus = async () => {
    try {
      const res = await fetch('/api/v1/admin/threat-feed/status', { headers: getHeaders() });
      if (res.ok) setFeedStatus(await res.json());
    } catch (err) {
      console.error('Failed to fetch threat feed status:', err);
    }
  };

  const handleForceSyncThreatFeeds = async () => {
    setLoading(true);
    setStatusMsg('');
    setErrMsg('');
    try {
      const res = await fetch('/api/v1/admin/threat-feed/sync', { method: 'POST', headers: getHeaders() });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchFeedStatus();
      fetchStats();
    } catch (err) {
      setErrMsg('Threat feed sync error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const [wafData, setWafData] = useState(null);

  const fetchWafTraffic = async () => {
    try {
      const res = await fetch('/api/v1/admin/waf/live-traffic', { headers: getHeaders() });
      if (res.ok) setWafData(await res.json());
    } catch (err) {
      console.error('Failed to fetch WAF traffic:', err);
    }
  };

  const handleSimulateWafAttack = async (attackType) => {
    setLoading(true);
    setStatusMsg('');
    setErrMsg('');
    try {
      const res = await fetch('/api/v1/admin/waf/simulate-attack', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ attack_type: attackType })
      });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchWafTraffic();
    } catch (err) {
      setErrMsg('WAF simulation error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const [activityReport, setActivityReport] = useState(null);
  const [activityFilterUser, setActivityFilterUser] = useState('');
  const [activityFilterAction, setActivityFilterAction] = useState('');
  const [activityPage, setActivityPage] = useState(1);

  const [updatesReport, setUpdatesReport] = useState(null);

  const fetchActivityReport = async () => {
    try {
      let url = `/api/v1/admin/activity-report?page=${activityPage}&limit=15`;
      if (activityFilterUser) url += `&username=${encodeURIComponent(activityFilterUser)}`;
      if (activityFilterAction) url += `&action_type=${encodeURIComponent(activityFilterAction)}`;

      const res = await fetch(url, { headers: getHeaders() });
      if (res.ok) {
        setActivityReport(await res.json());
      }
    } catch (err) {
      console.error('Failed to fetch activity report:', err);
    }
  };

  const fetchUpdatesReport = async () => {
    try {
      const res = await fetch('/api/v1/admin/updates-report', { headers: getHeaders() });
      if (res.ok) setUpdatesReport(await res.json());
    } catch (err) {
      console.error('Failed to fetch updates report:', err);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchUsers();
    fetchPosts();
    fetchFeedStatus();
    fetchWafTraffic();
    fetchActivityReport();
    fetchUpdatesReport();
  }, []);

  useEffect(() => {
    let interval = null;
    if (activeTab === 'updates_report') {
      fetchUpdatesReport();
      interval = setInterval(() => {
        fetchUpdatesReport();
      }, 5000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeTab]);

  useEffect(() => {
    let interval = null;
    if (activeTab === 'activity_logs') {
      fetchActivityReport();
      interval = setInterval(() => {
        fetchActivityReport();
      }, 5000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeTab, activityPage, activityFilterUser, activityFilterAction]);

  useEffect(() => {
    let interval = null;
    if (activeTab === 'waf_traffic') {
      fetchWafTraffic();
      interval = setInterval(() => {
        fetchWafTraffic();
      }, 3000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [activeTab]);

  const handleFileUpload = async (event, type) => {
    const file = event.target.files[0];
    if (!file) return;

    setUploadingMedia(true);
    setErrMsg('');
    setStatusMsg('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/v1/posts/upload-media', {
        method: 'POST',
        headers: {
          'X-API-Key': 'nkat_secret_api_key_2026',
          ...(localStorage.getItem('nkat_jwt_token') ? { Authorization: `Bearer ${localStorage.getItem('nkat_jwt_token')}` } : {})
        },
        body: formData
      });

      if (res.ok) {
        const data = await res.json();
        if (type === 'image' || data.media_type === 'image') {
          setPostForm(prev => ({ ...prev, image_url: data.url }));
          setStatusMsg(`Uploaded photo '${file.name}' successfully!`);
        } else {
          setPostForm(prev => ({ ...prev, video_url: data.url }));
          setStatusMsg(`Uploaded video '${file.name}' successfully!`);
        }
      } else {
        const errData = await res.json();
        setErrMsg(errData.detail || 'Failed to upload media file.');
      }
    } catch (err) {
      setErrMsg('Media upload error: ' + err.message);
    } finally {
      setUploadingMedia(false);
    }
  };

  const handleCreateOrUpdatePost = async (e) => {
    e.preventDefault();
    if (!postForm.title.trim() || !postForm.snippet.trim()) {
      setErrMsg('Post Title and Snippet are required.');
      return;
    }

    setLoading(true);
    setErrMsg('');
    setStatusMsg('');

    try {
      const url = editingPostId ? `/api/v1/posts/${editingPostId}` : '/api/v1/posts';
      const method = editingPostId ? 'PUT' : 'POST';

      const res = await fetch(url, {
        method,
        headers: getHeaders(),
        body: JSON.stringify(postForm)
      });

      if (res.ok) {
        setStatusMsg(editingPostId ? 'Threat Post updated successfully!' : ' New Threat Advisory / News Post published to platform homepage!');
        setEditingPostId(null);
        setPostForm({
          title: '',
          tag: 'ZERO-DAY ALERT',
          tag_color: '#ef4444',
          author: 'NKAT Security Intelligence Labs',
          read_time: '4 min read',
          image_url: '',
          video_url: '',
          snippet: '',
          content: ''
        });
        fetchPosts();
      } else {
        const data = await res.json();
        setErrMsg(data.detail || 'Failed to save post.');
      }
    } catch (err) {
      setErrMsg('Error saving post: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleEditPost = (post) => {
    setEditingPostId(post.id);
    setPostForm({
      title: post.title,
      tag: post.tag,
      tag_color: post.tag_color,
      author: post.author,
      read_time: post.read_time,
      image_url: post.image_url || '',
      video_url: post.video_url || '',
      snippet: post.snippet,
      content: post.content || ''
    });
    window.scrollTo({ top: 300, behavior: 'smooth' });
  };

  const handleDeletePost = async (postId, title) => {
    if (!window.confirm(`Delete news post '${title}'?`)) return;
    try {
      const res = await fetch(`/api/v1/posts/${postId}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        setStatusMsg(`Deleted post #${postId}.`);
        fetchPosts();
      }
    } catch (err) {
      setErrMsg('Error deleting post: ' + err.message);
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      const res = await fetch(`/api/v1/admin/users/${userId}/role`, {
        method: 'PATCH',
        headers: getHeaders(),
        body: JSON.stringify({ role: newRole })
      });
      if (res.ok) {
        setStatusMsg(`Updated user #${userId} role to '${newRole}'.`);
        fetchUsers();
      }
    } catch (err) {
      setErrMsg('Role update error: ' + err.message);
    }
  };

  const handleDeleteUser = async (userId, username) => {
    if (!window.confirm(`Delete user '${username}'?`)) return;
    try {
      const res = await fetch(`/api/v1/admin/users/${userId}`, {
        method: 'DELETE',
        headers: getHeaders()
      });
      if (res.ok) {
        setStatusMsg(`Deleted user '${username}'.`);
        fetchUsers();
        fetchStats();
      }
    } catch (err) {
      setErrMsg('User delete error: ' + err.message);
    }
  };

  const handleBulkApprove = async () => {
    if (!window.confirm('Bulk approve ALL open vulnerability findings across all targets?')) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/admin/findings/bulk-approve', { method: 'POST', headers: getHeaders() });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrMsg('Bulk approve error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBulkReject = async () => {
    if (!window.confirm('Bulk reject ALL open findings?')) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/admin/findings/bulk-reject', { method: 'POST', headers: getHeaders() });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrMsg('Bulk reject error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handlePurgeScans = async () => {
    if (!window.confirm('Purge old scan records (keeping latest scan)?')) return;
    setLoading(true);
    try {
      const res = await fetch('/api/v1/admin/scans/purge', { method: 'POST', headers: getHeaders() });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrMsg('Purge scans error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRetrainML = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/admin/ml/retrain', { method: 'POST', headers: getHeaders() });
      const data = await res.json();
      setStatusMsg(data.message);
      fetchStats();
    } catch (err) {
      setErrMsg('ML Retrain error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  // If Admin toggles into Scan Console mode
  if (viewConsoleMode) {
    return (
      <div>
        <div style={{ background: '#000000', padding: '10px 3rem', borderBottom: '1px solid rgba(255, 255, 255, 0.2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ fontSize: '0.85rem', color: '#ef4444', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '8px' }}>
            ADMIN WORKSPACE — SCANNER AUDIT CONSOLE VIEW MODE
          </span>
          <button
            onClick={() => setViewConsoleMode(false)}
            style={{ background: '#ef4444', color: '#ffffff', border: '2px solid #000000', padding: '6px 14px', borderRadius: '6px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer' }}
          >
            ← Back to Admin Control Center
          </button>
        </div>
        <CrowdStrikeHomepage user={user} onLogout={onLogout} />
      </div>
    );
  }

  return (
    <div style={{ background: 'transparent', color: '#f8fafc', minHeight: '100vh', padding: '2rem 3rem', maxWidth: '1480px', margin: '0 auto' }}>
      
      {/* Super Admin Top Banner */}
      <section style={{
        background: 'rgba(10, 10, 10, 0.98)',
        border: '1.5px solid rgba(255, 255, 255, 0.2)',
        borderRadius: '20px',
        padding: '2.5rem 3rem',
        boxShadow: '0 20px 50px rgba(0,0,0,0.9), 0 0 30px rgba(255, 255, 255, 0.1)',
        marginBottom: '2.5rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1.5rem'
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
            <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', border: '2px solid #000000', padding: '4px 12px', borderRadius: '12px', fontWeight: 800, fontSize: '0.75rem', letterSpacing: '0.5px' }}>
              SUPER ADMIN CONTROL CENTER
            </span>
            <span className="mono-text" style={{ fontSize: '0.78rem', color: '#ffffff', background: 'rgba(255, 255, 255, 0.1)', padding: '4px 10px', borderRadius: '12px', border: '2px solid #000000' }}>
              Full Platform Master Privileges
            </span>
          </div>
          <h1 className="heading-font" style={{ fontSize: '2.5rem', fontWeight: 900, color: '#ffffff', margin: 0, letterSpacing: '-0.5px' }}>
            NKAT AI Administrator Management Hub
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '1rem', marginTop: '6px', marginBot: 0 }}>
            Active Session: <strong style={{ color: '#ffffff' }}>{user ? user.username : 'admin'}</strong> ({user ? user.email : 'admin@nkat.ai'}) | Organization: <strong style={{ color: '#10b981' }}>{user ? user.organization_name : 'Default Organization'}</strong>
          </p>
        </div>

        <div style={{ display: 'flex', gap: '1rem' }}>
          <button
            onClick={() => setViewConsoleMode(true)}
            className="btn-aegis-secondary"
            style={{ padding: '0.85rem 1.6rem', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '8px' }}
          >
            <Eye size={16} /> Switch to Scanner Console
          </button>
        </div>
      </section>

      {/* Status & Error Alerts */}
      {statusMsg && (
        <div style={{ background: 'rgba(16, 185, 129, 0.15)', border: '2px solid #000000', color: '#10b981', padding: '14px 20px', borderRadius: '12px', marginBottom: '2rem', fontSize: '0.92rem', fontWeight: 600 }}>
          {statusMsg}
        </div>
      )}
      {errMsg && (
        <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '2px solid #000000', color: '#ef4444', padding: '14px 20px', borderRadius: '12px', marginBottom: '2rem', fontSize: '0.92rem', fontWeight: 600 }}>
          {errMsg}
        </div>
      )}

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '2rem', flexWrap: 'wrap', borderBottom: '2px solid #000000', paddingBottom: '1rem' }}>
        <button
          onClick={() => setActiveTab('posts_manager')}
          style={{
            background: activeTab === 'posts_manager' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'posts_manager' ? '#ef4444' : '#000000'}`,
            color: activeTab === 'posts_manager' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <FileText size={18} /> Cyber News & Threat Posts Manager ({postsList.length})
        </button>

        <button
          onClick={() => setActiveTab('users')}
          style={{
            background: activeTab === 'users' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'users' ? '#ef4444' : '#000000'}`,
            color: activeTab === 'users' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <Users size={18} /> User Accounts & Roles ({usersList.length})
        </button>

        <button
          onClick={() => setActiveTab('overrides')}
          style={{
            background: activeTab === 'overrides' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'overrides' ? '#ef4444' : '#000000'}`,
            color: activeTab === 'overrides' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <ShieldAlert size={18} /> Policy & Vulnerability Batch Controls
        </button>

        <button
          onClick={() => setActiveTab('threat_feeds')}
          style={{
            background: activeTab === 'threat_feeds' ? 'rgba(255, 255, 255, 0.18)' : 'rgba(255,255,255,0.03)',
            border: `1.5px solid ${activeTab === 'threat_feeds' ? '#ffffff' : 'rgba(255,255,255,0.12)'}`,
            color: activeTab === 'threat_feeds' ? '#ffffff' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <ShieldCheck size={18} /> Real-Time Threat Feeds (CISA, NIST, EPSS)
        </button>

        <button
          onClick={() => setActiveTab('waf_traffic')}
          style={{
            background: activeTab === 'waf_traffic' ? 'rgba(239, 68, 68, 0.18)' : 'rgba(255,255,255,0.03)',
            border: `1.5px solid ${activeTab === 'waf_traffic' ? '#ef4444' : 'rgba(255,255,255,0.12)'}`,
            color: activeTab === 'waf_traffic' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <ShieldAlert size={18} /> WAF Live Traffic ({wafData ? wafData.total_requests : '0'})
        </button>

        <button
          onClick={() => setActiveTab('activity_logs')}
          style={{
            background: activeTab === 'activity_logs' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'activity_logs' ? '#ef4444' : '#000000'}`,
            color: activeTab === 'activity_logs' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <FileText size={18} /> Unified Activity & Audit Logs ({activityReport ? activityReport.total_records : '0'})
        </button>

        <button
          onClick={() => setActiveTab('updates_report')}
          style={{
            background: activeTab === 'updates_report' ? 'rgba(16, 185, 129, 0.18)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'updates_report' ? '#10b981' : '#000000'}`,
            color: activeTab === 'updates_report' ? '#10b981' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <RefreshCw size={18} /> Real System Updates Report ({updatesReport?.updates?.length || '0'})
        </button>

        <button
          onClick={() => setActiveTab('db_telemetry')}
          style={{
            background: activeTab === 'db_telemetry' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.03)',
            border: `2px solid ${activeTab === 'db_telemetry' ? '#ef4444' : '#000000'}`,
            color: activeTab === 'db_telemetry' ? '#ef4444' : '#94a3b8',
            borderRadius: '12px',
            padding: '12px 22px',
            fontWeight: 800,
            fontSize: '0.95rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}
        >
          <Database size={18} /> Database Telemetry & Storage
        </button>
      </div>

      {/* TAB 1: Cyber News & Threat Posts Manager */}
      {activeTab === 'posts_manager' && (
        <div>
          {/* Post Creation & Edit Form */}
          <div style={{ background: 'rgba(10, 10, 10, 0.95)', border: '1px solid rgba(255, 255, 255, 0.2)', borderRadius: '16px', padding: '2rem', marginBottom: '2.5rem' }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#ffffff', margin: '0 0 1.25rem 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              {editingPostId ? <Edit3 size={20} /> : <PlusCircle size={20} />} 
              {editingPostId ? `Edit Threat Advisory Post #${editingPostId}` : 'Publish New Cyber Security Advisory / News Post'}
            </h3>

            <form onSubmit={handleCreateOrUpdatePost} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>POST TITLE</label>
                  <input
                    type="text"
                    required
                    value={postForm.title}
                    onChange={e => setPostForm({ ...postForm, title: e.target.value })}
                    placeholder="e.g. CISA KEV Sync: New Zero-Day Web Vulnerability Advisory"
                    style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#080c14', border: '1px solid rgba(255,255,255,0.15)', color: '#ffffff', outline: 'none' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>CATEGORY TAG</label>
                  <select
                    value={postForm.tag}
                    onChange={e => {
                      const tag = e.target.value;
                      let color = '#ffffff';
                      if (tag === 'ZERO-DAY ALERT') color = '#ef4444';
                      if (tag === 'ML TRIAGE ENGINE') color = '#ef4444';
                      if (tag === 'TARGET VERIFICATION') color = '#ffffff';
                      if (tag === 'EXECUTIVE REPORTING') color = '#10b981';
                      setPostForm({ ...postForm, tag, tag_color: color });
                    }}
                    style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#000000', border: '2px solid #000000', color: '#ffffff', outline: 'none' }}
                  >
                    <option value="ZERO-DAY ALERT">ZERO-DAY ALERT (Red)</option>
                    <option value="TARGET VERIFICATION">TARGET VERIFICATION (White)</option>
                    <option value="ML TRIAGE ENGINE">ML TRIAGE ENGINE (Red)</option>
                    <option value="EXECUTIVE REPORTING">EXECUTIVE REPORTING (Green)</option>
                    <option value="PLATFORM ANNOUNCEMENT">PLATFORM ANNOUNCEMENT (Slate)</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>AUTHOR</label>
                  <input
                    type="text"
                    value={postForm.author}
                    onChange={e => setPostForm({ ...postForm, author: e.target.value })}
                    placeholder="e.g. NKAT Threat Intelligence Group"
                    style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#000000', border: '2px solid #000000', color: '#ffffff', outline: 'none' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>ESTIMATED READ TIME</label>
                  <input
                    type="text"
                    value={postForm.read_time}
                    onChange={e => setPostForm({ ...postForm, read_time: e.target.value })}
                    placeholder="e.g. 5 min read"
                    style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#000000', border: '2px solid #000000', color: '#ffffff', outline: 'none' }}
                  />
                </div>
              </div>

              {/* Photo / Image Attachment Section */}
              <div style={{ background: '#000000', padding: '1rem 1.25rem', borderRadius: '10px', border: '2px solid #000000' }}>
                <label style={{ fontSize: '0.82rem', color: '#ffffff', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <Image size={16} /> ATTACH PHOTO / COVER IMAGE
                </label>
                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
                  <input
                    type="text"
                    value={postForm.image_url}
                    onChange={e => setPostForm({ ...postForm, image_url: e.target.value })}
                    placeholder="Image URL or upload file below (e.g. /news/post1.jpg or https://...)"
                    style={{ flex: 1, minWidth: '260px', padding: '10px 12px', borderRadius: '6px', background: '#000000', border: '2px solid #000000', color: '#ffffff', fontSize: '0.88rem' }}
                  />
                  <label style={{ background: 'rgba(255, 255, 255, 0.1)', border: '2px solid #000000', color: '#ffffff', borderRadius: '6px', padding: '9px 14px', fontSize: '0.82rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Upload size={14} /> Upload Photo
                    <input type="file" accept="image/*" onChange={e => handleFileUpload(e, 'image')} style={{ display: 'none' }} />
                  </label>
                </div>
                {postForm.image_url && (
                  <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <img src={postForm.image_url} alt="Preview" style={{ width: '80px', height: '50px', objectFit: 'cover', borderRadius: '6px', border: '2px solid #000000' }} />
                    <span style={{ fontSize: '0.78rem', color: '#10b981' }}> Photo attached</span>
                  </div>
                )}
              </div>

              {/* Video Attachment Section */}
              <div style={{ background: '#080c14', padding: '1rem 1.25rem', borderRadius: '10px', border: '2px solid #000000' }}>
                <label style={{ fontSize: '0.82rem', color: '#ffffff', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px' }}>
                  <Video size={16} /> ATTACH THREAT DEMO VIDEO
                </label>
                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
                  <input
                    type="text"
                    value={postForm.video_url}
                    onChange={e => setPostForm({ ...postForm, video_url: e.target.value })}
                    placeholder="Video MP4 URL or upload video file (e.g. /uploads/demo.mp4 or https://...)"
                    style={{ flex: 1, minWidth: '260px', padding: '10px 12px', borderRadius: '6px', background: '#04060a', border: '2px solid #000000', color: '#ffffff', fontSize: '0.88rem' }}
                  />
                  <label style={{ background: 'rgba(255, 255, 255, 0.1)', border: '2px solid #000000', color: '#ffffff', borderRadius: '6px', padding: '9px 14px', fontSize: '0.82rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <Upload size={14} /> Upload Video
                    <input type="file" accept="video/*" onChange={e => handleFileUpload(e, 'video')} style={{ display: 'none' }} />
                  </label>
                </div>
                {postForm.video_url && (
                  <div style={{ marginTop: '10px' }}>
                    <video src={postForm.video_url} controls style={{ width: '100%', maxHeight: '160px', borderRadius: '6px', border: '2px solid #000000' }} />
                    <span style={{ fontSize: '0.78rem', color: '#10b981', display: 'block', marginTop: '4px' }}> Video attached</span>
                  </div>
                )}
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>POST SUMMARY / SNIPPET (Visible on Homepage)</label>
                <textarea
                  required
                  rows={3}
                  value={postForm.snippet}
                  onChange={e => setPostForm({ ...postForm, snippet: e.target.value })}
                  placeholder="Provide a concise summary of the security advisory or platform release update..."
                  style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#080c14', border: '1px solid rgba(255,255,255,0.15)', color: '#ffffff', outline: 'none', fontFamily: 'inherit' }}
                />
              </div>

              <div>
                <label style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px' }}>FULL ARTICLE BODY CONTENT (Optional Detail)</label>
                <textarea
                  rows={4}
                  value={postForm.content}
                  onChange={e => setPostForm({ ...postForm, content: e.target.value })}
                  placeholder="Full technical analysis, CVE references, or detailed deployment guide..."
                  style={{ width: '100%', padding: '12px 14px', borderRadius: '8px', background: '#080c14', border: '1px solid rgba(255,255,255,0.15)', color: '#ffffff', outline: 'none', fontFamily: 'inherit' }}
                />
              </div>

              <div style={{ display: 'flex', gap: '1rem' }}>
                <button
                  type="submit"
                  disabled={loading}
                  className="btn-aegis-primary"
                  style={{ padding: '0.8rem 2rem', fontSize: '0.92rem' }}
                >
                  {loading ? 'Processing...' : editingPostId ? 'Save Changes' : ' Publish Post to Platform'}
                </button>

                {editingPostId && (
                  <button
                    type="button"
                    onClick={() => {
                      setEditingPostId(null);
                      setPostForm({ title: '', tag: 'ZERO-DAY ALERT', tag_color: '#ef4444', author: 'NKAT Security Intelligence Labs', read_time: '4 min read', snippet: '', content: '' });
                    }}
                    style={{ background: 'transparent', border: '1px solid rgba(255,255,255,0.2)', color: '#ffffff', padding: '0.8rem 1.5rem', borderRadius: '8px', cursor: 'pointer' }}
                  >
                    Cancel Edit
                  </button>
                )}
              </div>
            </form>
          </div>

          {/* Published Posts Grid */}
          <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', marginBottom: '1.25rem' }}>
            Published Cyber News & Threat Advisories ({postsList.length})
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
            {postsList.map(p => (
              <div key={p.id} style={{
                background: '#090d16',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: '14px',
                padding: '1.5rem',
                display: 'flex',
                flexDirection: 'column',
                justify: 'space-between',
                gap: '1rem'
              }}>
                <div>
                  {p.image_url && (
                    <img src={p.image_url} alt={p.title} style={{ width: '100%', height: '140px', objectFit: 'cover', borderRadius: '8px', marginBottom: '12px', border: '1px solid rgba(255,255,255,0.1)' }} />
                  )}

                  {p.video_url && (
                    <div style={{ marginBottom: '12px' }}>
                      <video src={p.video_url} controls style={{ width: '100%', maxHeight: '180px', borderRadius: '8px', border: '1px solid rgba(168, 85, 247, 0.4)' }} />
                    </div>
                  )}

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                    <span className="mono-text" style={{ fontSize: '0.72rem', fontWeight: 800, padding: '3px 10px', borderRadius: '12px', background: `${p.tag_color}20`, color: p.tag_color, border: `1px solid ${p.tag_color}` }}>
                      {p.tag}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{p.read_time}</span>
                  </div>

                  <h4 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', margin: '0 0 8px 0', lineHeight: 1.3 }}>
                    #{p.id} {p.title}
                  </h4>

                  <p style={{ fontSize: '0.85rem', color: '#cbd5e1', lineHeight: 1.5, margin: 0 }}>
                    {p.snippet}
                  </p>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '12px' }}>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8' }}>By: {p.author}</span>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    <button
                      onClick={() => handleEditPost(p)}
                      style={{ background: 'rgba(56, 189, 248, 0.15)', border: '1px solid #38bdf8', color: '#38bdf8', borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem', cursor: 'pointer', fontWeight: 700 }}
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDeletePost(p.id, p.title)}
                      style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#fca5a5', borderRadius: '6px', padding: '4px 10px', fontSize: '0.78rem', cursor: 'pointer', fontWeight: 700 }}
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: User Account & Role Controls */}
      {activeTab === 'users' && (
        <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '16px', padding: '1.75rem' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', marginBottom: '1.25rem' }}>
            User Account Governance & Role Scoping
          </h3>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.9rem' }}>
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                  <th style={{ padding: '12px 16px' }}>User ID</th>
                  <th style={{ padding: '12px 16px' }}>Username</th>
                  <th style={{ padding: '12px 16px' }}>Email Address</th>
                  <th style={{ padding: '12px 16px' }}>Role</th>
                  <th style={{ padding: '12px 16px' }}>Organization</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {usersList.map(u => (
                  <tr key={u.id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '12px 16px', color: '#94a3b8' }}>#{u.id}</td>
                    <td style={{ padding: '12px 16px', fontWeight: 800, color: '#ffffff' }}>{u.username}</td>
                    <td style={{ padding: '12px 16px', color: '#cbd5e1' }}>{u.email || '-'}</td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{
                        padding: '4px 12px',
                        borderRadius: '12px',
                        fontWeight: 800,
                        fontSize: '0.75rem',
                        background: u.role === 'admin' ? 'rgba(251, 191, 36, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                        color: u.role === 'admin' ? '#fbbf24' : '#38bdf8',
                        border: `1px solid ${u.role === 'admin' ? '#fbbf24' : '#38bdf8'}`
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
                            style={{ background: 'rgba(251, 191, 36, 0.15)', border: '1px solid #fbbf24', color: '#fbbf24', borderRadius: '6px', padding: '6px 12px', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 800 }}
                          >
                            Promote Admin
                          </button>
                        ) : (
                          <button
                            onClick={() => handleRoleChange(u.id, 'analyst')}
                            style={{ background: 'rgba(255, 255, 255, 0.1)', border: '1px solid rgba(255,255,255,0.2)', color: '#ffffff', borderRadius: '6px', padding: '6px 12px', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 800 }}
                          >
                            Set Analyst
                          </button>
                        )}
                        {u.username !== 'admin' && (
                          <button
                            onClick={() => handleDeleteUser(u.id, u.username)}
                            style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#fca5a5', borderRadius: '6px', padding: '6px 12px', fontSize: '0.8rem', cursor: 'pointer', fontWeight: 800 }}
                          >
                            Delete
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

      {/* TAB 3: Policy & Vulnerability Batch Controls */}
      {activeTab === 'overrides' && (
        <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.12)', borderRadius: '16px', padding: '1.75rem' }}>
          <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', marginBottom: '1.25rem' }}>
            Global Administrative Actions & Policy Overrides
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem' }}>
            <div style={{ background: '#04060a', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: '12px', padding: '1.5rem' }}>
              <h4 style={{ color: '#34d399', margin: '0 0 8px 0', fontSize: '1.05rem', fontWeight: 800 }}> Bulk Approve All Findings</h4>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                Instantly approve all currently open vulnerability findings across all targets with admin override logging.
              </p>
              <button
                onClick={handleBulkApprove}
                disabled={loading}
                style={{ background: '#10b981', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '10px 18px', fontWeight: 800, fontSize: '0.88rem', cursor: 'pointer', marginTop: '12px' }}
              >
                Approve All Open Findings
              </button>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1.5rem' }}>
              <h4 style={{ color: '#fca5a5', margin: '0 0 8px 0', fontSize: '1.05rem', fontWeight: 800 }}> Bulk Reject All Findings</h4>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                Bulk reject all currently open findings to clear active telemetry stream.
              </p>
              <button
                onClick={handleBulkReject}
                disabled={loading}
                style={{ background: '#ef4444', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '10px 18px', fontWeight: 800, fontSize: '0.88rem', cursor: 'pointer', marginTop: '12px' }}
              >
                Reject All Open Findings
              </button>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(56, 189, 248, 0.4)', borderRadius: '12px', padding: '1.5rem' }}>
              <h4 style={{ color: '#38bdf8', margin: '0 0 8px 0', fontSize: '1.05rem', fontWeight: 800 }}> Purge Historical Scans</h4>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                Clean up database storage by purging past historical scan runs, keeping only the most recent scan.
              </p>
              <button
                onClick={handlePurgeScans}
                disabled={loading}
                style={{ background: '#0284c7', color: '#ffffff', border: 'none', borderRadius: '8px', padding: '10px 18px', fontWeight: 800, fontSize: '0.88rem', cursor: 'pointer', marginTop: '12px' }}
              >
                Purge Old Scans
              </button>
            </div>

            <div style={{ background: '#04060a', border: '2px solid #000000', borderRadius: '12px', padding: '1.5rem' }}>
              <h4 style={{ color: '#ffffff', margin: '0 0 8px 0', fontSize: '1.05rem', fontWeight: 800 }}> Retrain ML Classifier</h4>
              <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.5 }}>
                Execute automated machine learning retraining script (`retrain_from_feedback.py`) on human approvals.
              </p>
              <button
                onClick={handleRetrainML}
                disabled={loading}
                style={{ background: '#ef4444', color: '#ffffff', border: '2px solid #000000', borderRadius: '8px', padding: '10px 18px', fontWeight: 800, fontSize: '0.88rem', cursor: 'pointer', marginTop: '12px' }}
              >
                Retrain ML Model Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TAB: Real-Time Threat Intelligence Feeds */}
      {activeTab === 'threat_feeds' && (
        <div style={{ background: '#090d16', border: '1px solid rgba(0, 240, 255, 0.25)', borderRadius: '16px', padding: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '1.25rem' }}>
            <div>
              <h3 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#00f0ff', margin: '0 0 6px 0', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldCheck size={24} /> Real-Time Threat Intelligence Feeds & API Integrations
              </h3>
              <p style={{ color: '#94a3b8', fontSize: '0.92rem', margin: 0 }}>
                Automatic background polling daemon updates vulnerability catalogs every 15 minutes from CISA KEV, NIST NVD, FIRST EPSS, and INSA advisories.
              </p>
            </div>

            <button
              onClick={handleForceSyncThreatFeeds}
              disabled={loading}
              className="btn-aegis-primary"
              style={{ padding: '0.85rem 1.6rem', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <RefreshCw size={16} className={loading ? 'spin' : ''} /> {loading ? 'Syncing Feeds...' : ' Force Sync Real-Time Feeds Now'}
            </button>
          </div>

          {/* Feed Status Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
            <div style={{ background: '#04060a', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#fca5a5', fontWeight: 800 }}>CISA KEV CATALOG</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>LIVE CONNECTED</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus ? `${feedStatus.cisa_kev.count} CVEs` : '1,142 CVEs'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Last Synced: {feedStatus?.cisa_kev.last_updated ? feedStatus.cisa_kev.last_updated.slice(0, 19) : 'Automated (15 min interval)'}
              </div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(56, 189, 248, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 800 }}>NIST NVD API v2</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>LIVE CONNECTED</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus ? `${feedStatus.nist_nvd.count} Records` : '50 Recent CVEs'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Source: services.nvd.nist.gov/rest/json/cves/2.0
              </div>
            </div>

            <div style={{ background: '#04060a', border: '2px solid #000000', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#ffffff', fontWeight: 800 }}>FIRST EPSS SCORES</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#10b981', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>LIVE CONNECTED</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus ? `${feedStatus.epss.count} Scores` : '100 Active Scores'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Source: api.first.org/data/v1/epss
              </div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(251, 191, 36, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#fbbf24', fontWeight: 800 }}>GITHUB SECURITY ADVISORIES</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>GRAPHQL LIVE</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus?.github_advisories ? `${feedStatus.github_advisories.count} GHSA Advisories` : '100 GHSA Advisories'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Source: api.github.com/graphql
              </div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 800 }}>URLHAUS MALWARE FEED</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>LIVE CONNECTED</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus?.urlhaus ? `${feedStatus.urlhaus.count} Malicious URLs` : '15,926 Malicious URLs'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Source: urlhaus.abuse.ch/downloads/json_recent
              </div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(14, 165, 233, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 800 }}>THREATFOX IOC INDICATORS</span>
                <span style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '2px 8px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>LIVE CONNECTED</span>
              </div>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff' }}>
                {feedStatus?.threatfox ? `${feedStatus.threatfox.count} IOC Indicators` : '5,674 IOC Indicators'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '6px' }}>
                Source: threatfox.abuse.ch/export/json/recent
              </div>
            </div>
          </div>

          {/* Connected Feed Sources Table */}
          <h4 style={{ color: '#ffffff', fontSize: '1.05rem', fontWeight: 800, marginBottom: '1rem' }}>
            Active Real-Time Threat Feed Integrations
          </h4>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
              <thead>
                <tr style={{ background: 'rgba(255,255,255,0.05)', color: '#94a3b8', borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
                  <th style={{ padding: '12px 16px' }}>Threat Feed Source Name</th>
                  <th style={{ padding: '12px 16px' }}>Feed Endpoint URL</th>
                  <th style={{ padding: '12px 16px' }}>Update Frequency</th>
                  <th style={{ padding: '12px 16px' }}>Auth Method</th>
                  <th style={{ padding: '12px 16px', textAlign: 'right' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {feedStatus?.sources ? feedStatus.sources.map((s, idx) => (
                  <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                    <td style={{ padding: '12px 16px', fontWeight: 800, color: '#ffffff' }}>{s.name}</td>
                    <td className="mono-text" style={{ padding: '12px 16px', color: '#38bdf8', fontSize: '0.8rem' }}>{s.url}</td>
                    <td style={{ padding: '12px 16px', color: '#cbd5e1' }}>15 Minutes Daemon</td>
                    <td style={{ padding: '12px 16px', color: '#34d399' }}>Free Public API (No Key Required)</td>
                    <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                      <span style={{ background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', border: '1px solid #10b981', padding: '4px 12px', borderRadius: '12px', fontSize: '0.75rem', fontWeight: 800 }}>
                        {s.status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                )) : (
                  <tr>
                    <td colSpan={5} style={{ padding: '16px', textAlign: 'center', color: '#94a3b8' }}>Loading Threat Feed Status...</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: Database Telemetry & Storage */}
      {activeTab === 'db_telemetry' && (
        <div>
          <div style={{ background: 'rgba(14, 18, 28, 0.95)', border: '1px solid rgba(251, 191, 36, 0.4)', borderRadius: '16px', padding: '2rem', marginBottom: '2rem' }}>
            <h3 style={{ margin: '0 0 1.25rem 0', color: '#fbbf24', fontSize: '1.2rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '10px' }}>
              <HardDrive size={22} /> Active Database File & Storage Path Location
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
              <div style={{ background: '#04060a', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 700 }}>DATABASE FILE PATH</div>
                <div className="mono-text" style={{ color: '#00f0ff', wordBreak: 'break-all', marginTop: '6px', fontWeight: 800, fontSize: '0.95rem' }}>
                  {stats ? stats.database_file_path : 'c:\\Users\\hp\\Downloads\\web-vuln-platform\\nkat_dev.db'}
                </div>
              </div>

              <div style={{ background: '#04060a', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 700 }}>ENGINE TYPE & DIALECT</div>
                <div style={{ color: '#ffffff', marginTop: '6px', fontWeight: 800, fontSize: '0.95rem' }}>
                  {stats ? stats.database_type : 'SQLite Local / PostgreSQL Driver'}
                </div>
              </div>

              <div style={{ background: '#04060a', padding: '16px', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ color: '#94a3b8', fontSize: '0.8rem', fontWeight: 700 }}>CURRENT DB DISK STORAGE SIZE</div>
                <div className="mono-text" style={{ color: '#34d399', marginTop: '6px', fontWeight: 900, fontSize: '1.2rem' }}>
                  {stats ? `${stats.database_size_mb} MB (${stats.database_size_bytes.toLocaleString()} bytes)` : '0.52 MB'}
                </div>
              </div>
            </div>
          </div>

          <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff', marginBottom: '1rem' }}>
            Database Table Telemetry & Record Counts
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
            <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.1)', padding: '1.4rem', borderRadius: '14px' }}>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 700 }}>REGISTERED USERS</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 900, color: '#ffffff', marginTop: '4px' }}>{stats ? stats.total_users : 0}</div>
            </div>

            <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.1)', padding: '1.4rem', borderRadius: '14px' }}>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 700 }}>TOTAL SCANS EXECUTED</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 900, color: '#38bdf8', marginTop: '4px' }}>{stats ? stats.total_scans : 0}</div>
            </div>

            <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.1)', padding: '1.4rem', borderRadius: '14px' }}>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 700 }}>DETECTED FINDINGS</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 900, color: '#fbbf24', marginTop: '4px' }}>{stats ? stats.total_findings : 0}</div>
            </div>

            <div style={{ background: '#090d16', border: '1px solid rgba(255,255,255,0.1)', padding: '1.4rem', borderRadius: '14px' }}>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 700 }}>APPROVED REMEDIATIONS</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 900, color: '#34d399', marginTop: '4px' }}>{stats ? stats.total_approved_findings : 0}</div>
            </div>

            <div style={{ background: '#090d16', border: '2px solid #000000', padding: '1.4rem', borderRadius: '14px' }}>
              <div style={{ fontSize: '0.82rem', color: '#94a3b8', fontWeight: 700 }}>ML FEEDBACK SAMPLES</div>
              <div style={{ fontSize: '2.2rem', fontWeight: 900, color: '#ffffff', marginTop: '4px' }}>{stats ? stats.total_feedback_labels : 0}</div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: WAF Live Traffic & Request Classification Panel */}
      {activeTab === 'waf_traffic' && (
        <div>
          {/* Header Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <h3 style={{ color: '#ef4444', fontSize: '1.4rem', fontWeight: 900, margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldAlert size={26} /> WAF Live Traffic & Real-Time ML Request Classification
              </h3>
              <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: '4px 0 0 0' }}>
                Monitors HTTP traffic in real-time, classifies payloads using machine learning heuristics, and makes automated ALLOW (200 OK) vs BLOCK (403 Forbidden) decisions.
              </p>
            </div>

            {/* Test Attack Simulation Buttons */}
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              <button
                onClick={() => handleSimulateWafAttack('sqli')}
                disabled={loading}
                style={{ background: 'rgba(239, 68, 68, 0.2)', border: '2px solid #000000', color: '#ef4444', padding: '8px 14px', borderRadius: '10px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Zap size={14} /> Simulate SQLi Attack
              </button>
              <button
                onClick={() => handleSimulateWafAttack('xss')}
                disabled={loading}
                style={{ background: 'rgba(245, 158, 11, 0.2)', border: '2px solid #000000', color: '#fbbf24', padding: '8px 14px', borderRadius: '10px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Zap size={14} /> Simulate XSS Attack
              </button>
              <button
                onClick={() => handleSimulateWafAttack('lfi')}
                disabled={loading}
                style={{ background: 'rgba(239, 68, 68, 0.2)', border: '2px solid #000000', color: '#ffffff', padding: '8px 14px', borderRadius: '10px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <Zap size={14} /> Simulate Path Traversal
              </button>
              <button
                onClick={fetchWafTraffic}
                style={{ background: 'rgba(255, 255, 255, 0.08)', border: '1px solid rgba(255, 255, 255, 0.2)', color: '#ffffff', padding: '8px 14px', borderRadius: '10px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <RefreshCw size={14} /> Refresh Stream
              </button>
            </div>
          </div>

          {/* Metric Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
            <div style={{ background: '#04060a', border: '1px solid rgba(255, 255, 255, 0.12)', borderRadius: '14px', padding: '1.4rem' }}>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 800 }}>TOTAL PROCESSED REQUESTS</div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#ffffff', marginTop: '4px' }}>
                {wafData ? wafData.total_requests : 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '6px' }}>Real-time HTTP Stream</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: '14px', padding: '1.4rem' }}>
              <div style={{ fontSize: '0.78rem', color: '#34d399', fontWeight: 800 }}>ALLOWED REQUESTS (200 OK)</div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#34d399', marginTop: '4px' }}>
                {wafData ? wafData.allowed_requests : 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '6px' }}>Clean Legitimate Traffic</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '14px', padding: '1.4rem' }}>
              <div style={{ fontSize: '0.78rem', color: '#f87171', fontWeight: 800 }}>BLOCKED ATTACKS (403 FORBIDDEN)</div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#ef4444', marginTop: '4px' }}>
                {wafData ? wafData.blocked_requests : 0}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '6px' }}>Threat Payload Intercepts</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(251, 191, 36, 0.4)', borderRadius: '14px', padding: '1.4rem' }}>
              <div style={{ fontSize: '0.78rem', color: '#fbbf24', fontWeight: 800 }}>WAF ML BLOCK RATE</div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#fbbf24', marginTop: '4px' }}>
                {wafData ? `${wafData.block_rate_percent}%` : '0%'}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '6px' }}>Threat Mitigation Efficiency</div>
            </div>
          </div>

          {/* Traffic Stream Table */}
          <h4 style={{ color: '#ffffff', fontSize: '1.1rem', fontWeight: 800, marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Terminal size={18} color="#ef4444" /> Live WAF Request Log Stream (Auto-polling 3s)
          </h4>

          <div style={{ overflowX: 'auto', background: '#04060a', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '14px' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.05)', color: '#94a3b8', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  <th style={{ padding: '12px 14px' }}>Timestamp</th>
                  <th style={{ padding: '12px 14px' }}>Client IP</th>
                  <th style={{ padding: '12px 14px' }}>Method</th>
                  <th style={{ padding: '12px 14px' }}>Path / Payload</th>
                  <th style={{ padding: '12px 14px' }}>ML Classification</th>
                  <th style={{ padding: '12px 14px' }}>ML Confidence</th>
                  <th style={{ padding: '12px 14px', textAlign: 'right' }}>WAF Decision</th>
                </tr>
              </thead>
              <tbody>
                {wafData?.logs && wafData.logs.length > 0 ? (
                  wafData.logs.map((log) => {
                    const isBlocked = log.action === 'BLOCKED';
                    return (
                      <tr key={log.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#94a3b8', fontSize: '0.78rem' }}>
                          {log.timestamp ? log.timestamp.slice(11, 19) : 'Now'}
                        </td>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#ffffff', fontWeight: 700 }}>
                          {log.client_ip}
                        </td>
                        <td style={{ padding: '12px 14px' }}>
                          <span style={{
                            background: log.method === 'POST' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.08)',
                            color: log.method === 'POST' ? '#38bdf8' : '#ffffff',
                            padding: '2px 6px',
                            borderRadius: '6px',
                            fontWeight: 800,
                            fontSize: '0.75rem'
                          }}>
                            {log.method}
                          </span>
                        </td>
                        <td className="mono-text" style={{ padding: '12px 14px', color: isBlocked ? '#fca5a5' : '#e2e8f0', wordBreak: 'break-all', maxWidth: '280px' }}>
                          {log.path}
                        </td>
                        <td style={{ padding: '12px 14px' }}>
                          <span style={{
                            color: isBlocked ? '#ef4444' : '#34d399',
                            fontWeight: 800
                          }}>
                            {log.classification}
                          </span>
                        </td>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#fbbf24', fontWeight: 800 }}>
                          {(log.ml_confidence * 100).toFixed(1)}%
                        </td>
                        <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                          <span style={{
                            background: isBlocked ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                            color: isBlocked ? '#ef4444' : '#34d399',
                            border: `1px solid ${isBlocked ? '#ef4444' : '#10b981'}`,
                            padding: '4px 10px',
                            borderRadius: '10px',
                            fontSize: '0.75rem',
                            fontWeight: 900
                          }}>
                            {isBlocked ? ' BLOCKED (403)' : ' ALLOWED (200)'}
                          </span>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} style={{ padding: '20px', textAlign: 'center', color: '#94a3b8' }}>
                      No WAF traffic logged yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 6: Unified Activity & Audit Reporting Panel */}
      {activeTab === 'activity_logs' && (
        <div>
          {/* Header Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <h3 style={{ color: '#ef4444', fontSize: '1.4rem', fontWeight: 900, margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                <FileText size={26} /> Unified Platform Activity & User Audit Telemetry
              </h3>
              <p style={{ color: '#94a3b8', fontSize: '0.88rem', margin: '4px 0 0 0' }}>
                Consolidated audit trail capturing logins, scan triggers, finding approvals/rejections, domain target submissions, and governance role updates.
              </p>
            </div>

            <div style={{ display: 'flex', gap: '10px' }}>
              <button
                onClick={fetchActivityReport}
                style={{ background: 'rgba(255, 255, 255, 0.08)', border: '1px solid rgba(255, 255, 255, 0.2)', color: '#ffffff', padding: '8px 14px', borderRadius: '10px', fontWeight: 800, fontSize: '0.8rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <RefreshCw size={14} /> Refresh Audit Trail
              </button>
            </div>
          </div>

          {/* Filters Bar */}
          <div style={{ background: '#04060a', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '14px', padding: '1.25rem', marginBottom: '1.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <div style={{ flex: '1', minWidth: '200px' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', fontWeight: 800, marginBottom: '6px' }}>FILTER BY USERNAME</label>
              <input
                type="text"
                placeholder="Search username (e.g. admin)..."
                value={activityFilterUser}
                onChange={(e) => { setActivityFilterUser(e.target.value); setActivityPage(1); }}
                style={{ width: '100%', background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.15)', color: '#ffffff', borderRadius: '8px', padding: '8px 12px', fontSize: '0.88rem' }}
              />
            </div>

            <div style={{ flex: '1', minWidth: '200px' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', fontWeight: 800, marginBottom: '6px' }}>FILTER BY ACTION TYPE</label>
              <select
                value={activityFilterAction}
                onChange={(e) => { setActivityFilterAction(e.target.value); setActivityPage(1); }}
                style={{ width: '100%', background: '#090d16', border: '1px solid rgba(255,255,255,0.15)', color: '#ffffff', borderRadius: '8px', padding: '8px 12px', fontSize: '0.88rem' }}
              >
                <option value="">All Platform Actions</option>
                <option value="LOGIN">LOGIN</option>
                <option value="SCAN_TRIGGER">SCAN_TRIGGER</option>
                <option value="FINDING_APPROVE">FINDING_APPROVE</option>
                <option value="FINDING_REJECT">FINDING_REJECT</option>
                <option value="DOMAIN_VERIFICATION">DOMAIN_VERIFICATION</option>
                <option value="ROLE_CHANGE">ROLE_CHANGE</option>
              </select>
            </div>
          </div>

          {/* Activity Log Stream Table */}
          <div style={{ overflowX: 'auto', background: '#04060a', border: '1px solid rgba(255, 255, 255, 0.1)', borderRadius: '14px', marginBottom: '1.5rem' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.05)', color: '#94a3b8', borderBottom: '1px solid rgba(255, 255, 255, 0.1)' }}>
                  <th style={{ padding: '12px 14px' }}>Timestamp</th>
                  <th style={{ padding: '12px 14px' }}>Actor / User</th>
                  <th style={{ padding: '12px 14px' }}>Action Type</th>
                  <th style={{ padding: '12px 14px' }}>Target Resource</th>
                  <th style={{ padding: '12px 14px' }}>IP Address</th>
                  <th style={{ padding: '12px 14px' }}>Details / Audit Message</th>
                </tr>
              </thead>
              <tbody>
                {activityReport?.logs && activityReport.logs.length > 0 ? (
                  activityReport.logs.map((log) => {
                    let badgeColor = '#38bdf8';
                    let badgeBg = 'rgba(56, 189, 248, 0.2)';
                    if (log.action_type === 'LOGIN') { badgeColor = '#38bdf8'; badgeBg = 'rgba(56, 189, 248, 0.2)'; }
                    else if (log.action_type === 'SCAN_TRIGGER') { badgeColor = '#00f0ff'; badgeBg = 'rgba(0, 240, 255, 0.2)'; }
                    else if (log.action_type.includes('APPROVE')) { badgeColor = '#34d399'; badgeBg = 'rgba(16, 185, 129, 0.2)'; }
                    else if (log.action_type.includes('REJECT')) { badgeColor = '#ef4444'; badgeBg = 'rgba(239, 68, 68, 0.2)'; }
                    else if (log.action_type.includes('ROLE')) { badgeColor = '#fbbf24'; badgeBg = 'rgba(251, 191, 36, 0.2)'; }
                    else if (log.action_type.includes('DOMAIN')) { badgeColor = '#c084fc'; badgeBg = 'rgba(168, 85, 247, 0.2)'; }

                    return (
                      <tr key={log.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#94a3b8', fontSize: '0.78rem' }}>
                          {log.timestamp ? log.timestamp.slice(0, 19).replace('T', ' ') : 'N/A'}
                        </td>
                        <td style={{ padding: '12px 14px', color: '#ffffff', fontWeight: 800 }}>
                          {log.username}
                        </td>
                        <td style={{ padding: '12px 14px' }}>
                          <span style={{ background: badgeBg, color: badgeColor, border: `1px solid ${badgeColor}`, padding: '3px 8px', borderRadius: '8px', fontSize: '0.75rem', fontWeight: 800 }}>
                            {log.action_type}
                          </span>
                        </td>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#cbd5e1', fontWeight: 700 }}>
                          {log.target_resource}
                        </td>
                        <td className="mono-text" style={{ padding: '12px 14px', color: '#64748b' }}>
                          {log.ip_address}
                        </td>
                        <td style={{ padding: '12px 14px', color: '#94a3b8', fontSize: '0.8rem' }}>
                          {log.details || 'No additional details'}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={6} style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>
                      No activity logs match the selected filter parameters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination Controls Bar */}
          {activityReport && activityReport.total_pages > 1 && (
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>
                Showing page {activityReport.page} of {activityReport.total_pages} ({activityReport.total_records} total records)
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  disabled={activityPage <= 1}
                  onClick={() => setActivityPage(prev => Math.max(1, prev - 1))}
                  style={{ background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.2)', color: '#ffffff', padding: '6px 12px', borderRadius: '8px', cursor: activityPage <= 1 ? 'not-allowed' : 'pointer', opacity: activityPage <= 1 ? 0.5 : 1 }}
                >
                  Previous
                </button>
                <button
                  disabled={activityPage >= activityReport.total_pages}
                  onClick={() => setActivityPage(prev => Math.min(activityReport.total_pages, prev + 1))}
                  style={{ background: 'rgba(255,255,255,0.08)', border: '1px solid rgba(255,255,255,0.2)', color: '#ffffff', padding: '6px 12px', borderRadius: '8px', cursor: activityPage >= activityReport.total_pages ? 'not-allowed' : 'pointer', opacity: activityPage >= activityReport.total_pages ? 0.5 : 1 }}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB: Real System Updates & Telemetry Report */}
      {activeTab === 'updates_report' && (
        <div style={{ background: '#090d16', border: '1px solid rgba(16, 185, 129, 0.35)', borderRadius: '16px', padding: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', marginBottom: '2rem', borderBottom: '1px solid rgba(255,255,255,0.08)', paddingBottom: '1.25rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <h3 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#34d399', margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <RefreshCw size={24} /> True Real System Updates & Telemetry Report
                </h3>
                <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(16, 185, 129, 0.2)', color: '#34d399', padding: '3px 10px', borderRadius: '10px', border: '1px solid #10b981', fontWeight: 800 }}>
                  LIVE 5S TELEMETRY STREAM
                </span>
              </div>
              <p style={{ color: '#94a3b8', fontSize: '0.92rem', margin: 0 }}>
                Real-time visibility into WHAT updated, WHEN it updated, and FROM WHERE (authoritative source URL / origin IP).
              </p>
            </div>

            <button
              onClick={fetchUpdatesReport}
              className="btn-aegis-primary"
              style={{ padding: '0.85rem 1.6rem', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '8px', background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', border: 'none' }}
            >
              <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh Updates Stream
            </button>
          </div>

          {/* Metric Highlights */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
            <div style={{ background: '#04060a', border: '1px solid rgba(56, 189, 248, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 800 }}>ACTIVE LIVE FEEDS</span>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff', marginTop: '6px' }}>
                {updatesReport?.summary?.total_active_feeds || 6} / 6 Feeds
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>CISA, EPSS, NVD, GHSA, URLhaus, ThreatFox</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 800 }}>POLLING SCHEDULER</span>
              <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', marginTop: '8px' }}>
                {updatesReport?.summary?.polling_schedule || '15-Min APScheduler Tick'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>Unified Background Daemon</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 800 }}>WAF BLOCKED ATTACKS</span>
              <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#ffffff', marginTop: '6px' }}>
                {updatesReport?.summary?.waf_blocked_total || 0} Attacks
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>Real 403 Forbidden Intercepts</div>
            </div>

            <div style={{ background: '#04060a', border: '1px solid rgba(168, 85, 247, 0.4)', borderRadius: '12px', padding: '1.4rem' }}>
              <span style={{ fontSize: '0.8rem', color: '#c084fc', fontWeight: 800 }}>REPORT GENERATED AT</span>
              <div className="mono-text" style={{ fontSize: '0.9rem', fontWeight: 700, color: '#ffffff', marginTop: '10px' }}>
                {updatesReport?.generated_at ? updatesReport.generated_at.slice(0, 19).replace('T', ' ') + ' UTC' : 'Live'}
              </div>
              <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '4px' }}>Auto-Synced Telemetry</div>
            </div>
          </div>

          {/* Detailed Updates Table */}
          <div style={{ overflowX: 'auto', borderRadius: '12px', border: '1px solid rgba(255,255,255,0.08)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.88rem' }}>
              <thead>
                <tr style={{ background: '#05070a', color: '#94a3b8', textTransform: 'uppercase', fontSize: '0.75rem', letterSpacing: '0.5px' }}>
                  <th style={{ padding: '14px 18px' }}>Component / Target</th>
                  <th style={{ padding: '14px 18px' }}>What Updated (Details)</th>
                  <th style={{ padding: '14px 18px' }}>When (Timestamp)</th>
                  <th style={{ padding: '14px 18px' }}>From Where (Info Source)</th>
                  <th style={{ padding: '14px 18px' }}>Status & Health</th>
                </tr>
              </thead>
              <tbody>
                {updatesReport?.updates && updatesReport.updates.length > 0 ? (
                  updatesReport.updates.map((item, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)', background: idx % 2 === 0 ? 'rgba(255,255,255,0.01)' : 'transparent' }}>
                      <td style={{ padding: '14px 18px', fontWeight: 800, color: '#ffffff' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <span style={{
                            background: item.type === 'THREAT_INTEL_FEED' ? 'rgba(56, 189, 248, 0.15)' : item.type === 'WAF_SECURITY' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(168, 85, 247, 0.15)',
                            color: item.type === 'THREAT_INTEL_FEED' ? '#38bdf8' : item.type === 'WAF_SECURITY' ? '#ef4444' : '#a855f7',
                            padding: '3px 8px',
                            borderRadius: '6px',
                            fontSize: '0.72rem',
                            fontWeight: 800
                          }}>
                            {item.type}
                          </span>
                          {item.component}
                        </div>
                      </td>
                      <td style={{ padding: '14px 18px', color: '#e2e8f0', fontWeight: 600 }}>
                        {item.what}
                      </td>
                      <td className="mono-text" style={{ padding: '14px 18px', color: '#fbbf24', fontSize: '0.82rem' }}>
                        {item.when ? item.when.slice(0, 19).replace('T', ' ') : 'N/A'}
                      </td>
                      <td className="mono-text" style={{ padding: '14px 18px', color: '#38bdf8', fontSize: '0.78rem', maxWidth: '320px', wordBreak: 'break-all' }}>
                        {item.from_info.startsWith('http') ? (
                          <a href={item.from_info} target="_blank" rel="noopener noreferrer" style={{ color: '#38bdf8', textDecoration: 'underline' }}>
                            {item.from_info}
                          </a>
                        ) : (
                          item.from_info
                        )}
                      </td>
                      <td style={{ padding: '14px 18px' }}>
                        <span style={{
                          background: item.status.includes('200') || item.status === 'SUCCESS' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                          color: item.status.includes('200') || item.status === 'SUCCESS' ? '#34d399' : '#f87171',
                          border: `1px solid ${item.status.includes('200') || item.status === 'SUCCESS' ? '#10b981' : '#ef4444'}`,
                          padding: '4px 10px',
                          borderRadius: '10px',
                          fontSize: '0.75rem',
                          fontWeight: 800
                        }}>
                          {item.status}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="5" style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
                      Loading real-time updates report stream...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
