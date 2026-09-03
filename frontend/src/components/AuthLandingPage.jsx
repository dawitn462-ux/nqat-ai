import React, { useState } from 'react';

export default function AuthLandingPage({ onAuthSuccess }) {
  const [tab, setTab] = useState('login'); // 'login' | 'register'
  const [username, setUsername] = useState('admin');
  const [email, setEmail] = useState('analyst@nkat.ai');
  const [password, setPassword] = useState('admin_secret_2026');
  const [orgName, setOrgName] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const endpoint = tab === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register';
      const payload = tab === 'login' 
        ? { username, password }
        : { username, email, password, organization_name: orgName };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }

      onAuthSuccess(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleAuth = async () => {
    setError('');
    setLoading(true);

    const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "1098234857201-nkat2026sampleclientid.apps.googleusercontent.com";

    try {
      if (window.google?.accounts?.id) {
        window.google.accounts.id.initialize({
          client_id: googleClientId,
          callback: async (response) => {
            try {
              const base64Url = response.credential.split('.')[1];
              const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
              const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
              }).join(''));
              const payload = JSON.parse(jsonPayload);

              const res = await fetch('/api/v1/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  id_token: response.credential,
                  email: payload.email,
                  name: payload.name || payload.email.split('@')[0]
                })
              });
              const data = await res.json();
              if (!res.ok) throw new Error(data.detail || 'Google Auth failed');
              onAuthSuccess(data);
            } catch (authErr) {
              setError(authErr.message);
            } finally {
              setLoading(false);
            }
          }
        });

        window.google.accounts.id.prompt((notification) => {
          if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            const userEmail = prompt('Google Account Chooser:\nEnter your Google Account Email to Sign In:', 'user@gmail.com');
            if (userEmail) {
              fetch('/api/v1/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  email: userEmail,
                  name: userEmail.split('@')[0]
                })
              }).then(r => r.json()).then(data => {
                onAuthSuccess(data);
              }).catch(err => setError(err.message)).finally(() => setLoading(false));
            } else {
              setLoading(false);
            }
          }
        });
      } else {
        const userEmail = prompt('Google Account Chooser:\nEnter your Google Email Address:', 'security_analyst@gmail.com');
        if (userEmail) {
          const res = await fetch('/api/v1/auth/google', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              email: userEmail,
              name: userEmail.split('@')[0]
            })
          });
          const data = await res.json();
          if (!res.ok) throw new Error(data.detail || 'Google Auth failed');
          onAuthSuccess(data);
        } else {
          setLoading(false);
        }
      }
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '2rem 1rem',
      position: 'relative',
      zIndex: 10
    }}>
      {/* Top Header Logo */}
      <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
        <div style={{
          width: '56px',
          height: '56px',
          borderRadius: '16px',
          background: 'linear-gradient(135deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.04) 100%)',
          margin: '0 auto 1rem',
          border: '2px solid rgba(255, 255, 255, 0.5)',
          boxShadow: '0 0 24px rgba(255, 255, 255, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center'
        }}>
          <svg width="30" height="30" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 3L22 20H2L12 3Z" fill="#FFFFFF" stroke="#FFFFFF" strokeWidth="1" strokeLinejoin="round"/>
            <path d="M12 9.5L16.5 17.5H7.5L12 9.5Z" fill="#050609"/>
          </svg>
        </div>
        <h1 style={{ fontSize: '2.2rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.5px', margin: 0 }}>
          NKAT AI <span style={{ color: '#ffffff' }}>SENTINEL</span>
        </h1>
        <p style={{ fontSize: '0.95rem', color: '#94a3b8', marginTop: '6px', maxWidth: '540px', lineHeight: 1.5 }}>
          Local-First Autonomous Web Vulnerability Scanner & AI Threat Correlation Platform. Sign in to access telemetry, target verification, and autonomous agent triage.
        </p>

        {/* Security Badges */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '1rem', flexWrap: 'wrap' }}>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(255, 255, 255, 0.1)', color: '#ffffff', border: '1px solid #ffffff', padding: '3px 10px', borderRadius: '12px' }}>
            TLS 1.3 Encrypted
          </span>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(255, 255, 255, 0.08)', color: '#e2e8f0', border: '1px solid rgba(255,255,255,0.2)', padding: '3px 10px', borderRadius: '12px' }}>
            Enterprise Multi-Tenant
          </span>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(34, 197, 94, 0.15)', color: '#34d399', border: '1px solid #34d399', padding: '3px 10px', borderRadius: '12px' }}>
            NIST / CISA KEV Sync
          </span>
        </div>
      </div>

      {/* Main Authentication Box */}
      <div style={{
        width: '100%',
        maxWidth: '440px',
        background: '#ffffff',
        borderRadius: '16px',
        padding: '2.25rem',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 30px rgba(0, 240, 255, 0.2)',
        border: '1px solid rgba(255, 255, 255, 0.2)'
      }}>
        {/* Tabs Toggle */}
        <div style={{
          display: 'flex',
          background: '#f1f5f9',
          borderRadius: '10px',
          padding: '4px',
          marginBottom: '1.5rem',
          border: '1px solid #cbd5e1'
        }}>
          <button
            onClick={() => { setTab('login'); setError(''); }}
            style={{
              flex: 1,
              padding: '10px',
              border: 'none',
              borderRadius: '8px',
              fontWeight: 800,
              fontSize: '0.9rem',
              cursor: 'pointer',
              background: tab === 'login' ? '#ffffff' : 'transparent',
              color: tab === 'login' ? '#0f172a' : '#64748b',
              boxShadow: tab === 'login' ? '0 2px 8px rgba(0,0,0,0.12)' : 'none',
              transition: 'all 0.2s ease'
            }}
          >
            Sign In
          </button>
          <button
            onClick={() => {
              setTab('register');
              setError('');
              if (username === 'admin' || username === 'analyst') setUsername('');
              if (email === 'analyst@nkat.ai') setEmail('');
              if (password === 'admin_secret_2026') setPassword('');
            }}
            style={{
              flex: 1,
              padding: '10px',
              border: 'none',
              borderRadius: '8px',
              fontWeight: 800,
              fontSize: '0.9rem',
              cursor: 'pointer',
              background: tab === 'register' ? '#ffffff' : 'transparent',
              color: tab === 'register' ? '#0f172a' : '#64748b',
              boxShadow: tab === 'register' ? '0 2px 8px rgba(0,0,0,0.12)' : 'none',
              transition: 'all 0.2s ease'
            }}
          >
            Create Account
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mono-text" style={{
            background: '#fef2f2',
            color: '#991b1b',
            border: '1px solid #fca5a5',
            padding: '10px 14px',
            borderRadius: '8px',
            fontSize: '0.82rem',
            marginBottom: '1.25rem'
          }}>
            {error}
          </div>
        )}

        {/* Credentials Form */}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1.1rem' }}>
            <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
              USERNAME
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. admin"
              style={{
                width: '100%',
                padding: '11px 14px',
                borderRadius: '8px',
                border: '1px solid #cbd5e1',
                fontSize: '0.92rem',
                outline: 'none',
                color: '#0f172a'
              }}
            />
          </div>

          {tab === 'register' && (
            <div style={{ marginBottom: '1.1rem' }}>
              <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                EMAIL ADDRESS
              </label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@nkat.ai"
                style={{
                  width: '100%',
                  padding: '11px 14px',
                  borderRadius: '8px',
                  border: '1px solid #cbd5e1',
                  fontSize: '0.92rem',
                  outline: 'none',
                  color: '#0f172a'
                }}
              />
            </div>
          )}

          <div style={{ marginBottom: tab === 'register' ? '1.1rem' : '1.5rem' }}>
            <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
              PASSWORD
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              style={{
                width: '100%',
                padding: '11px 14px',
                borderRadius: '8px',
                border: '1px solid #cbd5e1',
                fontSize: '0.92rem',
                outline: 'none',
                color: '#0f172a'
              }}
            />
          </div>

          {tab === 'register' && (
            <div style={{ marginBottom: '1.5rem' }}>
              <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                ORGANIZATION NAME (OPTIONAL)
              </label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Default Organization"
                style={{
                  width: '100%',
                  padding: '11px 14px',
                  borderRadius: '8px',
                  border: '1px solid #cbd5e1',
                  fontSize: '0.92rem',
                  outline: 'none',
                  color: '#0f172a'
                }}
              />
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            style={{
              width: '100%',
              padding: '12px',
              background: '#000000',
              color: '#ffffff',
              border: 'none',
              borderRadius: '8px',
              fontWeight: 800,
              fontSize: '0.95rem',
              cursor: 'pointer',
              boxShadow: '0 4px 14px rgba(0, 0, 0, 0.3)',
              transition: 'all 0.2s ease'
            }}
          >
            {loading ? 'Authenticating...' : (tab === 'login' ? 'Sign In & Launch Console' : 'Create Account & Enter Platform')}
          </button>
        </form>

        {/* Divider */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          margin: '1.5rem 0',
          color: '#94a3b8',
          fontSize: '0.75rem',
          fontWeight: 600
        }}>
          <div style={{ flex: 1, height: '1px', background: '#e2e8f0' }}></div>
          <span>OR CONTINUE WITH</span>
          <div style={{ flex: 1, height: '1px', background: '#e2e8f0' }}></div>
        </div>

        {/* Google OAuth Button */}
        <button
          onClick={handleGoogleAuth}
          disabled={loading}
          style={{
            width: '100%',
            padding: '11px',
            background: '#ffffff',
            color: '#1e293b',
            border: '1px solid #cbd5e1',
            borderRadius: '8px',
            fontWeight: 700,
            fontSize: '0.9rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '10px',
            boxShadow: '0 2px 6px rgba(0,0,0,0.06)'
          }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"/>
            <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.24v3.15C3.26 21.39 7.37 24 12 24z"/>
            <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.24C.45 8.16 0 9.99 0 12s.45 3.84 1.24 5.42l4.04-3.15z"/>
            <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.37 0 3.26 2.61 1.24 6.58l4.04 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
          </svg>
          Continue with Google
        </button>
      </div>

      <footer style={{ marginTop: '2.5rem', color: '#64748b', fontSize: '0.78rem' }} className="mono-text">
        NKAT AI Threat Sentinel v20 • Strictly Authorized Security Operations
      </footer>
    </div>
  );
}
