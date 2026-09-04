import React, { useState } from 'react';

export default function AuthLandingPage({ onAuthSuccess }) {
  const [tab, setTab] = useState('login'); // 'login' | 'register' | 'verify'
  const [regStep, setRegStep] = useState(1); // 1: Basic Info, 2: Password & Org
  
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  
  // Verification states
  const [verifyIdentity, setVerifyIdentity] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [infoMsg, setInfoMsg] = useState('');

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setError('');
    setInfoMsg('');

    if (tab === 'register' && regStep === 1) {
      if (!username.trim() || !email.trim()) {
        setError('Please enter both a username and email address to continue.');
        return;
      }
      setRegStep(2);
      setLoading(false);
      return;
    }

    setLoading(true);

    try {
      if (tab === 'verify') {
        const res = await fetch('/api/v1/auth/verify-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: verifyIdentity || email || username,
            verification_code: verificationCode.trim()
          })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Email verification failed. Please check the 6-digit code.');
        }

        onAuthSuccess(data);
        return;
      }

      const endpoint = tab === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register';
      const payload = tab === 'login' 
        ? { username, password }
        : { username, email, password, organization_name: orgName };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      let data = {};
      const resText = await res.text();
      if (resText) {
        try { data = JSON.parse(resText); } catch { data = { detail: resText }; }
      }

      if (!res.ok) {
        throw new Error(data.detail || `Authentication failed (HTTP ${res.status})`);
      }

      if (tab === 'register' || (!data.is_email_verified && data.role !== 'admin' && data.requires_verification)) {
        setVerifyIdentity(data.email || email || username);
        setTab('verify');
        if (data.verification_code) {
          setVerificationCode(data.verification_code);
        }
        const codeNotice = data.verification_code ? ` (OTP Code: ${data.verification_code})` : '';
        setInfoMsg(`Verification code generated for '${data.email || email}'!${codeNotice}`);
      } else {
        onAuthSuccess(data);
      }
    } catch (err) {
      setError(err.message || 'Authentication error.');
    } finally {
      setLoading(false);
    }
  };

  const handleResendCode = async () => {
    setError('');
    setInfoMsg('');
    setLoading(true);

    try {
      const res = await fetch('/api/v1/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity: verifyIdentity || email || username
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to resend email verification code.');
      }

      if (data.verification_code) {
        setVerificationCode(data.verification_code);
      }
      setInfoMsg(data.message || `Fresh 6-digit verification code sent to ${verifyIdentity || email}!`);
    } catch (err) {
      setError(err.message || 'Error resending verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickAccountSelect = async (selectedEmail) => {
    setEmail(selectedEmail);
    setUsername(selectedEmail.split('@')[0]);
    setError('');
    setLoading(true);

    try {
      const res = await fetch('/api/v1/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: selectedEmail,
          name: selectedEmail.split('@')[0]
        })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Google Account authentication failed');
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

    // Timeout safety fallback in case Google GIS popup is closed without callback
    const safetyTimer = setTimeout(() => setLoading(false), 7000);

    const googleClientId = import.meta.env.VITE_GOOGLE_CLIENT_ID || "771235983799-8va90kksvuueb7pusfl3q1gv1vtg7ohd.apps.googleusercontent.com";

    if (window.google?.accounts?.oauth2) {
      try {
        const client = window.google.accounts.oauth2.initTokenClient({
          client_id: googleClientId,
          scope: 'email profile',
          prompt: 'select_account',
          callback: async (tokenResponse) => {
            if (tokenResponse && tokenResponse.access_token) {
              try {
                const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                  headers: { Authorization: `Bearer ${tokenResponse.access_token}` }
                });
                const googleProfile = await userRes.json();

                const res = await fetch('/api/v1/auth/google', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    email: googleProfile.email,
                    name: googleProfile.name || googleProfile.given_name || googleProfile.email.split('@')[0],
                    id_token: tokenResponse.access_token
                  })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Google authentication failed');
                onAuthSuccess(data);
              } catch (authErr) {
                setError(authErr.message || 'Failed validating Google Account credentials');
              } finally {
                setLoading(false);
              }
            } else {
              setLoading(false);
            }
          }
        });
        client.requestAccessToken({ prompt: 'select_account' });
        return;
      } catch (err) {
        console.warn('GIS Token client error, falling back to popup window:', err);
      }
    }

    const redirectUri = window.location.origin;
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(googleClientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=token&scope=${encodeURIComponent('email profile')}&prompt=select_account`;

    const width = 500;
    const height = 650;
    const left = window.screenX + (window.outerWidth - width) / 2;
    const top = window.screenY + (window.outerHeight - height) / 2;

    const popup = window.open(
      authUrl,
      'Google_Account_Chooser',
      `width=${width},height=${height},top=${top},left=${left},scrollbars=yes,status=1`
    );

    if (!popup) {
      setError('Google Sign-In popup was blocked by browser. Please allow popups.');
      setLoading(false);
      return;
    }

    const checkPopupInterval = setInterval(async () => {
      try {
        if (!popup || popup.closed) {
          clearInterval(checkPopupInterval);
          setLoading(false);
          return;
        }

        if (popup.location && popup.location.origin === window.location.origin) {
          const hash = popup.location.hash;
          popup.close();
          clearInterval(checkPopupInterval);

          if (hash && hash.includes('access_token=')) {
            const params = new URLSearchParams(hash.substring(1));
            const accessToken = params.get('access_token');
            if (accessToken) {
              const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                headers: { Authorization: `Bearer ${accessToken}` }
              });
              const googleProfile = await userRes.json();

              const res = await fetch('/api/v1/auth/google', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  email: googleProfile.email,
                  name: googleProfile.name || googleProfile.email.split('@')[0],
                  id_token: accessToken
                })
              });
              const data = await res.json();
              if (!res.ok) throw new Error(data.detail || 'Google Auth endpoint error');
              onAuthSuccess(data);
            }
          }
        }
      } catch (e) {
        // Cross-origin checks expected during Google account selection
      }
    }, 500);
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
      zIndex: 10,
      background: 'radial-gradient(circle at 50% 10%, #0f172a 0%, #020617 100%)'
    }}>
      {/* Responsive Inline CSS Styles */}
      <style>{`
        .auth-split-grid {
          display: grid;
          grid-template-columns: 1.1fr 1fr;
          gap: 2rem;
          width: 100%;
          max-width: 980px;
          background: #ffffff;
          border-radius: 20px;
          padding: 2.25rem;
          box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7), 0 0 35px rgba(0, 240, 255, 0.15);
          border: 1px solid rgba(255, 255, 255, 0.2);
        }
        @media (max-width: 840px) {
          .auth-split-grid {
            grid-template-columns: 1fr;
            padding: 1.5rem;
          }
        }
        .google-acc-card {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 10px 14px;
          border-radius: 12px;
          border: 1px solid #e2e8f0;
          background: #f8fafc;
          cursor: pointer;
          transition: all 0.2s ease;
        }
        .google-acc-card:hover {
          background: #f1f5f9;
          border-color: #cbd5e1;
          transform: translateY(-2px);
        }
      `}</style>

      {/* Top Brand Header */}
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
        <h1 style={{ fontFamily: "'Outfit', 'Syne', sans-serif", fontSize: '2.4rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.5px', margin: 0 }}>
          Nqat AI <span style={{ color: '#ffffff' }}>SENTINEL</span>
        </h1>
        <p style={{ fontSize: '0.95rem', color: '#94a3b8', marginTop: '6px', maxWidth: '640px', lineHeight: 1.5 }}>
          Local-First Autonomous Web Vulnerability Scanner & AI Threat Correlation Platform. Sign in or register to access telemetry, target verification, and autonomous agent triage.
        </p>

        {/* Badges */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '1rem', flexWrap: 'wrap' }}>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(56, 189, 248, 0.1)', color: '#38bdf8', border: '1px solid #38bdf8', padding: '3px 10px', borderRadius: '12px' }}>
            TLS 1.3 Encrypted
          </span>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(255, 255, 255, 0.08)', color: '#e2e8f0', border: '1px solid rgba(255,255,255,0.2)', padding: '3px 10px', borderRadius: '12px' }}>
            Enterprise Multi-Tenant
          </span>
          <span className="mono-text" style={{ fontSize: '0.75rem', background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid #38bdf8', padding: '3px 10px', borderRadius: '12px' }}>
            NIST / CISA KEV Sync
          </span>
        </div>
      </div>

      {/* Flexible Side-by-Side Main Container */}
      <div className="auth-split-grid">
        {/* LEFT COLUMN: Google Account Chooser & Registration Requirements */}
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          borderRight: '1px solid #f1f5f9',
          paddingRight: '1.5rem'
        }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '1rem' }}>
              <svg width="24" height="24" viewBox="0 0 24 24">
                <path fill="#4285F4" d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17z"/>
                <path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.1-6.72-4.93H1.24v3.15C3.26 21.39 7.37 24 12 24z"/>
                <path fill="#FBBC05" d="M5.28 14.27c-.25-.72-.38-1.49-.38-2.27s.13-1.55.38-2.27V6.58H1.24C.45 8.16 0 9.99 0 12s.45 3.84 1.24 5.42l4.04-3.15z"/>
                <path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.37 0 3.26 2.61 1.24 6.58l4.04 3.15c.95-2.83 3.6-4.98 6.72-4.98z"/>
              </svg>
              <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#0f172a' }}>
                Google Account Quick Sign-In
              </h3>
            </div>
            <p style={{ fontSize: '0.82rem', color: '#64748b', margin: '0 0 1rem 0' }}>
              Sign in with your Google account to access your security dashboard:
            </p>

            {/* Main Google Popup Button */}
            <button
              type="button"
              onClick={handleGoogleAuth}
              disabled={loading}
              style={{
                width: '100%',
                padding: '11px',
                background: '#ffffff',
                color: '#1e293b',
                border: '2px solid #cbd5e1',
                borderRadius: '10px',
                fontWeight: 800,
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
              Continue with Google (Browser Chooser)
            </button>
          </div>

          {/* Registration Requirements Box */}
          <div style={{
            marginTop: '1.5rem',
            background: '#f8fafc',
            border: '1px solid #e2e8f0',
            borderRadius: '12px',
            padding: '14px'
          }}>
            <h4 style={{ margin: '0 0 8px 0', fontSize: '0.82rem', fontWeight: 800, color: '#0f172a' }}>
              🛡️ Registration Requirements
            </h4>
            <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.78rem', color: '#475569', lineHeight: 1.6 }}>
              <li><strong>Real Email Required:</strong> 6-digit OTP code sent directly to inbox.</li>
              <li><strong>Password Security:</strong> Minimum 6+ characters recommended.</li>
              <li><strong>Org Scoping:</strong> Multi-tenant isolation for security telemetry.</li>
            </ul>
          </div>
        </div>

        {/* RIGHT COLUMN: Form & Step Progression */}
        <div>
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
              onClick={() => { setTab('login'); setError(''); setInfoMsg(''); setRegStep(1); setLoading(false); }}
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
                setInfoMsg('');
                setRegStep(1);
                setLoading(false);
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

          {/* Info Message Alert */}
          {infoMsg && (
            <div style={{
              background: '#eff6ff',
              color: '#1e40af',
              border: '1px solid #bfdbfe',
              padding: '10px 14px',
              borderRadius: '8px',
              fontSize: '0.82rem',
              marginBottom: '1.25rem'
            }}>
              {infoMsg}
            </div>
          )}

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

          {/* Form Content */}
          <form onSubmit={handleSubmit}>
            {tab === 'verify' ? (
              <div>
                <div style={{ background: '#f8fafc', border: '1px solid #cbd5e1', borderRadius: '10px', padding: '12px 14px', marginBottom: '1.25rem', textAlign: 'center' }}>
                  <span style={{ fontSize: '0.82rem', color: '#475569', display: 'block', marginBottom: '8px' }}>
                    A 6-digit OTP verification code was sent to <strong>{verifyIdentity || email}</strong>. Please check your email inbox and enter the code below.
                  </span>
                  <button
                    type="button"
                    onClick={handleResendCode}
                    style={{
                      background: '#f1f5f9',
                      border: '1px solid #cbd5e1',
                      color: '#0f172a',
                      borderRadius: '8px',
                      padding: '6px 14px',
                      fontSize: '0.78rem',
                      fontWeight: 800,
                      cursor: 'pointer'
                    }}
                  >
                    Resend Verification Email
                  </button>
                </div>

                <div style={{ marginBottom: '1.5rem' }}>
                  <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                    ENTER 6-DIGIT OTP VERIFICATION CODE
                  </label>
                  <input
                    type="text"
                    required
                    maxLength={10}
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    placeholder="e.g. 123456"
                    style={{
                      width: '100%',
                      padding: '12px 14px',
                      borderRadius: '8px',
                      border: '2px solid #0284c7',
                      fontSize: '1.2rem',
                      letterSpacing: '4px',
                      fontWeight: 800,
                      textAlign: 'center',
                      outline: 'none',
                      color: '#0f172a'
                    }}
                  />
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    width: '100%',
                    padding: '12px',
                    background: '#0284c7',
                    color: '#ffffff',
                    border: 'none',
                    borderRadius: '8px',
                    fontWeight: 800,
                    fontSize: '0.95rem',
                    cursor: 'pointer',
                    boxShadow: '0 4px 14px rgba(2, 132, 199, 0.4)',
                    transition: 'all 0.2s ease'
                  }}
                >
                  {loading ? 'Verifying Code...' : 'Verify Email & Enter Dashboard'}
                </button>
              </div>
            ) : tab === 'register' ? (
              <div>
                {/* Step Indicator */}
                <div style={{ display: 'flex', gap: '8px', marginBottom: '1.25rem' }}>
                  <div style={{ flex: 1, height: '4px', background: regStep >= 1 ? '#0284c7' : '#e2e8f0', borderRadius: '2px' }}></div>
                  <div style={{ flex: 1, height: '4px', background: regStep >= 2 ? '#0284c7' : '#e2e8f0', borderRadius: '2px' }}></div>
                </div>

                {regStep === 1 ? (
                  <div>
                    <div style={{ marginBottom: '1.1rem' }}>
                      <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                        USERNAME
                      </label>
                      <input
                        type="text"
                        required
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="e.g. security_analyst"
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

                    <div style={{ marginBottom: '1.5rem' }}>
                      <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                        REAL EMAIL ADDRESS (FOR OTP CODE)
                      </label>
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="user@gmail.com"
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

                    <button
                      type="button"
                      onClick={() => {
                        if (!username.trim() || !email.trim()) {
                          setError('Please fill in both Username and Email address to proceed.');
                          return;
                        }
                        setError('');
                        setRegStep(2);
                      }}
                      style={{
                        width: '100%',
                        padding: '12px',
                        background: '#0284c7',
                        color: '#ffffff',
                        border: 'none',
                        borderRadius: '8px',
                        fontWeight: 800,
                        fontSize: '0.95rem',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: '8px',
                        boxShadow: '0 4px 14px rgba(2, 132, 199, 0.3)'
                      }}
                    >
                      Next: Password & Org Setup &rarr;
                    </button>
                  </div>
                ) : (
                  <div>
                    <div style={{ marginBottom: '1.1rem' }}>
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

                    <div style={{ display: 'flex', gap: '10px' }}>
                      <button
                        type="button"
                        onClick={() => setRegStep(1)}
                        style={{
                          padding: '12px 18px',
                          background: '#f1f5f9',
                          color: '#475569',
                          border: '1px solid #cbd5e1',
                          borderRadius: '8px',
                          fontWeight: 700,
                          fontSize: '0.9rem',
                          cursor: 'pointer'
                        }}
                      >
                        &larr; Back
                      </button>
                      <button
                        type="submit"
                        disabled={loading}
                        style={{
                          flex: 1,
                          padding: '12px',
                          background: '#000000',
                          color: '#ffffff',
                          border: 'none',
                          borderRadius: '8px',
                          fontWeight: 800,
                          fontSize: '0.95rem',
                          cursor: 'pointer',
                          boxShadow: '0 4px 14px rgba(0, 0, 0, 0.3)'
                        }}
                      >
                        {loading ? 'Sending OTP Email...' : 'Complete Registration & Send OTP Email'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div>
                <div style={{ marginBottom: '1.1rem' }}>
                  <label className="mono-text" style={{ fontSize: '0.74rem', color: '#475569', fontWeight: 700, display: 'block', marginBottom: '6px' }}>
                    USERNAME OR EMAIL
                  </label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="e.g. admin or analyst@nkat.ai"
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

                <div style={{ marginBottom: '1.5rem' }}>
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
                  {loading ? 'Authenticating...' : 'Sign In & Launch Console'}
                </button>
              </div>
            )}
          </form>
        </div>
      </div>

      <footer style={{ marginTop: '2.5rem', color: '#64748b', fontSize: '0.78rem' }} className="mono-text">
        Nqat AI Threat Sentinel v2.0 • Strictly Authorized Security Operations
      </footer>
    </div>
  );
}
