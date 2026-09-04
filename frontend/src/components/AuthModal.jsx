import React, { useState } from 'react';
import { Mail, Lock, User, Building, AlertCircle, ArrowRight, ShieldCheck, RefreshCw, CheckCircle } from 'lucide-react';

export default function AuthModal({ isOpen, onClose, onAuthSuccess }) {
  const [tab, setTab] = useState('login'); // 'login' | 'register' | 'verify'
  const [identity, setIdentity] = useState('analyst@nkat.ai'); // Username or Email for login
  const [username, setUsername] = useState('analyst');
  const [email, setEmail] = useState('analyst@nkat.ai');
  const [password, setPassword] = useState('admin_secret_2026');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [orgName, setOrgName] = useState('');
  
  // Verification states
  const [verifyIdentity, setVerifyIdentity] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [infoMsg, setInfoMsg] = useState('');
  
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [pendingAuthData, setPendingAuthData] = useState(null);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setInfoMsg('');

    if (tab === 'register' && confirmPassword && password !== confirmPassword) {
      setError('Passwords do not match. Please re-enter passwords.');
      return;
    }

    setLoading(true);

    try {
      if (tab === 'verify') {

        // Handle Email Verification Step
        const res = await fetch('/api/v1/auth/verify-email', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            identity: verifyIdentity || identity || email,
            verification_code: verificationCode.trim()
          })
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Email verification code failed. Please check the 6-digit code.');
        }

        onAuthSuccess(data);
        onClose();
        return;
      }

      const endpoint = tab === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register';
      const payload = tab === 'login' 
        ? { username: identity, password }
        : { username, email, password, organization_name: orgName };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      let data = {};
      const resText = await res.text();
      if (resText) {
        try {
          data = JSON.parse(resText);
        } catch {
          data = { detail: resText };
        }
      }

      if (!res.ok) {
        throw new Error(data.detail || `Authentication failed (HTTP ${res.status})`);
      }

      // If user registered or logged in, check if email is verified
      if (tab === 'register' || (!data.is_email_verified && data.role !== 'admin')) {
        setPendingAuthData(data);
        setVerifyIdentity(data.email || email || username);
        setTab('verify');
        setInfoMsg(` Real verification email dispatched to '${data.email || email}'! Enter your 6-digit OTP code below.`);
      } else {
        onAuthSuccess(data);
        onClose();
      }
    } catch (err) {
      setError(err.message || 'Network or server authentication error.');
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
          identity: verifyIdentity || email || identity
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || 'Failed to resend email verification code.');
      }

      setPendingAuthData(data);
      setInfoMsg(data.message || `Fresh 6-digit verification code generated for ${verifyIdentity || email}!`);
    } catch (err) {
      setError(err.message || 'Error resending verification code.');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleAuth = async () => {
    setError('');
    setLoading(true);

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
                if (onClose) onClose();
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
              if (onClose) onClose();
            }
          }
        }
      } catch (e) {
        // Cross-origin checks expected during Google account selection
      }
    }, 500);
  };

  return (
    <div className="auth-modal-overlay" onClick={onClose} style={{ overflowY: 'auto', padding: '2rem 1rem' }}>
      <div className="auth-modal-box" onClick={(e) => e.stopPropagation()} style={{
        background: '#000000',
        border: '1px solid #1a1a1a',
        boxShadow: '0 24px 60px rgba(0, 0, 0, 0.95)',
        borderRadius: '24px',
        padding: '2.25rem',
        maxWidth: '460px',
        width: '100%',
        maxHeight: '88vh',
        overflowY: 'auto',
        color: '#ffffff'
      }}>
        
        {/* Close Button */}
        <button onClick={onClose} style={{
          position: 'absolute',
          top: '1.25rem',
          right: '1.25rem',
          background: 'none',
          border: 'none',
          fontSize: '1.4rem',
          cursor: 'pointer',
          color: '#64748b'
        }}></button>

        {/* Modal Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            width: '44px',
            height: '44px',
            borderRadius: '12px',
            background: tab === 'verify' ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' : 'linear-gradient(135deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.04) 100%)',
            margin: '0 auto 0.75rem',
            border: '1px solid #222222',
            boxShadow: '0 0 20px rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            {tab === 'verify' ? (
              <Mail size={22} color="#ffffff" />
            ) : (
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 3L22 20H2L12 3Z" fill="#FFFFFF" stroke="#FFFFFF" strokeWidth="1" strokeLinejoin="round"/>
                <path d="M12 9.5L16.5 17.5H7.5L12 9.5Z" fill="#000000"/>
              </svg>
            )}
          </div>
          <h2 className="heading-font" style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.3px' }}>
            {tab === 'verify' ? 'Verify Registered Email' : (tab === 'login' ? 'Sign In to Nqat AI' : 'Register New Account')}
          </h2>
          <div className="mono-text" style={{ fontSize: '0.74rem', color: '#94a3b8', marginTop: '4px', fontWeight: 700 }}>
            {tab === 'verify' ? ' Mandatory 6-Digit Email OTP Verification' : 'Enterprise Multi-Tenant Security Platform'}
          </div>
        </div>

        {/* Tabs Toggle (Sign In / Register Account) */}
        {tab !== 'verify' && (
          <div style={{
            display: 'flex',
            background: '#0a0a0a',
            borderRadius: '9999px',
            padding: '4px',
            marginBottom: '1.5rem',
            border: '1px solid #1a1a1a'
          }}>
            <button
              onClick={() => { setTab('login'); setError(''); setInfoMsg(''); setLoading(false); }}
              style={{
                flex: 1,
                padding: '9px',
                border: 'none',
                borderRadius: '9999px',
                fontWeight: 700,
                fontSize: '0.88rem',
                cursor: 'pointer',
                background: tab === 'login' ? '#ffffff' : 'transparent',
                color: tab === 'login' ? '#000000' : '#94a3b8',
                boxShadow: tab === 'login' ? '0 4px 14px rgba(255, 255, 255, 0.2)' : 'none',
                transition: 'all 0.25s ease'
              }}
            >
              Sign In
            </button>
            <button
              onClick={() => {
                setTab('register');
                setError('');
                setInfoMsg('');
                setLoading(false);
                if (username === 'analyst' || username === 'admin') setUsername('');
                if (email === 'analyst@nkat.ai') setEmail('');
                if (password === 'admin_secret_2026') setPassword('');
              }}
              style={{
                flex: 1,
                padding: '9px',
                border: 'none',
                borderRadius: '9999px',
                fontWeight: 700,
                fontSize: '0.88rem',
                cursor: 'pointer',
                background: tab === 'register' ? '#ffffff' : 'transparent',
                color: tab === 'register' ? '#000000' : '#94a3b8',
                boxShadow: tab === 'register' ? '0 4px 14px rgba(255, 255, 255, 0.2)' : 'none',
                transition: 'all 0.25s ease'
              }}
            >
              Register Account
            </button>
          </div>
        )}

        {/* Info Notification Banner */}
        {infoMsg && (
          <div className="mono-text" style={{
            background: '#0a0a0a',
            color: '#ffffff',
            border: '1px solid #222222',
            padding: '12px 14px',
            borderRadius: '12px',
            fontSize: '0.82rem',
            marginBottom: '1.25rem',
            lineHeight: 1.4
          }}>
            {infoMsg}
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mono-text" style={{
            background: 'rgba(239, 68, 68, 0.12)',
            color: '#f87171',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            padding: '10px 14px',
            borderRadius: '10px',
            fontSize: '0.8rem',
            marginBottom: '1.25rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <AlertCircle size={16} style={{ flexShrink: 0 }} /> {error}
          </div>
        )}

        {/* Auth / Verification Form */}
        <form onSubmit={handleSubmit}>
          {tab === 'verify' ? (
            <>
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                  REGISTERED EMAIL ADDRESS
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type="email"
                    required
                    value={verifyIdentity}
                    onChange={(e) => setVerifyIdentity(e.target.value)}
                    placeholder="user@domain.com"
                    style={{
                      width: '100%',
                      padding: '12px 14px 12px 40px',
                      borderRadius: '12px',
                      border: '1px solid #222222',
                      background: '#050505',
                      color: '#ffffff',
                      fontSize: '0.92rem',
                      outline: 'none'
                    }}
                  />
                  <Mail size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                </div>
              </div>

              <div style={{ background: '#0a0a0a', border: '1px solid #222222', borderRadius: '10px', padding: '12px 14px', marginBottom: '1.25rem', textAlign: 'center' }}>
                <span style={{ fontSize: '0.78rem', color: '#94a3b8', display: 'block', marginBottom: '8px' }}>
                  A 6-digit OTP verification code was sent to <strong>{verifyIdentity || email}</strong>. Please check your email inbox and enter the code above.
                </span>
                <button
                  type="button"
                  onClick={handleResendCode}
                  style={{
                    background: '#111111',
                    border: '1px solid #333333',
                    color: '#ffffff',
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
                <label style={{ fontSize: '0.78rem', color: '#ffffff', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                  ENTER 6-DIGIT VERIFICATION OTP CODE
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type="text"
                    required
                    maxLength={10}
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value)}
                    placeholder="e.g. 482915"
                    style={{
                      width: '100%',
                      padding: '14px 14px 14px 40px',
                      borderRadius: '12px',
                      border: '1px solid #333333',
                      background: '#050505',
                      color: '#ffffff',
                      fontSize: '1.2rem',
                      fontWeight: '800',
                      letterSpacing: '4px',
                      textAlign: 'center',
                      outline: 'none'
                    }}
                  />
                  <ShieldCheck size={20} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#ffffff' }} />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="btn-aegis-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.85rem', marginBottom: '1rem' }}
              >
                {loading ? 'Verifying Code...' : 'Confirm Email & Unlock Platform'} <CheckCircle size={16} />
              </button>

              <div style={{ display: 'flex', justifyContent: 'space-between', gap: '10px' }}>
                <button
                  type="button"
                  onClick={handleResendCode}
                  disabled={loading}
                  style={{
                    flex: 1,
                    background: 'rgba(255, 255, 255, 0.08)',
                    border: '1px solid rgba(255, 255, 255, 0.2)',
                    borderRadius: '10px',
                    color: '#e2e8f0',
                    padding: '8px 12px',
                    fontSize: '0.78rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '6px'
                  }}
                >
                  <RefreshCw size={14} /> Resend Verification Code
                </button>
                <button
                  type="button"
                  onClick={() => { setTab('login'); setError(''); setInfoMsg(''); }}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#94a3b8',
                    fontSize: '0.78rem',
                    fontWeight: 700,
                    cursor: 'pointer'
                  }}
                >
                  Back to Sign In
                </button>
              </div>
            </>
          ) : (
            <>
              {tab === 'login' ? (
                <div style={{ marginBottom: '1.1rem' }}>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                    EMAIL ADDRESS OR USERNAME
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      required
                      value={identity}
                      onChange={(e) => setIdentity(e.target.value)}
                      placeholder="analyst@nkat.ai or admin"
                      style={{
                        width: '100%',
                        padding: '12px 14px 12px 40px',
                        borderRadius: '12px',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        background: 'rgba(4, 6, 10, 0.8)',
                        color: '#ffffff',
                        fontSize: '0.92rem',
                        outline: 'none'
                      }}
                    />
                    <Mail size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                  </div>
                </div>
              ) : (
                <>
                  <div style={{ marginBottom: '1.1rem' }}>
                    <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                      USERNAME
                    </label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type="text"
                        required
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder="e.g. analyst"
                        style={{
                          width: '100%',
                          padding: '12px 14px 12px 40px',
                          borderRadius: '12px',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          background: 'rgba(4, 6, 10, 0.8)',
                          color: '#ffffff',
                          fontSize: '0.92rem',
                          outline: 'none'
                        }}
                      />
                      <User size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                    </div>
                  </div>

                  <div style={{ marginBottom: '1.1rem' }}>
                    <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                      EMAIL ADDRESS (REAL VERIFICATION DISPATCH)
                    </label>
                    <div style={{ position: 'relative' }}>
                      <input
                        type="email"
                        required
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        placeholder="user@domain.com"
                        style={{
                          width: '100%',
                          padding: '12px 14px 12px 40px',
                          borderRadius: '12px',
                          border: '1px solid rgba(255, 255, 255, 0.15)',
                          background: 'rgba(4, 6, 10, 0.8)',
                          color: '#ffffff',
                          fontSize: '0.92rem',
                          outline: 'none'
                        }}
                      />
                      <Mail size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                    </div>
                  </div>
                </>
              )}

              <div style={{ marginBottom: '1.1rem' }}>
                <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                  PASSWORD
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    style={{
                      width: '100%',
                      padding: '12px 14px 12px 40px',
                      borderRadius: '12px',
                      border: '1px solid rgba(255, 255, 255, 0.15)',
                      background: 'rgba(4, 6, 10, 0.8)',
                      color: '#ffffff',
                      fontSize: '0.92rem',
                      outline: 'none'
                    }}
                  />
                  <Lock size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                </div>
              </div>

              {tab === 'register' && (
                <div style={{ marginBottom: '1.1rem' }}>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                    CONFIRM PASSWORD
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="password"
                      required
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      placeholder="••••••••••••"
                      style={{
                        width: '100%',
                        padding: '12px 14px 12px 40px',
                        borderRadius: '12px',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        background: 'rgba(4, 6, 10, 0.8)',
                        color: '#ffffff',
                        fontSize: '0.92rem',
                        outline: 'none'
                      }}
                    />
                    <Lock size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                  </div>
                </div>
              )}


              {tab === 'register' && (
                <div style={{ marginBottom: '1.5rem' }}>
                  <label style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 700, display: 'block', marginBottom: '6px', letterSpacing: '0.5px' }}>
                    ORGANIZATION NAME (OPTIONAL)
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type="text"
                      value={orgName}
                      onChange={(e) => setOrgName(e.target.value)}
                      placeholder="Default Organization"
                      style={{
                        width: '100%',
                        padding: '12px 14px 12px 40px',
                        borderRadius: '12px',
                        border: '1px solid rgba(255, 255, 255, 0.15)',
                        background: 'rgba(4, 6, 10, 0.8)',
                        color: '#ffffff',
                        fontSize: '0.92rem',
                        outline: 'none'
                      }}
                    />
                    <Building size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: '#64748b' }} />
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={loading}
                className="btn-aegis-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.85rem' }}
              >
                {loading ? (tab === 'register' ? 'Registering Account & Sending OTP...' : 'Authenticating...') : (tab === 'login' ? 'Sign In & Continue' : 'Register Account & Send Email OTP')} <ArrowRight size={16} />
              </button>
            </>
          )}
        </form>

        {tab !== 'verify' && (
          <>
            {/* Divider */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              margin: '1.5rem 0',
              color: '#64748b',
              fontSize: '0.75rem',
              fontWeight: 700
            }}>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.1)' }}></div>
              <span>OR</span>
              <div style={{ flex: 1, height: '1px', background: 'rgba(255, 255, 255, 0.1)' }}></div>
            </div>

            {/* Continue with Google */}
            <div style={{ marginBottom: '1.25rem' }}>
              <button
                onClick={handleGoogleAuth}
                disabled={loading}
                className="btn-aegis-secondary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.8rem' }}
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
          </>
        )}

      </div>
    </div>
  );
}
