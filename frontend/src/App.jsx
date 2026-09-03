import React, { useState } from 'react';
import PublicLandingPage from './components/PublicLandingPage';
import CyberBackground from './components/CyberBackground';

export default function App() {
  const [user, setUser] = useState(() => {
    // Check URL parameters for direct email link click verification
    if (typeof window !== 'undefined' && window.location.search) {
      const params = new URLSearchParams(window.location.search);
      const isVerified = params.get('verified') === 'true';
      const token = params.get('token');
      const username = params.get('user');

      if (isVerified && token) {
        const sessionData = {
          access_token: token,
          token_type: 'bearer',
          user_id: 99,
          username: username || 'Verified User',
          email: params.get('email') || `${username}@domain.com`,
          role: 'analyst',
          organization_id: 99,
          organization_name: `${username}'s Organization`,
          is_email_verified: true
        };
        localStorage.setItem('nkat_jwt_token', token);
        localStorage.setItem('nkat_user_session', JSON.stringify(sessionData));
        // Clean URL params cleanly
        window.history.replaceState({}, document.title, window.location.pathname);
        return sessionData;
      }
    }

    const token = localStorage.getItem('nkat_jwt_token');
    const saved = localStorage.getItem('nkat_user_session');
    if (token && saved) {
      try { return JSON.parse(saved); } catch { return null; }
    }
    return null;
  });

  const handleAuthSuccess = (data) => {
    setUser(data);
    if (data.access_token) {
      localStorage.setItem('nkat_jwt_token', data.access_token);
    }
    localStorage.setItem('nkat_user_session', JSON.stringify(data));
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('nkat_jwt_token');
    localStorage.removeItem('nkat_user_session');
  };

  return (
    <div className="app-container">
      <CyberBackground />

      <PublicLandingPage
        user={user}
        onAuthSuccess={handleAuthSuccess}
        onLogout={handleLogout}
      />
    </div>
  );
}
