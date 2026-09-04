import React, { useState, useEffect } from 'react';
import NotificationPanel from './NotificationPanel';
import AdminPanelModal from './AdminPanelModal';
import { Bell, User, Lock, LogOut, ShieldAlert } from 'lucide-react';

export default function Navbar({ user, onOpenAuth, onLogout }) {
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const [isAdminOpen, setIsAdminOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);

  const fetchUnreadCount = async () => {
    try {
      const token = localStorage.getItem('nkat_jwt_token');
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch('/api/v1/notifications?unread_only=true', { headers });
      if (res.ok) {
        const data = await res.json();
        setUnreadCount(data.length);
      }
    } catch {
      // Ignore background errors
    }
  };

  useEffect(() => {
    fetchUnreadCount();
    const interval = setInterval(fetchUnreadCount, 15000);
    return () => clearInterval(interval);
  }, []);

  const isAdmin = user && (user.role === 'admin' || user.username === 'admin');

  return (
    <header style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '1.2rem 3rem',
      background: 'rgba(5, 6, 9, 0.88)',
      backdropFilter: 'blur(20px)',
      borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
      position: 'sticky',
      top: 0,
      zIndex: 100
    }}>
      {/* Brand & Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
        <div style={{
          width: '36px',
          height: '36px',
          borderRadius: '8px',
          background: 'linear-gradient(135deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.04) 100%)',
          border: '1px solid rgba(255, 255, 255, 0.4)',
          boxShadow: '0 0 16px rgba(255, 255, 255, 0.25)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          flexShrink: 0
        }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M12 3L22 20H2L12 3Z" fill="#FFFFFF" stroke="#FFFFFF" strokeWidth="1" strokeLinejoin="round"/>
            <path d="M12 9.5L16.5 17.5H7.5L12 9.5Z" fill="#050609"/>
          </svg>
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="brand-font" style={{ fontFamily: "'Outfit', 'Syne', sans-serif", fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.5px' }}>Nqat AI</span>
            <span className="aegis-badge-pill" style={{ padding: '2px 8px', fontSize: '0.65rem' }}>
              v2.0
            </span>
          </div>
          <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.8px' }}>WEBSITE VULNERABILITY ASSISTANT</span>
        </div>
      </div>

      {/* System Status Pill & Auth Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.2rem' }}>
        <div className="mono-text" style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '0.76rem',
          color: '#e2e8f0',
          background: 'rgba(255, 255, 255, 0.04)',
          padding: '6px 14px',
          borderRadius: '9999px',
          border: '2px solid #000000'
        }}>
          <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }}></span>
          <span>Engine Online</span>
        </div>

        {/* Notification Bell Button */}
        <button
          onClick={() => setIsNotifOpen(!isNotifOpen)}
          style={{
            position: 'relative',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '2px solid #000000',
            color: '#ffffff',
            borderRadius: '9999px',
            padding: '8px 14px',
            fontSize: '0.88rem',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Bell size={16} />
          {unreadCount > 0 && (
            <span style={{
              background: '#ef4444',
              color: '#ffffff',
              borderRadius: '50%',
              width: '18px',
              height: '18px',
              fontSize: '0.7rem',
              fontWeight: 800,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              {unreadCount}
            </span>
          )}
        </button>

        {user ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', textTransform: 'uppercase', fontSize: '0.8rem', fontWeight: 700, color: '#ffffff', background: 'rgba(255, 255, 255, 0.08)', padding: '6px 14px', borderRadius: '9999px', border: '2px solid #000000' }}>
              <User size={14} /> {user.username} <span style={{ color: '#10b981', fontSize: '0.72rem' }}>({user.role})</span>
            </div>
            <button onClick={onLogout} style={{
              background: 'transparent',
              color: '#94a3b8',
              border: '2px solid #000000',
              padding: '6px 14px',
              borderRadius: '9999px',
              fontSize: '0.8rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}>
              <LogOut size={14} /> Logout
            </button>
          </div>
        ) : (
          <button onClick={onOpenAuth} className="btn-aegis-primary" style={{ padding: '0.65rem 1.4rem', fontSize: '0.88rem' }}>
            <Lock size={15} /> Sign In
          </button>
        )}
      </div>

      <NotificationPanel isOpen={isNotifOpen} onClose={() => setIsNotifOpen(false)} />
      <AdminPanelModal isOpen={isAdminOpen} onClose={() => setIsAdminOpen(false)} />
    </header>
  );
}
