import React, { useState, useEffect } from 'react';

export default function NotificationPanel({ isOpen, onClose }) {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(false);

  const token = localStorage.getItem('nkat_jwt_token');
  const authHeaders = token
    ? { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }
    : { 'Content-Type': 'application/json' };

  const fetchNotifications = async () => {
    try {
      setLoading(true);
      const res = await fetch('/api/v1/notifications', { headers: authHeaders });
      if (res.ok) {
        const data = await res.json();
        setNotifications(data);
      }
    } catch (err) {
      console.error('Failed to fetch notifications:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchNotifications();
    }
  }, [isOpen]);

  const handleMarkRead = async (id) => {
    try {
      const res = await fetch(`/api/v1/notifications/${id}/read`, {
        method: 'PATCH',
        headers: authHeaders,
        body: JSON.stringify({ is_read: true })
      });
      if (res.ok) {
        fetchNotifications();
      }
    } catch (err) {
      console.error('Mark read error:', err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      const res = await fetch('/api/v1/notifications/read-all', {
        method: 'POST',
        headers: authHeaders
      });
      if (res.ok) {
        fetchNotifications();
      }
    } catch (err) {
      console.error('Mark all read error:', err);
    }
  };

  const handleDelete = async (id) => {
    try {
      const res = await fetch(`/api/v1/notifications/${id}`, {
        method: 'DELETE',
        headers: authHeaders
      });
      if (res.ok) {
        fetchNotifications();
      }
    } catch (err) {
      console.error('Delete notification error:', err);
    }
  };

  if (!isOpen) return null;

  const unreadCount = notifications.filter(n => !n.is_read).length;

  return (
    <div style={{
      position: 'fixed',
      top: '70px',
      right: '2rem',
      width: '420px',
      maxHeight: '520px',
      zIndex: 9999,
      background: 'rgba(10, 10, 10, 0.98)',
      border: '2px solid #000000',
      borderRadius: '14px',
      boxShadow: '0 20px 50px rgba(0,0,0,0.9)',
      padding: '1.25rem',
      color: '#ffffff',
      display: 'flex',
      flexDirection: 'column'
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '2px solid #000000', paddingBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '1.2rem' }}></span>
          <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 800, color: '#ffffff' }}>
            In-App Security Alerts
          </h3>
          {unreadCount > 0 && (
            <span style={{
              background: '#ef4444',
              color: '#ffffff',
              borderRadius: '10px',
              padding: '2px 8px',
              fontSize: '0.75rem',
              fontWeight: 800
            }}>
              {unreadCount} new
            </span>
          )}
        </div>
        <button onClick={onClose} style={{ background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: '1rem' }}>
        </button>
      </div>

      {/* Action Bar */}
      {notifications.length > 0 && (
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.75rem' }}>
          <button
            onClick={handleMarkAllRead}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#38bdf8',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer'
            }}
          >
            Mark All as Read
          </button>
        </div>
      )}

      {/* Notification Stream */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {loading && notifications.length === 0 ? (
          <p style={{ color: '#94a3b8', fontSize: '0.85rem', textAlign: 'center' }}>Loading alerts...</p>
        ) : notifications.length === 0 ? (
          <p style={{ color: '#64748b', fontSize: '0.85rem', textAlign: 'center', fontStyle: 'italic', padding: '1rem 0' }}>
            No security notifications detected. All verified target re-scans clear!
          </p>
        ) : (
          notifications.map((n) => {
            const sev = (n.severity || 'INFO').toUpperCase();
            const isCrit = sev === 'CRITICAL';
            const isHigh = sev === 'HIGH';
            const isMed = sev === 'MEDIUM';
            const badgeColor = isCrit ? '#ef4444' : isHigh ? '#f97316' : isMed ? '#eab308' : '#ffffff';

            return (
              <div
                key={n.id}
                style={{
                  background: n.is_read ? 'rgba(255,255,255,0.02)' : 'rgba(255, 255, 255, 0.05)',
                  border: `1px solid ${n.is_read ? 'rgba(255,255,255,0.08)' : badgeColor}`,
                  borderRadius: '10px',
                  padding: '10px 12px',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '4px' }}>
                  <span style={{
                    fontSize: '0.7rem',
                    fontWeight: 800,
                    padding: '1px 6px',
                    borderRadius: '8px',
                    background: `${badgeColor}22`,
                    color: badgeColor,
                    border: `1px solid ${badgeColor}`
                  }}>
                    {sev}
                  </span>
                  <span style={{ fontSize: '0.72rem', color: '#64748b' }}>
                    {strTime(n.created_at)}
                  </span>
                </div>
                <div style={{ fontWeight: 700, fontSize: '0.88rem', color: '#ffffff', marginBottom: '4px' }}>
                  {n.title}
                </div>
                <div style={{ fontSize: '0.8rem', color: '#cbd5e1', lineHeight: 1.4, marginBottom: '8px' }}>
                  {n.message}
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  {!n.is_read && (
                    <button
                      onClick={() => handleMarkRead(n.id)}
                      style={{ background: 'transparent', border: 'none', color: '#38bdf8', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer' }}
                    >
                      Mark Read
                    </button>
                  )}
                  <button
                    onClick={() => handleDelete(n.id)}
                    style={{ background: 'transparent', border: 'none', color: '#ef4444', fontSize: '0.75rem', cursor: 'pointer' }}
                  >
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

function strTime(iso) {
  if (!iso) return '';
  try {
    const d = new Date(iso);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return String(iso).slice(11, 16);
  }
}
