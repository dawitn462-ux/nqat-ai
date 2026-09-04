import React, { useState, useEffect } from 'react';
import { Shield, Activity, Lock, Cpu } from 'lucide-react';

export default function SecureWebTicker({ variant = 'hero' }) {
  const [displayText, setDisplayText] = useState('');
  const fullPhrases = [
    "SECURE YOUR WEB,",
    "DEFEND YOUR INFRASTRUCTURE,",
    "PREVENT ZERO-DAY THREATS,",
    "AUTONOMOUS AI CORRELATION,"
  ];
  const [phraseIndex, setPhraseIndex] = useState(0);
  const [isDeleting, setIsDeleting] = useState(false);
  const [typingSpeed, setTypingSpeed] = useState(90);

  useEffect(() => {
    const currentPhrase = fullPhrases[phraseIndex];

    const timer = setTimeout(() => {
      if (!isDeleting) {
        setDisplayText(currentPhrase.substring(0, displayText.length + 1));
        setTypingSpeed(80);

        if (displayText === currentPhrase) {
          setTimeout(() => setIsDeleting(true), 1800);
        }
      } else {
        setDisplayText(currentPhrase.substring(0, displayText.length - 1));
        setTypingSpeed(40);

        if (displayText === '') {
          setIsDeleting(false);
          setPhraseIndex((prev) => (prev + 1) % fullPhrases.length);
        }
      }
    }, typingSpeed);

    return () => clearTimeout(timer);
  }, [displayText, isDeleting, phraseIndex, typingSpeed]);

  if (variant === 'ribbon') {
    return (
      <div className="secure-web-ribbon-container">
        <div className="secure-web-ribbon-track">
          <div className="secure-web-ribbon-content">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#38bdf8' }}>
              <Shield size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>AUTONOMOUS NQAT AI VULNERABILITY ASSISTANT</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ffffff' }}>
              <Activity size={14} /> REAL-TIME THREAT CORRELATION
            </span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#38bdf8' }}>
              <Lock size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>MACHINE LEARNING EXPLOIT PREDICTION</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}>
              <Cpu size={14} /> HUMAN-IN-THE-LOOP CONTROL
            </span>
            <span className="dot-separator">•</span>
          </div>
          <div className="secure-web-ribbon-content" aria-hidden="true">
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#38bdf8' }}>
              <Shield size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>AUTONOMOUS NQAT AI VULNERABILITY ASSISTANT</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ffffff' }}>
              <Activity size={14} /> REAL-TIME THREAT CORRELATION
            </span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#38bdf8' }}>
              <Lock size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>MACHINE LEARNING EXPLOIT PREDICTION</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ef4444' }}>
              <Cpu size={14} /> HUMAN-IN-THE-LOOP CONTROL
            </span>
            <span className="dot-separator">•</span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="secure-web-hero-badge" style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '10px',
      background: 'rgba(239, 68, 68, 0.12)',
      border: '1.5px solid #ef4444',
      padding: '8px 20px',
      borderRadius: '9999px',
      backdropFilter: 'blur(12px)',
      boxShadow: '0 0 20px rgba(239, 68, 68, 0.3)'
    }}>
      <div className="secure-web-pulse-ring" style={{ borderColor: '#ef4444' }} />
      <div className="secure-web-badge-inner" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
        <Shield size={18} style={{ color: '#ef4444', flexShrink: 0 }} />
        <span className="secure-web-typewriter" style={{
          color: '#ef4444',
          fontWeight: 900,
          fontSize: '1rem',
          letterSpacing: '0.8px',
          fontFamily: 'var(--font-mono)',
          textShadow: '0 0 12px rgba(239, 68, 68, 0.5)'
        }}>
          {displayText}
          <span className="typewriter-cursor" style={{ color: '#ef4444', fontWeight: 900 }}>|</span>
        </span>
        <span className="secure-sub-tag" style={{
          fontSize: '0.72rem',
          fontWeight: 800,
          color: '#000000',
          background: '#ffffff',
          padding: '2px 8px',
          borderRadius: '10px',
          letterSpacing: '0.5px'
        }}>
          NEXT-GEN CYBER DEFENSE
        </span>
      </div>
    </div>
  );
}
