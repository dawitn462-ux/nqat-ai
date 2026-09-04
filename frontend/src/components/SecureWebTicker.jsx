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
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
              <Shield size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>AUTONOMOUS NQAT AI VULNERABILITY ASSISTANT</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ffffff' }}>
              <Activity size={14} /> REAL-TIME THREAT CORRELATION
            </span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
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
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
              <Shield size={14} /> SECURE YOUR WEB,
            </span>
            <span className="dot-separator">•</span>
            <span>AUTONOMOUS NQAT AI VULNERABILITY ASSISTANT</span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#ffffff' }}>
              <Activity size={14} /> REAL-TIME THREAT CORRELATION
            </span>
            <span className="dot-separator">•</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
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
    <div className="secure-web-hero-badge">
      <div className="secure-web-pulse-ring" />
      <div className="secure-web-badge-inner">
        <Shield size={16} style={{ color: '#10b981' }} />
        <span className="secure-web-typewriter">
          {displayText}
          <span className="typewriter-cursor">|</span>
        </span>
        <span className="secure-sub-tag">NEXT-GEN CYBER DEFENSE</span>
      </div>
    </div>
  );
}
