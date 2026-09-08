import React, { useState, useEffect, useRef } from 'react';

export default function QatLoadingScreen({ onComplete }) {
  const [isFadingOut, setIsFadingOut] = useState(false);
  const heroRef = useRef(null);
  const ringsRef = useRef(null);
  const coreRef = useRef(null);

  useEffect(() => {
    // 1. Mouse movement parallax effect
    const handleMouseMove = (event) => {
      if (!ringsRef.current || !coreRef.current) return;
      const x = (event.clientX / window.innerWidth - 0.5);
      const y = (event.clientY / window.innerHeight - 0.5);
      ringsRef.current.style.transform = `translate(-50%, -50%) translate(${x * 12}px, ${y * 12}px)`;
      coreRef.current.style.marginLeft = `${x * 8}px`;
      coreRef.current.style.marginTop = `${y * 8}px`;
    };

    const handleMouseLeave = () => {
      if (!ringsRef.current || !coreRef.current) return;
      ringsRef.current.style.transform = "translate(-50%, -50%)";
      coreRef.current.style.marginLeft = "0";
      coreRef.current.style.marginTop = "0";
    };

    const handleKeyDown = (e) => {
      if (e.key === 'Escape' || e.key === 'Enter' || e.key === ' ') {
        triggerComplete();
      }
    };

    const currentHero = heroRef.current;
    if (currentHero) {
      currentHero.addEventListener('mousemove', handleMouseMove);
      currentHero.addEventListener('mouseleave', handleMouseLeave);
    }
    window.addEventListener('keydown', handleKeyDown);

    // 2. Automatic animation sequence timer
    const autoTimer = setTimeout(() => {
      triggerComplete();
    }, 4200);

    return () => {
      if (currentHero) {
        currentHero.removeEventListener('mousemove', handleMouseMove);
        currentHero.removeEventListener('mouseleave', handleMouseLeave);
      }
      window.removeEventListener('keydown', handleKeyDown);
      clearTimeout(autoTimer);
    };
  }, []);

  const triggerComplete = () => {
    setIsFadingOut(true);
    setTimeout(() => {
      if (onComplete) onComplete();
    }, 700);
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 999999,
      background: '#020202',
      color: '#ffffff',
      fontFamily: "'Inter', sans-serif",
      overflow: 'hidden',
      opacity: isFadingOut ? 0 : 1,
      transform: isFadingOut ? 'scale(1.04)' : 'scale(1)',
      transition: 'opacity 0.7s cubic-bezier(0.4, 0, 0.2, 1), transform 0.7s cubic-bezier(0.4, 0, 0.2, 1)',
      pointerEvents: isFadingOut ? 'none' : 'auto'
    }}>
      <style>{`
        /* ATMOSPHERE AURA */
        .qat-aura {
          position: absolute;
          width: 650px;
          height: 650px;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          border-radius: 50%;
          background: radial-gradient(circle, rgba(255, 0, 0, .18), rgba(150, 0, 0, .07) 35%, transparent 70%);
          filter: blur(30px);
          animation: qatAuraPulse 3s ease-in-out infinite;
        }
        @keyframes qatAuraPulse {
          0%, 100% { transform: translate(-50%, -50%) scale(.8); opacity: .55; }
          50% { transform: translate(-50%, -50%) scale(1.15); opacity: 1; }
        }

        /* CYBER GRID */
        .qat-grid {
          position: absolute;
          width: 200%;
          height: 200%;
          left: -50%;
          top: 20%;
          background-image:
            linear-gradient(rgba(255, 0, 0, .075) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 0, 0, .075) 1px, transparent 1px);
          background-size: 60px 60px;
          transform: perspective(500px) rotateX(65deg);
          animation: qatGridMove 5s linear infinite;
        }
        @keyframes qatGridMove {
          from { background-position: 0 0; }
          to { background-position: 0 600px; }
        }

        /* ROTATING RINGS */
        .qat-rings {
          position: absolute;
          width: 520px;
          height: 520px;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          transition: transform 0.1s ease-out;
        }
        .qat-ring {
          position: absolute;
          inset: 0;
          border-radius: 50%;
          border: 1px solid rgba(255, 0, 0, .32);
          box-shadow: 0 0 30px rgba(255, 0, 0, .06);
        }
        .qat-ring:nth-child(1) { animation: qatRotateClockwise 8s linear infinite; }
        .qat-ring:nth-child(2) { inset: 45px; border-style: dashed; animation: qatRotateCounter 6s linear infinite; }
        .qat-ring:nth-child(3) { inset: 90px; border-color: rgba(255, 40, 40, .45); animation: qatRotateClockwise 4s linear infinite; }

        @keyframes qatRotateClockwise { to { transform: rotate(360deg); } }
        @keyframes qatRotateCounter { to { transform: rotate(-360deg); } }

        /* SECURITY CORE */
        .qat-core {
          position: absolute;
          width: 155px;
          height: 155px;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%) rotate(45deg);
          border: 1px solid rgba(255, 0, 0, .65);
          box-shadow: 0 0 35px rgba(255, 0, 0, .2), inset 0 0 35px rgba(255, 0, 0, .08);
          animation: qatCorePulse 2s ease-in-out infinite;
          transition: margin 0.1s ease-out;
        }
        .qat-core::before {
          content: "";
          position: absolute;
          inset: 22px;
          border: 1px solid rgba(255, 255, 255, .35);
        }
        .qat-core::after {
          content: "";
          position: absolute;
          width: 32px;
          height: 32px;
          left: 50%;
          top: 50%;
          transform: translate(-50%, -50%);
          background: #ff1010;
          box-shadow: 0 0 20px #ff0000, 0 0 50px #ff0000, 0 0 90px rgba(255, 0, 0, .55);
        }
        @keyframes qatCorePulse {
          0%, 100% { box-shadow: 0 0 20px rgba(255, 0, 0, .15), inset 0 0 20px rgba(255, 0, 0, .05); }
          50% { box-shadow: 0 0 75px rgba(255, 0, 0, .55), inset 0 0 45px rgba(255, 0, 0, .15); }
        }

        /* BRAND REVEAL & GLITCH */
        .qat-brand {
          position: relative;
          z-index: 10;
          text-align: center;
          animation: qatBrandReveal 4.2s cubic-bezier(.16, 1, .3, 1) forwards;
        }
        .qat-brand h1 {
          position: relative;
          font-size: clamp(58px, 10vw, 135px);
          line-height: .9;
          font-weight: 700;
          letter-spacing: -6px;
          white-space: nowrap;
          color: #fff;
          text-shadow: 0 0 8px rgba(255, 255, 255, .45), 0 0 35px rgba(255, 0, 0, .12);
        }
        .qat-brand h1 span {
          color: #ff1515;
          text-shadow: 0 0 8px #ff0000, 0 0 25px #ff0000, 0 0 55px rgba(255, 0, 0, .5);
        }
        .qat-brand h1::before,
        .qat-brand h1::after {
          content: "Nqat AI";
          position: absolute;
          left: 0;
          top: 0;
          width: 100%;
          opacity: 0;
        }
        .qat-brand h1::before {
          color: #ff0000;
          animation: qatGlitchRed 3s infinite;
        }
        .qat-brand h1::after {
          color: #fff;
          animation: qatGlitchWhite 3.4s infinite;
        }
        @keyframes qatGlitchRed {
          0%, 88%, 100% { opacity: 0; transform: translate(0); }
          90% { opacity: .8; transform: translate(-5px, 1px); }
          92% { opacity: 0; }
          94% { opacity: .6; transform: translate(5px, -1px); }
        }
        @keyframes qatGlitchWhite {
          0%, 90%, 100% { opacity: 0; transform: translate(0); }
          92% { opacity: .5; transform: translate(5px); }
          94% { opacity: 0; }
        }

        .qat-subtitle {
          margin-top: 26px;
          font-size: 11px;
          letter-spacing: 8px;
          text-transform: uppercase;
          color: #777;
          animation: qatSubtitleAnimation 4.2s ease forwards;
        }
        .qat-subtitle::before {
          content: "◆";
          color: #ff1111;
          margin-right: 12px;
          text-shadow: 0 0 10px red;
        }
        @keyframes qatSubtitleAnimation {
          0%, 10% { opacity: 0; letter-spacing: 16px; }
          20%, 85% { opacity: 1; letter-spacing: 8px; }
          100% { opacity: 0.8; }
        }

        @keyframes qatBrandReveal {
          0% { opacity: 0; filter: blur(25px); transform: scale(.65); }
          35% { opacity: 1; filter: blur(0); transform: scale(1); }
          85% { opacity: 1; transform: scale(1); }
          100% { opacity: 1; transform: scale(1.02); }
        }

        /* PARTICLES */
        .qat-particles { position: absolute; inset: 0; }
        .qat-particle {
          position: absolute;
          width: 3px;
          height: 3px;
          border-radius: 50%;
          background: #ff1515;
          box-shadow: 0 0 8px #ff0000, 0 0 18px #ff0000;
          animation: qatParticleFloat 3s ease-in-out infinite;
        }
        .qat-particle:nth-child(1) { left: 8%; top: 22%; }
        .qat-particle:nth-child(2) { left: 18%; top: 70%; animation-delay: .8s; }
        .qat-particle:nth-child(3) { left: 30%; top: 12%; animation-delay: 1.5s; }
        .qat-particle:nth-child(4) { left: 73%; top: 20%; animation-delay: .3s; }
        .qat-particle:nth-child(5) { left: 87%; top: 67%; animation-delay: 1.2s; }
        .qat-particle:nth-child(6) { left: 65%; top: 82%; animation-delay: 2s; }
        .qat-particle:nth-child(7) { left: 92%; top: 35%; animation-delay: .5s; }
        .qat-particle:nth-child(8) { left: 7%; top: 60%; animation-delay: 2.2s; }
        .qat-particle:nth-child(9) { left: 48%; top: 8%; animation-delay: 1s; }
        .qat-particle:nth-child(10) { left: 53%; top: 92%; animation-delay: 1.7s; }

        @keyframes qatParticleFloat {
          0%, 100% { transform: translateY(0) scale(.5); opacity: .2; }
          50% { transform: translateY(-35px) scale(1.4); opacity: 1; }
        }

        /* SCANNER */
        .qat-scanner {
          position: absolute;
          width: 100%;
          height: 2px;
          left: 0;
          top: -5%;
          background: linear-gradient(90deg, transparent, #ff0000, #fff, #ff0000, transparent);
          box-shadow: 0 0 20px #ff0000, 0 0 50px rgba(255, 0, 0, .6);
          opacity: .5;
          animation: qatScan 3.5s linear infinite;
        }
        @keyframes qatScan {
          from { top: -5%; }
          to { top: 105%; }
        }

        /* HUD & STATUS */
        .qat-hud {
          position: absolute;
          inset: 28px;
          border: 1px solid rgba(255, 0, 0, .09);
          pointer-events: none;
        }
        .qat-hud::before, .qat-hud::after {
          content: "";
          position: absolute;
          width: 55px;
          height: 55px;
          border: 2px solid #ff1111;
          filter: drop-shadow(0 0 7px red);
        }
        .qat-hud::before { left: -1px; top: -1px; border-right: 0; border-bottom: 0; }
        .qat-hud::after { right: -1px; bottom: -1px; border-left: 0; border-top: 0; }

        .qat-status {
          position: absolute;
          top: 45px;
          left: 55px;
          z-index: 20;
          font-size: 9px;
          letter-spacing: 3px;
          color: #777;
        }
        .qat-status span {
          color: #ff1111;
          text-shadow: 0 0 10px red;
          margin-right: 8px;
        }
        .qat-version {
          position: absolute;
          right: 55px;
          bottom: 45px;
          z-index: 20;
          color: #444;
          font-size: 9px;
          letter-spacing: 3px;
        }
      `}</style>

      <section ref={heroRef} style={{
        position: 'relative',
        width: '100%',
        height: '100vh',
        overflow: 'hidden',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'radial-gradient(circle at 50% 45%, rgba(180, 0, 0, .20), transparent 28%), radial-gradient(circle at 50% 100%, rgba(255, 0, 0, .08), transparent 45%), #020202'
      }}>
        <div className="qat-aura"></div>
        <div className="qat-grid"></div>

        <div className="qat-rings" ref={ringsRef}>
          <div className="qat-ring"></div>
          <div className="qat-ring"></div>
          <div className="qat-ring"></div>
        </div>

        <div className="qat-particles">
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
          <div className="qat-particle"></div>
        </div>

        <div className="qat-scanner"></div>
        <div className="qat-core" ref={coreRef}></div>

        <div className="qat-brand">
          <h1>Nqat <span>AI</span></h1>
          <div className="qat-subtitle">Agentic Web Assistant</div>
        </div>

        <div className="qat-hud"></div>
        <div className="qat-status"><span>●</span> Nqat AI WEB SECURITY INITIALIZING...</div>
        <div className="qat-version">AI DEFENSE SYSTEM 2026</div>

        <button
          onClick={triggerComplete}
          style={{
            position: 'absolute',
            bottom: '45px',
            left: '50%',
            transform: 'translateX(-50%)',
            zIndex: 30,
            background: 'rgba(255, 0, 0, 0.12)',
            border: '1px solid rgba(255, 0, 0, 0.4)',
            color: '#ff4444',
            padding: '8px 22px',
            borderRadius: '20px',
            fontSize: '10px',
            letterSpacing: '2px',
            textTransform: 'uppercase',
            cursor: 'pointer',
            boxShadow: '0 0 12px rgba(255,0,0,0.2)',
            transition: 'all 0.3s ease'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.background = 'rgba(255, 0, 0, 0.35)';
            e.currentTarget.style.borderColor = '#ff1111';
            e.currentTarget.style.color = '#ffffff';
            e.currentTarget.style.boxShadow = '0 0 20px rgba(255, 0, 0, 0.6)';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.background = 'rgba(255, 0, 0, 0.12)';
            e.currentTarget.style.borderColor = 'rgba(255, 0, 0, 0.4)';
            e.currentTarget.style.color = '#ff4444';
            e.currentTarget.style.boxShadow = '0 0 12px rgba(255,0,0,0.2)';
          }}
        >
          Skip Intro →
        </button>
      </section>
    </div>
  );
}
