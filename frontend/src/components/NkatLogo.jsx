import React from 'react';

export default function NkatLogo({ size = 'medium', showText = true, subtitle = true }) {
  const isSmall = size === 'small';
  const isLarge = size === 'large';

  // Sizing tokens
  const shieldWidth = isSmall ? 36 : isLarge ? 58 : 44;
  const shieldHeight = isSmall ? 40 : isLarge ? 64 : 49;
  const titleFontSize = isSmall ? '1.25rem' : isLarge ? '2.4rem' : '1.5rem';
  const subtitleFontSize = isSmall ? '0.58rem' : isLarge ? '0.82rem' : '0.68rem';
  const dotSize = isSmall ? 4 : isLarge ? 7 : 5;
  const lineBarHeight = isSmall ? 2 : 2.5;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: isSmall ? '0.65rem' : '0.9rem', flexShrink: 0 }}>
      {/* Exact Vector Shield Emblem */}
      <svg
        width={shieldWidth}
        height={shieldHeight}
        viewBox="0 0 50 56"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        style={{ flexShrink: 0, filter: 'drop-shadow(0 0 12px rgba(255, 255, 255, 0.2))' }}
      >
        {/* Outer White Shield */}
        <path d="M25 3L4 12V25C4 39.5 18 50.5 25 53C32 50.5 46 39.5 46 25V12L25 3Z" stroke="#ffffff" strokeWidth="2.6" fill="#0d0e10" strokeLinejoin="round" strokeLinecap="round"/>
        {/* Inner White Shield */}
        <path d="M25 8.5L8.5 15.5V25C8.5 36.5 19.5 45.5 25 47.8C30.5 45.5 41.5 36.5 41.5 25V15.5L25 8.5Z" stroke="#ffffff" strokeWidth="1.3" fill="none" strokeLinejoin="round" opacity="0.95"/>
        {/* Node Graph Connections */}
        <path d="M25 18L16 23.5V34.5L25 40L34 34.5V23.5L25 18Z" stroke="#ffffff" strokeWidth="1.6" fill="none"/>
        <path d="M16 23.5L34 23.5" stroke="#ffffff" strokeWidth="1.6"/>
        <path d="M16 34.5L34 34.5" stroke="#ffffff" strokeWidth="1.6"/>
        {/* White Circles with Inner Dots */}
        <circle cx="25" cy="18" r="3" fill="#ffffff"/>
        <circle cx="25" cy="18" r="1.4" fill="#000000"/>
        <circle cx="16" cy="23.5" r="3" fill="#ffffff"/>
        <circle cx="16" cy="23.5" r="1.4" fill="#000000"/>
        <circle cx="34" cy="23.5" r="3" fill="#ffffff"/>
        <circle cx="34" cy="23.5" r="1.4" fill="#000000"/>
        <circle cx="16" cy="34.5" r="3" fill="#ffffff"/>
        <circle cx="16" cy="34.5" r="1.4" fill="#000000"/>
        <circle cx="34" cy="34.5" r="3" fill="#ffffff"/>
        <circle cx="34" cy="34.5" r="1.4" fill="#000000"/>
        {/* Center Target Ring */}
        <circle cx="25" cy="29" r="3.5" fill="#ffffff"/>
        <circle cx="25" cy="29" r="2.2" fill="#000000"/>
        <circle cx="25" cy="29" r="1.1" fill="#ffffff"/>
        {/* Bottom Arc Curve */}
        <path d="M17 41Q25 46.5 33 41" stroke="#ffffff" strokeWidth="1.4" fill="none" strokeLinecap="round"/>
        <circle cx="17" cy="41" r="1" fill="#ffffff"/>
        <circle cx="33" cy="41" r="1" fill="#ffffff"/>
      </svg>

      {/* Brand Name & Subtitle */}
      {showText && (
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          {/* Main Title Row: Nqat AI */}
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px' }}>
            <span style={{
              fontFamily: "'Outfit', 'Inter', sans-serif",
              fontSize: titleFontSize,
              fontWeight: 900,
              color: '#ffffff',
              letterSpacing: '-0.5px',
              whiteSpace: 'nowrap',
              lineHeight: 1
            }}>
              Nqat
            </span>
            <span style={{
              fontFamily: "'Outfit', 'Inter', sans-serif",
              fontSize: titleFontSize,
              fontWeight: 900,
              color: '#ffffff',
              letterSpacing: '-0.5px',
              whiteSpace: 'nowrap',
              lineHeight: 1
            }}>
              AI
            </span>
          </div>

          {/* Subtitle: AGENTIC WEB ASSISTANT */}
          {subtitle && (
            <span style={{
              fontSize: subtitleFontSize,
              color: '#a1a1aa',
              fontWeight: 700,
              fontFamily: "'Space Grotesk', 'Outfit', sans-serif",
              textTransform: 'uppercase',
              letterSpacing: isSmall ? '1.8px' : isLarge ? '3.5px' : '2.5px',
              marginTop: '4px',
              whiteSpace: 'nowrap',
              lineHeight: 1.1,
              opacity: 0.95
            }}>
              {isLarge ? 'SENTINEL AGENTIC ASSISTANT' : 'AGENTIC WEB ASSISTANT'}
            </span>
          )}

          {/* Monochrome Underline Bar with End Dot */}
          <div style={{ display: 'flex', alignItems: 'center', marginTop: '5px', width: '100%' }}>
            <div style={{
              height: `${lineBarHeight}px`,
              background: '#ffffff',
              flex: 1,
              borderRadius: '2px',
              boxShadow: '0 0 6px rgba(255, 255, 255, 0.4)'
            }} />
            <div style={{
              width: `${dotSize}px`,
              height: `${dotSize}px`,
              background: '#ffffff',
              borderRadius: '50%',
              marginLeft: '5px',
              boxShadow: '0 0 8px #ffffff',
              flexShrink: 0
            }} />
          </div>
        </div>
      )}
    </div>
  );
}
