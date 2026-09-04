import React, { useState, useEffect } from 'react';
import AuthModal from './AuthModal';
import CrowdStrikeHomepage from './CrowdStrikeHomepage';
import AdminDashboardPage from './AdminDashboardPage';
import SecureWebTicker from './SecureWebTicker';
import Navbar from './Navbar';
import { 
  Search, Cpu, ShieldCheck, Lock, User, ArrowRight, CheckCircle2, 
  Send, LogOut, ChevronDown, ChevronUp, Zap, Sparkles, Terminal, 
  Check, FileText, Globe, Layers, AlertCircle, ArrowUpRight, Newspaper, Calendar, Clock
} from 'lucide-react';

export default function PublicLandingPage({ user, onAuthSuccess, onLogout }) {
  const [activeSection, setActiveSection] = useState('home');
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [contactMsg, setContactMsg] = useState('');
  const [contactForm, setContactForm] = useState({ name: '', email: '', message: '' });
  const [dynamicPosts, setDynamicPosts] = useState([]);

  useEffect(() => {
    fetch('/api/v1/posts')
      .then(res => res.json())
      .then(data => setDynamicPosts(data))
      .catch(err => console.error('Error fetching posts:', err));
  }, []);

  const handleContactSubmit = (e) => {
    e.preventDefault();
    setContactMsg('Thank you for contacting NKAT AI Assistant Team. We will reach out shortly.');
    setContactForm({ name: '', email: '', message: '' });
    setTimeout(() => setContactMsg(''), 5000);
  };

  const scrollTo = (id) => {
    setActiveSection(id);
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth' });
  };

  // ----------------------------------------------------
  // AFTER LOGIN VIEW (Renders Logged-In Dashboard Console)
  // ----------------------------------------------------
  if (user) {
    const isAdmin = user.role === 'admin' || user.username === 'admin';
    return (
      <div style={{ background: 'transparent', color: '#f8fafc', minHeight: '100vh', position: 'relative', zIndex: 1 }}>
        <Navbar user={user} onLogout={onLogout} />
        {isAdmin ? (
          <AdminDashboardPage user={user} onLogout={onLogout} />
        ) : (
          <CrowdStrikeHomepage user={user} onLogout={onLogout} />
        )}
      </div>
    );
  }

  // ----------------------------------------------------
  // 4 CYBER NEWS & THREAT INSIGHTS POSTS
  // ----------------------------------------------------
  const cyberNewsPosts = [
    {
      id: 1,
      tag: "ZERO-DAY ALERT",
      tagColor: "#ef4444",
      date: "Aug 31, 2026",
      readTime: "5 min read",
      title: "CISA KEV Sync: Critical Web Application Vulnerabilities Cataloged",
      snippet: "Our autonomous threat engine synchronized 14 newly cataloged CVE vulnerabilities affecting public web endpoints. Learn how machine learning triage isolates true exploit vectors.",
      author: "NKAT Security Intelligence Labs",
      image: "/news/post1.jpg"
    },
    {
      id: 2,
      tag: "TARGET VERIFICATION",
      tagColor: "#10b981",
      date: "Aug 30, 2026",
      readTime: "4 min read",
      title: "Enforcing Target Ownership: Why DNS TXT & HTTP Checks are Mandatory",
      snippet: "Discover how mandatory target verification tokens guarantee strict legal authorization, prevent unauthorized external scanning, and satisfy corporate compliance.",
      author: "Compliance Engineering Team",
      image: "/news/post2.jpg"
    },
    {
      id: 3,
      tag: "ML TRIAGE ENGINE",
      tagColor: "#ef4444",
      date: "Aug 28, 2026",
      readTime: "6 min read",
      title: "Eliminating Alert Fatigue: XGBoost Scoring for SQLi & XSS Vectors",
      snippet: "Traditional vulnerability tools flood teams with false positives. Here is how predictive ML models evaluate payload context to prioritize high-confidence findings.",
      author: "AI Threat Research Group",
      image: "/news/post3.jpg"
    },
    {
      id: 4,
      tag: "EXECUTIVE REPORTING",
      tagColor: "#10b981",
      date: "Aug 25, 2026",
      readTime: "3 min read",
      title: "Automating OWASP Top 10 & CWE Mapping for Instant PDF Audits",
      snippet: "Transforming raw scan telemetry into executive-ready PDF audit reports mapped to standard compliance frameworks reduces quarterly auditing overhead by 90%.",
      author: "Product Security Operations",
      image: "/news/post4.jpg"
    }
  ];

  return (
    <div style={{ background: '#000000', color: '#ffffff', minHeight: '100vh', position: 'relative', zIndex: 1 }}>
      
      {/* ---------------------------------------------------- */}
      {/* NAVIGATION BAR (Aegis Aegis Sticky Dark Navbar) */}
      {/* ---------------------------------------------------- */}
      <header style={{
        position: 'sticky',
        top: 0,
        zIndex: 100,
        padding: '1.2rem 3rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'rgba(0, 0, 0, 0.95)',
        backdropFilter: 'blur(20px)',
        borderBottom: '2px solid #000000'
      }}>
        {/* Brand Logo & Name */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem', cursor: 'pointer' }} onClick={() => scrollTo('home')}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: '10px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '2px solid #000000',
            boxShadow: '0 0 16px rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0
          }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 3L22 20H2L12 3Z" fill="#FFFFFF" stroke="#FFFFFF" strokeWidth="1" strokeLinejoin="round"/>
              <path d="M12 9.5L16.5 17.5H7.5L12 9.5Z" fill="#000000"/>
            </svg>
          </div>
          <div>
            <div className="brand-font" style={{ fontFamily: "'Outfit', 'Syne', sans-serif", fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', letterSpacing: '-0.5px', lineHeight: 1.1 }}>
              Nqat <span style={{ color: '#ffffff' }}>AI</span>
            </div>
            <div style={{ fontSize: '0.62rem', color: '#94a3b8', fontWeight: 700, letterSpacing: '1px', textTransform: 'uppercase' }}>
              WEBSITE VULNERABILITY ASSISTANT
            </div>
          </div>
        </div>

        {/* Navigation Links & Sign In Group */}
        <nav style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
          <button
            onClick={() => scrollTo('home')}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '0.9rem',
              fontWeight: activeSection === 'home' ? 700 : 500,
              color: activeSection === 'home' ? '#ffffff' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.2s ease',
              position: 'relative'
            }}
          >
            Home
            {activeSection === 'home' && (
              <span style={{ position: 'absolute', bottom: '-6px', left: 0, right: 0, height: '2px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            )}
          </button>

          <button
            onClick={() => scrollTo('about')}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '0.9rem',
              fontWeight: activeSection === 'about' ? 700 : 500,
              color: activeSection === 'about' ? '#ffffff' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.2s ease',
              position: 'relative'
            }}
          >
            About Us
            {activeSection === 'about' && (
              <span style={{ position: 'absolute', bottom: '-6px', left: 0, right: 0, height: '2px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            )}
          </button>

          <button
            onClick={() => scrollTo('news')}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '0.9rem',
              fontWeight: activeSection === 'news' ? 700 : 500,
              color: activeSection === 'news' ? '#ffffff' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.2s ease',
              position: 'relative'
            }}
          >
            Cyber News
            {activeSection === 'news' && (
              <span style={{ position: 'absolute', bottom: '-6px', left: 0, right: 0, height: '2px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            )}
          </button>

          <button
            onClick={() => scrollTo('contact')}
            style={{
              background: 'none',
              border: 'none',
              fontSize: '0.9rem',
              fontWeight: activeSection === 'contact' ? 700 : 500,
              color: activeSection === 'contact' ? '#ffffff' : '#94a3b8',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              transition: 'all 0.2s ease',
              position: 'relative'
            }}
          >
            Contact Us
            {activeSection === 'contact' && (
              <span style={{ position: 'absolute', bottom: '-6px', left: 0, right: 0, height: '2px', backgroundColor: '#ffffff', borderRadius: '2px' }} />
            )}
          </button>

          {/* Sign In / Register Button placed right next to Contact Us */}
          <button
            onClick={() => setIsAuthOpen(true)}
            className="btn-aegis-primary"
            style={{ padding: '0.6rem 1.35rem', fontSize: '0.88rem', marginLeft: '0.5rem', display: 'inline-flex', alignItems: 'center', gap: '8px' }}
          >
            <Lock size={14} /> Sign In / Register
          </button>
        </nav>
      </header>


      {/* ---------------------------------------------------- */}
      {/* HOME SECTION (Exact Original Text + Aegis Interface Layout) */}
      {/* ---------------------------------------------------- */}
      <section id="home" style={{ padding: '5.5rem 2rem 4rem', maxWidth: '1200px', margin: '0 auto', textAlign: 'center' }}>
        
        {/* Animated Badge Typewriter */}
        <SecureWebTicker variant="hero" />

        {/* Hero Headline */}
        <h1 className="heading-font" style={{
          fontSize: '4rem',
          fontWeight: 900,
          color: '#ffffff',
          lineHeight: 1.12,
          letterSpacing: '-1.5px',
          marginTop: '1.25rem'
        }}>
          Nqat AI <br />
          <span style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #ef4444 100%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            WEBSITE VULNERABILITY ASSISTANT
          </span>
        </h1>

        {/* Hero Subtitle */}
        <p style={{
          fontSize: '1.2rem',
          color: '#94a3b8',
          maxWidth: '740px',
          margin: '1.75rem auto 2.5rem',
          lineHeight: 1.6
        }}>
          Empowering modern enterprises with autonomous web auditing, machine learning threat prediction, CISA KEV exploitation correlation, and human-in-the-loop remediation.
        </p>

        {/* Action Buttons */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => setIsAuthOpen(true)}
            className="btn-aegis-primary"
          >
            Launch Vulnerability Assistant <ArrowRight size={18} />
          </button>
          <button
            onClick={() => scrollTo('about')}
            className="btn-aegis-secondary"
          >
            Explore Capabilities
          </button>
        </div>

        {/* 3 Core Feature Cards Grid */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '1.75rem',
          marginTop: '5rem',
          textAlign: 'left'
        }}>
          
          <div className="aegis-glass-card" style={{ padding: '2.25rem' }}>
            <div style={{ color: '#ffffff', marginBottom: '0.85rem' }}>
              <Search size={32} />
            </div>
            <h3 className="heading-font" style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', marginBottom: '0.5rem' }}>
              Autonomous Web Audit
            </h3>
            <p style={{ fontSize: '0.92rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Multi-vector continuous scans for SQL Injection, XSS, exposed repositories, subdomains, and security headers.
            </p>
          </div>

          <div className="aegis-glass-card" style={{ padding: '2.25rem' }}>
            <div style={{ color: '#e2e8f0', marginBottom: '0.85rem' }}>
              <Cpu size={32} />
            </div>
            <h3 className="heading-font" style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', marginBottom: '0.5rem' }}>
              AI Threat Triage Engine
            </h3>
            <p style={{ fontSize: '0.92rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Autonomous multi-tool reasoning agent that analyzes vulnerabilities and predicts exploit likelihood scores.
            </p>
          </div>

          <div className="aegis-glass-card" style={{ padding: '2.25rem' }}>
            <div style={{ color: '#ffffff', marginBottom: '0.85rem' }}>
              <ShieldCheck size={32} />
            </div>
            <h3 className="heading-font" style={{ fontSize: '1.35rem', fontWeight: 800, color: '#ffffff', marginBottom: '0.5rem' }}>
              Target Ownership Control
            </h3>
            <p style={{ fontSize: '0.92rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Mandatory DNS TXT and HTTP File target verification ensuring strict legal compliance and safety control.
            </p>
          </div>

        </div>
      </section>

      {/* ---------------------------------------------------- */}
      {/* STATS NUMBERS COUNTER ROW */}
      {/* ---------------------------------------------------- */}
      <div className="aegis-stat-row">
        <div className="aegis-stat-item">
          <div className="aegis-stat-number">&gt;90%</div>
          <div className="aegis-stat-label">Reduction in Triage Volume</div>
        </div>
        <div className="aegis-stat-item">
          <div className="aegis-stat-number">100%</div>
          <div className="aegis-stat-label">Target Ownership Compliance</div>
        </div>
        <div className="aegis-stat-item">
          <div className="aegis-stat-number">&lt;3min</div>
          <div className="aegis-stat-label">Full Web Audit Scan Time</div>
        </div>
        <div className="aegis-stat-item">
          <div className="aegis-stat-number">24/7</div>
          <div className="aegis-stat-label">Autonomous Threat Monitoring</div>
        </div>
      </div>

      {/* ---------------------------------------------------- */}
      {/* ABOUT US SECTION */}
      {/* ---------------------------------------------------- */}
      <section id="about" style={{ padding: '6rem 2rem', background: '#000000', borderTop: '1px solid rgba(255, 255, 255, 0.08)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
        <div style={{ maxWidth: '1150px', margin: '0 auto' }}>
          
          <div className="aegis-section-header">
            <div className="aegis-badge-pill">
              <span>ABOUT Nqat AI ASSISTANT</span>
            </div>
            <h2 className="aegis-section-title">
              Engineered for Precision & Security Autonomy
            </h2>
            <p className="aegis-section-subtitle">
              Local-first security correlation platform combining XGBoost machine learning threat scoring with standard web vulnerability auditing.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '2.5rem', alignItems: 'center' }}>
            
            {/* Why Choose Column */}
            <div>
              <h3 className="heading-font" style={{ fontSize: '1.6rem', fontWeight: 800, color: '#ffffff', marginBottom: '1.5rem' }}>
                Why Choose Nqat AI Website Vulnerability Assistant?
              </h3>
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
                <li style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <CheckCircle2 size={22} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong style={{ color: '#ffffff', fontSize: '1.05rem' }}>ML Exploit Classifier:</strong>
                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', marginTop: '3px', lineHeight: 1.5 }}>Predictive ML models trained on real CVE vulnerability datasets to calculate risk confidence.</p>
                  </div>
                </li>
                <li style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <CheckCircle2 size={22} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong style={{ color: '#ffffff', fontSize: '1.05rem' }}>Human-in-the-Loop Governance:</strong>
                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', marginTop: '3px', lineHeight: 1.5 }}>Enforces explicit approval, rejection, and state rollback policies for total control.</p>
                  </div>
                </li>
                <li style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <CheckCircle2 size={22} style={{ color: '#10b981', flexShrink: 0, marginTop: '2px' }} />
                  <div>
                    <strong style={{ color: '#ffffff', fontSize: '1.05rem' }}>Executive PDF Security Reporting:</strong>
                    <p style={{ fontSize: '0.9rem', color: '#94a3b8', marginTop: '3px', lineHeight: 1.5 }}>Generates executive-ready PDF audit reports with remediation guides and standards mapping.</p>
                  </div>
                </li>
              </ul>
            </div>

            {/* Specifications Matrix Card */}
            <div className="aegis-glass-card" style={{ padding: '2.5rem' }}>
              <div className="mono-text" style={{ fontSize: '0.78rem', fontWeight: 700, letterSpacing: '1px', color: '#10b981' }}>PLATFORM SPECIFICATIONS</div>
              <h4 className="heading-font" style={{ fontSize: '1.4rem', fontWeight: 800, color: '#ffffff', marginTop: '6px', marginBottom: '1.5rem' }}>
                Enterprise Security Matrix
              </h4>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
                  <span style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Authentication</span>
                  <strong style={{ color: '#ffffff', fontSize: '0.9rem' }}>Multi-Tenant HS256 JWT</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
                  <span style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Target Authorization</span>
                  <strong style={{ color: '#ffffff', fontSize: '0.9rem' }}>DNS TXT & HTTP File Check</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '10px' }}>
                  <span style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Threat Feeds</span>
                  <strong style={{ color: '#ffffff', fontSize: '0.9rem' }}>CISA KEV / FIRST EPSS</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '4px' }}>
                  <span style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Standards Mapping</span>
                  <strong style={{ color: '#ffffff', fontSize: '0.9rem' }}>OWASP Top 10 & CWE</strong>
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* ---------------------------------------------------- */}
      {/* SECTION: 4 CYBER NEWS POSTS ("Cyber News & Threat Insights") */}
      {/* ---------------------------------------------------- */}
      <section id="news" style={{ padding: '6rem 2rem', maxWidth: '1200px', margin: '0 auto' }}>
        <div className="aegis-section-header">
          <div className="aegis-badge-pill">
            <span>CYBER NEWS & THREAT INTELLIGENCE</span>
          </div>
          <h2 className="aegis-section-title">
            Latest Cyber News <br /> & Threat Insights
          </h2>
          <p className="aegis-section-subtitle">
            Stay informed with real-time cybersecurity updates, zero-day threat analysis, and target verification compliance guides.
          </p>
        </div>

        {/* Dynamic Posts Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: '1.75rem' }}>
          {(dynamicPosts.length > 0 ? dynamicPosts : cyberNewsPosts).map((post) => {
            const rawColor = post.tag_color || post.tagColor;
            const color = (rawColor === '#00f0ff' || rawColor === '#38bdf8' || rawColor === '#eab308' || rawColor === '#f97316') ? '#10b981' : (rawColor || '#10b981');
            const readTime = post.read_time || post.readTime || '3 min read';
            const pubDate = post.created_at || post.date || 'Today';
            return (
              <div key={post.id} className="aegis-glass-card" style={{ padding: '0', overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                
                {/* Post Media Header (Video or Image) */}
                <div style={{ width: '100%', overflow: 'hidden', position: 'relative', background: '#000000' }}>
                  {post.video_url ? (
                    <video
                      src={post.video_url}
                      controls
                      style={{ width: '100%', height: '185px', objectFit: 'cover' }}
                    />
                  ) : (
                    <img
                      src={post.image_url || post.image || '/news/post1.jpg'}
                      alt={post.title}
                      style={{ width: '100%', height: '175px', objectFit: 'cover', transition: 'transform 0.4s ease' }}
                      onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.06)'}
                      onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1.0)'}
                    />
                  )}
                  <div style={{
                    position: 'absolute',
                    top: '12px',
                    left: '12px',
                    fontSize: '0.68rem',
                    fontWeight: 800,
                    color: color,
                    background: 'rgba(0, 0, 0, 0.85)',
                    backdropFilter: 'blur(10px)',
                    border: `1px solid ${color}60`,
                    padding: '4px 12px',
                    borderRadius: '9999px',
                    letterSpacing: '0.8px',
                    zIndex: 2
                  }}>
                    {post.tag}
                  </div>
                </div>

                {/* Post Body Content */}
                <div style={{ padding: '1.75rem 1.75rem 1.5rem', flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                      <span style={{ fontSize: '0.75rem', color: '#64748b', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <Clock size={12} /> {readTime}
                      </span>
                      <span style={{ fontSize: '0.75rem', color: '#64748b' }}>{pubDate}</span>
                    </div>

                    <h3 className="heading-font" style={{ fontSize: '1.15rem', fontWeight: 800, color: '#ffffff', lineHeight: 1.35, marginBottom: '0.75rem' }}>
                      {post.title}
                    </h3>

                    <p style={{ fontSize: '0.88rem', color: '#94a3b8', lineHeight: 1.6, marginBottom: '1.25rem' }}>
                      {post.snippet}
                    </p>
                  </div>

                  <div style={{ paddingTop: '1rem', borderTop: '1px solid rgba(255, 255, 255, 0.06)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600 }}>{post.author}</span>
                    <span style={{ fontSize: '0.78rem', color: '#ffffff', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '2px', cursor: 'pointer' }}>
                      Read <ArrowUpRight size={14} />
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* ---------------------------------------------------- */}
      {/* CONTACT US SECTION */}
      {/* ---------------------------------------------------- */}
      <section id="contact" style={{ padding: '6rem 2rem', maxWidth: '840px', margin: '0 auto' }}>
        
        <div className="aegis-section-header">
          <div className="aegis-badge-pill">
            <span>GET IN TOUCH</span>
          </div>
          <h2 className="aegis-section-title">
            Contact the NKAT Security Team
          </h2>
          <p className="aegis-section-subtitle">
            Have questions about platform deployment, target verification, or API integration? Send us a message.
          </p>
        </div>

        {contactMsg && (
          <div className="mono-text" style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            background: 'rgba(16, 185, 129, 0.15)',
            color: '#6ee7b7',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            padding: '14px 18px',
            borderRadius: '14px',
            fontSize: '0.9rem',
            textAlign: 'center',
            marginBottom: '1.5rem'
          }}>
            <CheckCircle2 size={18} /> {contactMsg}
          </div>
        )}

        <form onSubmit={handleContactSubmit} className="aegis-glass-card" style={{ padding: '2.5rem' }}>
          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#94a3b8', display: 'block', marginBottom: '6px', letterSpacing: '0.8px' }}>YOUR NAME</label>
            <input
              type="text"
              required
              value={contactForm.name}
              onChange={(e) => setContactForm({ ...contactForm, name: e.target.value })}
              placeholder="Security Specialist"
              style={{
                width: '100%',
                padding: '14px 18px',
                borderRadius: '12px',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                background: 'rgba(10, 10, 10, 0.9)',
                color: '#ffffff',
                fontSize: '0.95rem',
                outline: 'none'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.25rem' }}>
            <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#94a3b8', display: 'block', marginBottom: '6px', letterSpacing: '0.8px' }}>WORK EMAIL</label>
            <input
              type="email"
              required
              value={contactForm.email}
              onChange={(e) => setContactForm({ ...contactForm, email: e.target.value })}
              placeholder="security@enterprise.com"
              style={{
                width: '100%',
                padding: '14px 18px',
                borderRadius: '12px',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                background: 'rgba(10, 10, 10, 0.9)',
                color: '#ffffff',
                fontSize: '0.95rem',
                outline: 'none'
              }}
            />
          </div>

          <div style={{ marginBottom: '1.75rem' }}>
            <label style={{ fontSize: '0.82rem', fontWeight: 700, color: '#94a3b8', display: 'block', marginBottom: '6px', letterSpacing: '0.8px' }}>MESSAGE</label>
            <textarea
              required
              rows={4}
              value={contactForm.message}
              onChange={(e) => setContactForm({ ...contactForm, message: e.target.value })}
              placeholder="How can we assist your security operations?"
              style={{
                width: '100%',
                padding: '14px 18px',
                borderRadius: '12px',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                background: 'rgba(10, 10, 10, 0.9)',
                color: '#ffffff',
                fontSize: '0.95rem',
                outline: 'none',
                resize: 'vertical'
              }}
            />
          </div>

          <button
            type="submit"
            className="btn-aegis-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '0.9rem' }}
          >
            Send Inquiry <Send size={16} />
          </button>
        </form>
      </section>

      {/* ---------------------------------------------------- */}
      {/* FOOTER */}
      {/* ---------------------------------------------------- */}
      <footer style={{
        background: '#000000',
        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        padding: '4rem 3rem 2.5rem',
        color: '#94a3b8',
        textAlign: 'center'
      }}>
        <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
          <div className="brand-font" style={{ fontSize: '1.25rem', color: '#ffffff', fontWeight: 800, marginBottom: '6px' }}>
            Nqat AI WEBSITE VULNERABILITY ASSISTANT
          </div>
          <div style={{ fontSize: '0.88rem', color: '#64748b', marginBottom: '1.5rem' }}>
            Local-First Autonomous Cybersecurity Operations • Strictly Scoped Security Testing
          </div>
          <div style={{ fontSize: '0.8rem', color: '#475569', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1.5rem' }}>
            2026 Nqat AI Platform. All rights reserved.
          </div>
        </div>
      </footer>

      {/* Auth Modal Trigger */}
      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onAuthSuccess={onAuthSuccess}
      />
    </div>
  );
}
