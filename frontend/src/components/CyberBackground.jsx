import React, { useEffect, useRef } from 'react';

export default function CyberBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);

    // Load Noctturno wavy background image (without text)
    const bgImg = new Image();
    bgImg.src = '/bg_noctturno.jpg';
    let imgLoaded = false;
    bgImg.onload = () => {
      imgLoaded = true;
    };

    const handleResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', handleResize);

    // Particle nodes
    const particleCount = Math.min(Math.floor(width / 24), 55);
    const particles = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        radius: Math.random() * 2 + 1,
        alpha: Math.random() * 0.5 + 0.3,
        color: Math.random() > 0.4 ? '#ffffff' : Math.random() > 0.5 ? '#ef4444' : '#fca5a5'
      });
    }

    // Floating matrix / hex strings
    const hexTokens = ['0x9F', '0x3E', 'NKAT', 'SSL/TLS', 'VULN_ASSISTANT', '0xAA', 'AI_NODE', 'HTTP/3', 'SQLi_CHK', 'CVE-2026', 'DEFENSE'];
    const floatingTexts = [];
    for (let i = 0; i < 16; i++) {
      floatingTexts.push({
        x: Math.random() * width,
        y: Math.random() * height,
        text: hexTokens[Math.floor(Math.random() * hexTokens.length)],
        speedY: -0.2 - Math.random() * 0.3,
        alpha: Math.random() * 0.2 + 0.08
      });
    }

    let scanlineY = 0;

    const render = () => {
      ctx.fillStyle = '#000000';
      ctx.fillRect(0, 0, width, height);

      // Render Noctturno background image
      if (imgLoaded) {
        ctx.globalAlpha = 0.35;
        // Cover scaling
        const imgRatio = bgImg.width / bgImg.height;
        const canvasRatio = width / height;
        let drawWidth = width;
        let drawHeight = height;
        let offsetX = 0;
        let offsetY = 0;

        if (canvasRatio > imgRatio) {
          drawHeight = width / imgRatio;
          offsetY = (height - drawHeight) / 2;
        } else {
          drawWidth = height * imgRatio;
          offsetX = (width - drawWidth) / 2;
        }

        ctx.drawImage(bgImg, offsetX, offsetY, drawWidth, drawHeight);
        ctx.globalAlpha = 1.0;
      }

      // Dark vignette overlay to ensure text readability & pure black background
      const vignette = ctx.createRadialGradient(width / 2, height / 2, width * 0.2, width / 2, height / 2, width * 0.7);
      vignette.addColorStop(0, 'rgba(0, 0, 0, 0.5)');
      vignette.addColorStop(1, 'rgba(0, 0, 0, 0.95)');
      ctx.fillStyle = vignette;
      ctx.fillRect(0, 0, width, height);

      // Ambient monochrome & red spotlights
      const grad1 = ctx.createRadialGradient(width * 0.2, height * 0.2, 0, width * 0.2, height * 0.2, width * 0.4);
      grad1.addColorStop(0, 'rgba(255, 255, 255, 0.04)');
      grad1.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad1;
      ctx.fillRect(0, 0, width, height);

      const grad2 = ctx.createRadialGradient(width * 0.8, height * 0.8, 0, width * 0.8, height * 0.8, width * 0.5);
      grad2.addColorStop(0, 'rgba(239, 68, 68, 0.05)');
      grad2.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad2;
      ctx.fillRect(0, 0, width, height);

      // Moving Radar Scanline
      scanlineY = (scanlineY + 1.2) % (height + 100);
      const scanGrad = ctx.createLinearGradient(0, scanlineY - 60, 0, scanlineY);
      scanGrad.addColorStop(0, 'rgba(255, 255, 255, 0)');
      scanGrad.addColorStop(0.5, 'rgba(255, 255, 255, 0.02)');
      scanGrad.addColorStop(1, 'rgba(255, 255, 255, 0.1)');
      ctx.fillStyle = scanGrad;
      ctx.fillRect(0, scanlineY - 60, width, 60);

      ctx.strokeStyle = 'rgba(255, 255, 255, 0.15)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(0, scanlineY);
      ctx.lineTo(width, scanlineY);
      ctx.stroke();

      // Floating hex text tokens
      ctx.font = '11px "Fira Code", monospace';
      floatingTexts.forEach(item => {
        item.y += item.speedY;
        if (item.y < -20) {
          item.y = height + 20;
          item.x = Math.random() * width;
          item.text = hexTokens[Math.floor(Math.random() * hexTokens.length)];
        }
        ctx.fillStyle = `rgba(255, 255, 255, ${item.alpha})`;
        ctx.fillText(item.text, item.x, item.y);
      });

      // Update & Draw particles
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        p.alpha += Math.sin(Date.now() * 0.003) * 0.005;
        p.alpha = Math.max(0.2, Math.min(0.8, p.alpha));

        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.alpha;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.globalAlpha = 1;

        // Draw connections
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (dist < 120) {
            ctx.strokeStyle = '#ffffff';
            ctx.globalAlpha = (1 - dist / 120) * 0.1;
            ctx.lineWidth = 0.8;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.stroke();
            ctx.globalAlpha = 1;
          }
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100vw',
        height: '100vh',
        zIndex: 0,
        pointerEvents: 'none',
        display: 'block'
      }}
    />
  );
}
