const fs = require('fs');
const path = require('path');

const svgContent = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect x="2" y="2" width="60" height="60" rx="14" fill="#090d16" stroke="#ef4444" stroke-width="3"/>
  <path d="M32 10 L52 50 L12 50 Z" fill="#ffffff" stroke="#ffffff" stroke-width="1.5" stroke-linejoin="round"/>
  <path d="M32 23 L43 45 L21 45 Z" fill="#090d16"/>
  <circle cx="32" cy="38" r="5" fill="#ef4444"/>
</svg>`;

const base64Svg = Buffer.from(svgContent).toString('base64');
console.log('BASE64 SVG:', base64Svg);

const publicDir = path.join(__dirname, '..', 'frontend', 'public');
fs.writeFileSync(path.join(publicDir, 'favicon.svg'), svgContent, 'utf8');

// Write data URI to a file for easy inspection
fs.writeFileSync(path.join(__dirname, 'favicon_b64.txt'), base64Svg, 'utf8');
