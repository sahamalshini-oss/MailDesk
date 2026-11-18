const fs = require('fs');
const content = fs.readFileSync('C:/Users/Sahansa/Desktop/MailDesk/frontend/index.html', 'utf8');

// The current broken esc function has literal & < > " ' 
// We need to replace with proper HTML entities
const brokenEsc = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": '\u0027' }[c]));`;
const fixedEsc = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '\u0026amp;', '<': '\u0026lt;', '>': '\u0026gt;', '"': '\u0026quot;', "'": '\u0026#39;' }[c]));`;

if (content.includes(brokenEsc)) {
  const newContent = content.replace(brokenEsc, fixedEsc);
  fs.writeFileSync('C:/Users/Sahansa/Desktop/MailDesk/frontend/index.html', newContent, 'utf8');
  console.log('Fixed esc function');
} else {
  console.log('Pattern not found, searching...');
  const idx = content.indexOf('const esc = v');
  if (idx >= 0) {
    const snippet = content.substring(idx, idx + 200);
    console.log('Found:', JSON.stringify(snippet));
  }
}