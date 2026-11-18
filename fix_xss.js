const fs = require('fs');
const content = fs.readFileSync('C:/Users/Sahansa/Desktop/MailDesk/frontend/index.html', 'utf8');

const oldStr = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": ''' }[c]));
const emailFontWhitelist = ['sans-serif', 'serif', 'monospace', 'arial', 'calibri', 'georgia', 'verdana', 'times-new-roman', 'courier-new'];`;

const newStr = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": ''' }[c]));
const sanitizeHtml = (html) => window.DOMPurify ? DOMPurify.sanitize(html, { ALLOWED_TAGS: ['p','br','b','i','u','strike','strong','em','a','img','ul','ol','li','h1','h2','h3','h4','h5','h6','blockquote','pre','code','span','div','table','thead','tbody','tr','th','td','hr'], ALLOWED_ATTR: ['href','target','rel','src','alt','width','height','style','class','data-fld','data-preview-field','data-rem','data-atch','data-cid','data-cname','data-t','data-use','data-e','data-d','data-f','data-rp','data-edit','data-cancel','data-name','data-edit-form','data-group-add','data-group-email','data-rm','data-g','data-open-draft','data-delete-draft','data-follow','data-at','data-note','data-reply','data-done'] }) : html;
const emailFontWhitelist = ['sans-serif', 'serif', 'monospace', 'arial', 'calibri', 'georgia', 'verdana', 'times-new-roman', 'courier-new'];`;

if (content.includes(oldStr)) {
  const newContent = content.replace(oldStr, newStr);
  fs.writeFileSync('C:/Users/Sahansa/Desktop/MailDesk/frontend/index.html', newContent, 'utf8');
  console.log('Done');
} else {
  console.log('Trying with actual file content...');
  // Use the exact content from the file
  const oldStr2 = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": ''' }[c]));
const emailFontWhitelist = ['sans-serif', 'serif', 'monospace', 'arial', 'calibri', 'georgia', 'verdana', 'times-new-roman', 'courier-new'];`;
  
  const exactOld = content.substring(content.indexOf('const esc = v'), content.indexOf('const emailFontWhitelist') + 80);
  console.log('Exact old:', JSON.stringify(exactOld));
  
  const exactNew = `const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&', '<': '<', '>': '>', '"': '"', "'": ''' }[c]));
const sanitizeHtml = (html) => window.DOMPurify ? DOMPurify.sanitize(html, { ALLOWED_TAGS: ['p','br','b','i','u','strike','strong','em','a','img','ul','ol','li','h1','h2','h3','h4','h5','h6','blockquote','pre','code','span','div','table','thead','tbody','tr','th','td','hr'], ALLOWED_ATTR: ['href','target','rel','src','alt','width','height','style','class','data-fld','data-preview-field','data-rem','data-atch','data-cid','data-cname','data-t','data-use','data-e','data-d','data-f','data-rp','data-edit','data-cancel','data-name','data-edit-form','data-group-add','data-group-email','data-rm','data-g','data-open-draft','data-delete-draft','data-follow','data-at','data-note','data-reply','data-done'] }) : html;
const emailFontWhitelist = ['sans-serif', 'serif', 'monospace', 'arial', 'calibri', 'georgia', 'verdana', 'times-new-roman', 'courier-new'];`;
  
  if (content.includes(exactOld)) {
    const newContent = content.replace(exactOld, exactNew);
    fs.writeFileSync('C:/Users/Sahansa/Desktop/MailDesk/frontend/index.html', newContent, 'utf8');
    console.log('Done with exact match');
  } else {
    console.log('Still not found');
  }
}