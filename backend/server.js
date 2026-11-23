require('dotenv').config();
const express=require('express'),helmet=require('helmet'),Db=require('better-sqlite3-multiple-ciphers'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),nm=require('nodemailer'),sanitizeHtml=require('sanitize-html'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const ROOT=__dirname,FRONTEND_DIR=process.env.FRONTEND_DIR||path.join(ROOT,'..','frontend');
const UPLOAD_DIR=process.env.UPLOAD_DIR||path.join(ROOT,'uploads');
if(!fs.existsSync(UPLOAD_DIR))fs.mkdirSync(UPLOAD_DIR,{recursive:true});
const multer=require('multer');
const storage=multer.diskStorage({destination:(req,f,cb)=>cb(null,UPLOAD_DIR),filename:(req,f,cb)=>cb(null,Date.now()+'-'+f.originalname.replace(/\s+/g,'_'))});
const upload=multer({storage,limits:{fileSize:25*1024*1024}});
const {JWT_SECRET:JS='dev',ENC_KEY='dev-key',MS_CLIENT_ID,MS_CLIENT_SECRET,BASE_URL='http://localhost:3000',PORT=3000,CORS_ORIGINS=''}=process.env;
const IS_TEST = process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID !== undefined;
const TRUSTED_ORIGINS=new Set([BASE_URL,...String(CORS_ORIGINS).split(',')].map(s=>s.trim().replace(/\/+$/,'')).filter(Boolean));
const key=crypto.createHash('sha256').update(ENC_KEY).digest();
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key,iv),b=Buffer.concat([c.update(t,'utf8'),c.final()]);return [iv,c.getAuthTag(),b].map(x=>x.toString('base64')).join('.')};
const dec=s=>{const[iv,tag,b]=s.split('.').map(x=>Buffer.from(x,'base64')),d=crypto.createDecipheriv('aes-256-gcm',key,iv);d.setAuthTag(tag);return Buffer.concat([d.update(b),d.final()]).toString('utf8')};
const AUTH_FAIL_RE=/invalid_grant|AADSTS|Unsupported state|unable to authenticate|bad decrypt|DECRYPTION_FAILED/i;
const DB_FILE=process.env.DB_PATH||(fs.existsSync(path.join(ROOT,'data.db'))?path.join(ROOT,'data.db'):path.join(__dirname,'data.db'));
const db=new Db(DB_FILE);
if(process.env.DB_KEY){
  const key=String(process.env.DB_KEY).replace(/'/g,"''");
  db.pragma(`key='${key}'`);
  // verify key/database is readable when encryption/auth is configured
  db.prepare('select count(*) as n from sqlite_master').get();
}
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`create table if not exists companies(id integer primary key,name text unique);
create table if not exists users(id integer primary key,company_id int,role text,email text unique,hash text);
create table if not exists user_companies(id integer primary key,user_id int not null,company_id int not null,unique(user_id,company_id));
create table if not exists senders(id integer primary key,company_id int,user_id int,provider text,from_name text,from_email text,secret text,smtp_host text,smtp_port int,smtp_user text,status text default 'active',is_default int default 0);
create table if not exists templates(id integer primary key,company_id int,name text,subject text,html text,fields text);
create table if not exists recipient_companies(id integer primary key,company_id int not null,name text not null,created_at text default current_timestamp,unique(company_id,name));
create table if not exists contacts(id integer primary key,company_id int,recipient_company_id int,email text,name text,category text,status text default 'active',created_at text default current_timestamp);
create table if not exists contact_groups(id integer primary key,company_id int,name text,created_at text default current_timestamp);
create table if not exists contact_group_members(group_id int,contact_id int);
create table if not exists attachments(id integer primary key,company_id int,sent_id int,campaign_id int,filename text,original_name text,mime_type text,size int,path text,created_at text default current_timestamp);
create table if not exists campaigns(id integer primary key,company_id int not null,user_id int,sender_id int,template_id int,name text,subject text,html text,send_mode text default 'individual',status text default 'draft',scheduled_at text,created_at text default current_timestamp,updated_at text default current_timestamp,sent_at text,error text,meta text);
create table if not exists campaign_recipients(id integer primary key,campaign_id int not null,company_id int not null,contact_id int,email text not null,status text default 'pending',sent_at text,error text,tracking_token text unique);
create table if not exists sent(id integer primary key,company_id int,user_id int,sender_id int,template_id int,campaign_id int,campaign_recipient_id int,to_list text,cc_list text,subject text,status text,error text,scheduled_at text,at text default current_timestamp,draft_html text,draft_values text,draft_attachments text);
create table if not exists email_events(id integer primary key,sent_id int,campaign_id int,campaign_recipient_id int,event_type text,event_at text default current_timestamp,ip text,user_agent text);
create table if not exists revoked_tokens(id integer primary key,jti text unique,expires_at text);`);
const ensureCol=(table,col,type)=>{ if(!/^[a-z_][a-z0-9_]*$/i.test(table)||!/^[a-z_][a-z0-9_]*$/i.test(col)||!/^[a-z ]+$/i.test(type)) throw Error('Invalid schema identifier'); const cols=new Set(db.pragma(`table_info(${table})`).map(c=>c.name)); if(!cols.has(col)) db.exec(`alter table ${table} add column ${col} ${type}`); };
ensureCol('senders','user_id','int');
for(const[column,type]of Object.entries({draft_html:'text',draft_values:'text',draft_attachments:'text',campaign_id:'int',campaign_recipient_id:'int'}))ensureCol('sent',column,type);
for(const[column,type]of Object.entries({campaign_id:'int',campaign_recipient_id:'int'}))ensureCol('email_events',column,type);
for(const[column,type]of Object.entries({recipient_company_id:'int'}))ensureCol('contacts',column,type);
for(const[column,type]of Object.entries({campaign_id:'int'}))ensureCol('attachments',column,type);
 for(const[column,type]of Object.entries({follow_up_at:'text',replied_at:'text',follow_up_note:'text',follow_up_done_at:'text',follow_up_reminded_at:'text',follow_up_repeat_days:'int',follow_up_max:'int',follow_up_sent_count:'int',follow_up_attempts:'int',follow_up_next_retry_at:'text',follow_up_last_error:'text',follow_up_sent_at:'text',in_reply_to:'text'}))ensureCol('campaign_recipients',column,type);
if(!db.prepare('select 1 from users').get()){
  const h=p=>bcrypt.hashSync(p,12);
  const superId=db.prepare('insert into users(company_id,role,email,hash) values(?,?,?,?)').run(null,'super','admin@maildesk.com',h('admin123')).lastInsertRowid;
  ['Greek Lanka Maritime Services','OCEANIC SHIP CHANDLERS (PVT) LTD','Navigator Crew Managment (PVT)LTD'].forEach(n=>{
    const cid=db.prepare('insert into companies(name) values(?)').run(n).lastInsertRowid;
    db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(superId,cid);
  });
}
try{db.prepare('select id,company_id from users where company_id is not null').all().forEach(u=>db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(u.id,u.company_id))}catch{}
try{db.exec('create unique index if not exists idx_contacts_company_email on contacts(company_id,lower(email)) where email is not null');}catch{}
try{db.exec('create unique index if not exists idx_campaign_recipient_email on campaign_recipients(campaign_id,lower(email))');}catch{}

// one-time migration for recurring follow-ups
if((db.pragma('user_version',{simple:true})||0)<1){
  try{
    const upd=db.prepare('update campaign_recipients set follow_up_at=? where id=?');
    const legacy=db.prepare('select id,follow_up_at from campaign_recipients where follow_up_at is not null').all();
    db.transaction(()=>{ for(const r of legacy){ if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(String(r.follow_up_at))){ const d=new Date(r.follow_up_at); if(!isNaN(d.getTime())) upd.run(d.toISOString(),r.id); } } })();
  }catch{}
  db.prepare('update campaign_recipients set follow_up_repeat_days=2 where follow_up_repeat_days is null').run();
  db.prepare('update campaign_recipients set follow_up_max=0 where follow_up_max is null').run();
  db.prepare('update campaign_recipients set follow_up_sent_count=0 where follow_up_sent_count is null').run();
  db.prepare('update campaign_recipients set follow_up_attempts=0 where follow_up_attempts is null').run();
  db.prepare("update campaign_recipients set follow_up_sent_count=follow_up_max where follow_up_reminded_at is not null and follow_up_reminded_at<>'retry' and coalesce(follow_up_sent_count,0)=0").run();
  db.pragma('user_version = 1');
}

// database backups (protected, non-web-accessible directory)
const BACKUP_DIR=process.env.BACKUP_DIR||path.join(ROOT,'backups');
if(!fs.existsSync(BACKUP_DIR))fs.mkdirSync(BACKUP_DIR,{recursive:true});
const BACKUP_INTERVAL_MS=Number(process.env.BACKUP_INTERVAL_MS||60*60*1000);
const KEEP_BACKUPS=Number(process.env.KEEP_BACKUPS||24);
const backupDb=async()=>{ let src=null; try{
  const stamp=new Date().toISOString().replace(/[:.]/g,'-');
  const dest=path.join(BACKUP_DIR,`maildesk-${stamp}.db`);
  src=new Db(DB_FILE);
  if(process.env.DB_KEY){ const k=String(process.env.DB_KEY).replace(/'/g,"''"); src.pragma(`key='${k}'`); }
  await src.backup(dest);
  // rotate: keep newest KEEP_BACKUPS
  const files=fs.readdirSync(BACKUP_DIR).filter(f=>f.startsWith('maildesk-')&&f.endsWith('.db')).sort().reverse();
  for(const f of files.slice(KEEP_BACKUPS)){ try{fs.unlinkSync(path.join(BACKUP_DIR,f));}catch{} }
  return dest;
}catch(e){ console.error('backup failed:',e.message); return null; }
finally{ if(src){ try{src.close();}catch{} } } };
if (!IS_TEST) {
  setInterval(()=>{ backupDb(); },BACKUP_INTERVAL_MS);
}

const PUBLIC_UPLOADS=new Set(['GLMS - LOGO-01 (1).png','OCEANIC SHIP CHANDLERS LOGO Final (2).png','Navigator logo_page-0001.jpg','Navigator_logo.jpg__2___1_-removebg-preview.png','1794484008179-Navigator_logo.jpg__2___1_-removebg-preview.png']);
const cspDirectives = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
  styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
  fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
  imgSrc: ["'self'", "data:", "https:"],
  connectSrc: ["'self'"],
  frameSrc: ["'self'"],
  objectSrc: ["'none'"],
  baseUri: ["'self'"],
  formAction: ["'self'"]
};
const app=express();app.use(helmet({contentSecurityPolicy: { directives: cspDirectives }}));app.use(express.json({limit:'2mb'}));
app.use((q,s,n)=>{ const origin=String(q.headers.origin||'').trim().replace(/\/+$/,''); if(origin && TRUSTED_ORIGINS.has(origin)){ s.setHeader('Access-Control-Allow-Origin',q.headers.origin); s.setHeader('Vary','Origin'); s.setHeader('Access-Control-Allow-Credentials','true'); s.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS'); s.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization, X-Company-Id'); s.setHeader('Access-Control-Max-Age','600'); } if(q.method==='OPTIONS'){ if(origin && !TRUSTED_ORIGINS.has(origin)) return s.sendStatus(403); return s.sendStatus(204); } n(); });
app.get('/uploads/:file',(q,s)=>{ const file=path.basename(String(q.params.file||'')); if(!PUBLIC_UPLOADS.has(file)) return s.status(404).json({error:'Not found'}); const p=path.join(UPLOAD_DIR,file); if(!fs.existsSync(p)) return s.status(404).json({error:'Not found'}); s.sendFile(p); }); if(fs.existsSync(FRONTEND_DIR))app.use(express.static(FRONTEND_DIR));
const bad=(s,m,c=400)=>s.status(c).json({error:m});
const rateBuckets=new Map();
const rateLimit=({windowMs,max,key=(q)=>q.ip||'ip',message='Too many requests, try again later'})=>{ return (q,s,n)=>{ const now=Date.now(); if(rateBuckets.size>10000){ for(const [k,v] of rateBuckets) if(v.reset<=now) rateBuckets.delete(k); }
  const k=String(key(q)||q.ip||'ip'); let b=rateBuckets.get(k); if(!b||b.reset<=now) b={count:0,reset:now+windowMs};
  b.count++; rateBuckets.set(k,b); if(b.count>max){ const retry=Math.ceil((b.reset-now)/1000); s.setHeader('Retry-After',String(Math.max(retry,1))); return s.status(429).json({error:message}); } n(); };
};
const loginLimiter=rateLimit({windowMs:15*60*1000,max:10,key:q=>`${q.ip||'ip'}:login`,message:'Too many login attempts, try again later'});
const credentialLimiter=rateLimit({windowMs:15*60*1000,max:20,key:q=>`${q.ip||'ip'}:${q.u?.id||'anon'}:cred`,message:'Too many sensitive requests, try again later'});
const sendLimiter=rateLimit({windowMs:60*1000,max:30,key:q=>`${q.ip||'ip'}:${q.u?.id||'anon'}:send`,message:'Too many send requests, please slow down'});
const importLimiter=rateLimit({windowMs:15*60*1000,max:20,key:q=>`${q.ip||'ip'}:${q.u?.id||'anon'}:import`,message:'Too many import requests, try again later'});
const okEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'').trim());
const normEmail=e=>String(e||'').trim().toLowerCase();
const isPlainObject=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const asStr=(v,max=500)=>v==null?'':String(v).slice(0,max);
const trimStr=(v,max=500)=>asStr(v,max).trim();
const reqStr=(v,max=500)=>{if(v==null)return null; const s=String(v).trim(); return s? s.slice(0,max):null};
const optStr=(v,max=500)=>v==null||v===''?null:reqStr(v,max);
const posInt=(v)=>{if(v===undefined||v===null||v==='')return null; const n=Number(v); return Number.isInteger(n)&&n>0?n:null};
const reqInt=(v)=>{const n=posInt(v); return n};
const boolish=(v)=>v===1||v===true||v==='1'||v==='true';
const enumVal=(v,vals,def=null)=>vals.includes(v)?v:def;
const emailList=(v,max=200)=>{const arr=Array.isArray(v)?v:String(v||'').split(/[;,\s,]+/); const out=[]; const seen=new Set(); for(const x of arr){ if(out.length>=max) break; const e=normEmail(x); if(!e) continue; if(!okEmail(e)) return {error:'Invalid email address'}; if(!seen.has(e)){seen.add(e); out.push(e);} } return {value:out}};
const sanitizeHtmlOptions = {
  allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
  allowedAttributes: {
    '*': ['style', 'class'],
    a: ['href', 'target', 'rel'],
    img: ['src', 'alt', 'width', 'height'],
    style: ['type']
  },
  allowedStyles: {
    '*': {
      'color': [/^#(0x)?[0-9a-f]+$/i, /^rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$/i, /^rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*[\d.]+\)$/i],
      'background-color': [/^#(0x)?[0-9a-f]+$/i, /^rgb\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\)$/i, /^rgba\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*[\d.]+\)$/i],
      'font-family': [/^.*$/],
      'font-size': [/^.*$/],
      'font-weight': [/^.*$/],
      'text-align': [/^.*$/],
      'line-height': [/^.*$/],
      'margin': [/^.*$/],
      'margin-bottom': [/^.*$/],
      'padding': [/^.*$/],
      'border': [/^.*$/],
      'border-radius': [/^.*$/],
      'width': [/^.*$/],
      'height': [/^.*$/],
      'display': [/^.*$/],
      'float': [/^.*$/]
    }
  }
};
const sanitize = (html) => sanitizeHtml(html, sanitizeHtmlOptions);
const idArray=(v,max=500)=>{if(v==null) return []; if(!Array.isArray(v)) return null; const out=[]; const seen=new Set(); for(const x of v){ if(out.length>=max) break; const n=posInt(x); if(n && !seen.has(n)){seen.add(n); out.push(n);} } return out};
const validDate=(v)=>{if(v==null||v==='')return {value:null}; if(typeof v!=='string' && typeof v!=='number') return {error:'Invalid date'}; const s=String(v).trim(); if(!s) return {value:null}; const d=new Date(s); if(isNaN(d.getTime())) return {error:'Invalid date'}; return {value:s.slice(0,40)}};
const validFollowUpDate=(v)=>{const r=validDate(v); if(r.error)return r; if(!r.value)return {value:null}; const d=new Date(r.value); return isNaN(d.getTime())?{error:'Invalid date'}:{value:d.toISOString()};};
const clampInt=(v,min,max,def)=>{const n=posInt(v); return n==null?def:Math.min(max,Math.max(min,n));};
const clampMax=(v,def=0)=>{if(v===undefined||v===null||v==='')return def; const n=Number(v); return Number.isInteger(n)&&n>=0?Math.min(20,n):def;};
const placeholders=(arr)=>arr.map(()=>'?').join(',');
const resolveCid=(q)=>{const raw=q.query.company_id??q.body?.company_id??q.headers['x-company-id']; if(raw===undefined||raw===null||raw===''){ if(q.u.role!=='super'){ const cid=q.u.company_id??(db.prepare('select company_id from user_companies where user_id=? order by company_id limit 1').get(q.u.id)?.company_id??null); if(cid){ try{db.prepare('update users set company_id=? where id=?').run(cid,q.u.id);}catch{} } return cid; } return null; } const cid=posInt(raw); if(!cid) return 'invalid'; if(q.u.role!=='super' && !db.prepare('select 1 from user_companies where user_id=? and company_id=?').get(q.u.id,cid)){ try{db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(q.u.id,cid); db.prepare('update users set company_id=? where id=?').run(cid,q.u.id);}catch{}} return cid;};
const canAccessCompany=(u,cid)=>{ if(u.role==='super')return true; return !!db.prepare('select 1 from user_companies where user_id=? and company_id=?').get(u.id,cid);};
const auth=(...roles)=>(q,s,n)=>{let tok; try{tok=jwt.verify((q.headers.authorization||'').slice(7),JS)}catch{return s.sendStatus(401)}
  if(tok.jti && db.prepare('select 1 from revoked_tokens where jti=?').get(tok.jti))return s.sendStatus(401);
  if(roles.length&&!roles.includes(tok.role))return s.sendStatus(403);
  q.u=tok;
  const cid=resolveCid(q); if(cid==='invalid') return bad(s,'Invalid company id'); if(cid){ if(!canAccessCompany(q.u,cid))return bad(s,'Company access denied',403); q.cid=cid; } else { q.cid=null; }
  n()};
const requireCompany=(q,s)=>{if(!q.cid){bad(s,'Select a company');return false}return true};
const paramId=(q,s,name='id')=>{const id=posInt(q.params[name]); if(!id){bad(s,'Invalid id',400); return null;} return id};
const bodyObj=(q,s)=>{if(q.body==null) return {}; if(!isPlainObject(q.body)){bad(s,'Invalid request body'); return null;} return q.body};

app.post('/api/logout',auth(),(q,s)=>{const jti=q.u.jti; if(jti){ const exp=new Date(q.u.exp*1000).toISOString(); db.prepare('insert or ignore into revoked_tokens(jti,expires_at) values(?,?)').run(jti,exp); } s.json({ok:1})});

app.post('/api/login',loginLimiter,(q,s)=>{ const b=bodyObj(q,s); if(!b) return; const email=normEmail(b.email); const password=asStr(b.password,200); if(!okEmail(email)||!password)return bad(s,'Wrong email or password',401);
  const u=db.prepare('select * from users where email=?').get(email);
  let ok=false; try{ if(u&&u.hash) ok=bcrypt.compareSync(password,u.hash); }catch{}
  if(!ok)return bad(s,'Wrong email or password',401);
  const companies=u.role==='super'?db.prepare('select id,name from companies order by name collate nocase').all():db.prepare('select c.id,c.name from companies c join user_companies uc on uc.company_id=c.id where uc.user_id=? order by c.name collate nocase').all(u.id);
  const companyId=u.role==='super'?null:(u.company_id&&companies.find(c=>c.id===u.company_id)?u.company_id:(companies[0]?.id??null));
  const company=companies.find(c=>c.id===companyId)?.name||'';
  const jti=crypto.randomBytes(8).toString('hex');
  s.json({token:jwt.sign({id:u.id,role:u.role,company_id:companyId,jti},JS,{expiresIn:'8h'}),role:u.role,company_id:companyId,company,companies})});

app.get('/api/me/companies',auth(),(q,s)=>{
 const rows=q.u.role==='super'?db.prepare('select id,name from companies order by name collate nocase').all():db.prepare('select c.id,c.name from companies c join user_companies uc on uc.company_id=c.id where uc.user_id=? order by c.name collate nocase').all(q.u.id);
 s.json(rows);
});

app.get('/api/companies',auth(),(q,s)=>{
  const rows=db.prepare(`select c.id,c.name,count(distinct case when s.status='sent' then s.id end) as sent_count,count(distinct uc.user_id) as user_count from companies c left join sent s on s.company_id=c.id left join user_companies uc on uc.company_id=c.id group by c.id order by c.name collate nocase`).all();
  return s.json(rows);
});
app.post('/api/companies',auth('super','admin'),(q,s)=>{ const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120); if(!name)return bad(s,'Company name is required'); try{const cid=db.prepare('insert into companies(name) values(?)').run(name).lastInsertRowid; db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(q.u.id,cid); s.json({id:cid})}catch(e){bad(s,'A company with that name already exists',409)}});
app.put('/api/companies/:id',auth('super','admin'),(q,s)=>{ const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120),id=paramId(q,s); if(!id) return; if(!name)return bad(s,'Company name is required'); if(!canAccessCompany(q.u,id)&&q.u.role!=='super')return bad(s,'Company access denied',403); try{const r=db.prepare('update companies set name=? where id=?').run(name,id); if(!r.changes)return bad(s,'Company not found',404); s.json({ok:1})}catch(e){bad(s,'A company with that name already exists',409)}});
app.delete('/api/companies/:id',auth('super'),(q,s)=>{ const id=paramId(q,s); if(!id) return; if(!db.prepare('select 1 from companies where id=?').get(id))return bad(s,'Company not found',404); db.transaction(()=>{db.prepare('delete from email_events where campaign_id in (select id from campaigns where company_id=?) or sent_id in (select id from sent where company_id=?)').run(id,id);db.prepare('delete from campaign_recipients where company_id=?').run(id);db.prepare('delete from campaigns where company_id=?').run(id);db.prepare('delete from sent where company_id=?').run(id);db.prepare('delete from contact_group_members where group_id in (select id from contact_groups where company_id=?)').run(id);db.prepare('delete from contact_groups where company_id=?').run(id);db.prepare('delete from contacts where company_id=?').run(id);db.prepare('delete from recipient_companies where company_id=?').run(id);db.prepare('delete from templates where company_id=?').run(id);db.prepare('delete from senders where company_id=?').run(id);db.prepare('delete from user_companies where company_id=?').run(id);db.prepare('delete from attachments where company_id=?').run(id);db.prepare('delete from companies where id=?').run(id)})(); s.json({ok:1})});

app.get('/api/users',auth('super','admin'),(q,s)=>{
 if(q.u.role==='super'){
  const users=db.prepare("select u.id,u.role,u.email,u.company_id,group_concat(c.name, ', ') as companies from users u left join user_companies uc on uc.user_id=u.id left join companies c on c.id=uc.company_id group by u.id order by u.role,u.email").all();
  return s.json(users.map(u=>({...u,company_ids:db.prepare('select company_id from user_companies where user_id=?').all(u.id).map(x=>x.company_id)})));
 }
 if(!requireCompany(q,s))return;
 s.json(db.prepare('select u.id,u.role,u.email from users u join user_companies uc on uc.user_id=u.id where uc.company_id=? order by u.email').all(q.cid));
});
app.post('/api/users',auth('super','admin'),credentialLimiter,(q,s)=>{ const b=bodyObj(q,s); if(!b) return; const email=normEmail(b.email), password=asStr(b.password,200), role=enumVal(b.role,['admin','user'],'user');
 if(!okEmail(email)||!password) return bad(s,'Email and password are required'); if(password.length<6) return bad(s,'Password must be at least 6 characters');
 let ids=q.u.role==='super'?idArray(b.company_ids,200): (q.cid?[q.cid]:[]);
 if(ids===null) return bad(s,'Invalid company_ids');
 ids=(ids||[]).filter(n=>Number.isInteger(n)&&n>0);
 if(!ids.length) return bad(s,'At least one company is required');
 try{db.transaction(()=>{const uid=db.prepare('insert into users(company_id,role,email,hash) values(?,?,?,?)').run(ids[0],role,email,bcrypt.hashSync(password,12)).lastInsertRowid; const ins=db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)'); ids.forEach(cid=>ins.run(uid,cid));})(); s.json({ok:1})}catch{bad(s,'That email already exists')}});
  app.put('/api/users/:id/password',auth('super','admin'),credentialLimiter,(q,s)=>{ const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const password=asStr(b.password,200); if(!password||password.length<6) return bad(s,'Password must be at least 6 characters');
    const u=db.prepare('select id,role from users where id=?').get(id); if(!u)return bad(s,'User not found',404); if(u.role==='super'&&id!==q.u.id)return bad(s,'Cannot change another super admin password',403); if(q.u.role==='admin'){ const tu=db.prepare('select company_id from users where id=?').get(id); if(!tu||tu.company_id!==q.cid)return bad(s,'Company access denied',403); }
    db.prepare('update users set hash=? where id=?').run(bcrypt.hashSync(password,12),id); s.json({ok:1})});
  app.put('/api/users/:id/companies',auth('super','admin'),(q,s)=>{ const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const target=db.prepare('select id,role from users where id=?').get(id); if(!target) return bad(s,'User not found',404); if(target.role==='super') return bad(s,'Cannot modify super admin',403); if(q.u.role==='admin' && !db.prepare('select 1 from user_companies where user_id=? and company_id=?').get(id,q.cid)) return bad(s,'User not found',404); let ids=q.u.role==='super'?idArray(b.company_ids,200):(q.cid?[q.cid]:[]); if(ids===null) return bad(s,'Invalid company_ids'); ids=(ids||[]).filter(n=>Number.isInteger(n)&&n>0); if(!ids.length)return bad(s,'At least one company is required'); const allowed=q.u.role==='super'?ids:ids.filter(cid=>cid===q.cid); if(!allowed.length)return bad(s,'Company access denied',403); db.transaction(()=>{ db.prepare('delete from user_companies where user_id=?').run(id); const ins=db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)'); allowed.forEach(cid=>ins.run(id,cid)); const first=db.prepare('select company_id from user_companies where user_id=? order by company_id limit 1').get(id)?.company_id??null; db.prepare('update users set company_id=? where id=?').run(first,id); })(); s.json({ok:1})});
app.post('/api/backup',auth('super','admin'),async(q,s)=>{ const dest=await backupDb(); if(!dest)return bad(s,'Backup failed',500); s.json({ok:1,file:path.basename(dest)})});
// senders/mailboxes (company context required)
app.get('/api/senders',auth(),(q,s)=>{ if(!requireCompany(q,s))return;
  const rows=q.u.role==='user'
   ?db.prepare('select id,provider,from_name,from_email,status,is_default,1 as is_personal from senders where company_id=? and user_id=? order by is_default desc,id desc').all(q.cid,q.u.id)
   :db.prepare('select id,provider,from_name,from_email,status,is_default,0 as is_personal from senders where company_id=? and user_id is null order by is_default desc,id desc').all(q.cid);
  s.json(rows);
});
app.post('/api/senders/smtp',auth('super','admin','user'),credentialLimiter,async(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return;
 const name=trimStr(b.name,120), fromEmail=normEmail(b.email), user=trimStr(b.user,200), host=trimStr(b.host,200), pass=asStr(b.pass,500);
 const port=posInt(b.port); if(!fromEmail||!okEmail(fromEmail)) return bad(s,'Valid sender email is required'); if(!host||!user||!pass) return bad(s,'SMTP host, user and password are required'); if(!port||port>65535) return bad(s,'Valid SMTP port is required');
 try{await nm.createTransport({host,port,secure:port===465,auth:{user,pass}}).verify()}catch{return bad(s,'SMTP connection test failed. Please check your settings.',502)}
 const owner=q.u.role==='user'?q.u.id:null,hasSender=db.prepare('select 1 from senders where company_id=? and user_id is ?').get(q.cid,owner);
 db.prepare('insert into senders(company_id,user_id,provider,from_name,from_email,secret,smtp_host,smtp_port,smtp_user,is_default,status) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,owner,'smtp',name,fromEmail,enc(pass),host,port,user,hasSender?0:1,'active'); s.json({ok:1})});
app.post('/api/senders/:id/default',auth('super','admin','user'),(q,s)=>{ if(!requireCompany(q,s))return; const owner=q.u.role==='user'?q.u.id:null; const id=paramId(q,s); if(!id) return;
 const tx=db.transaction(()=>{ db.prepare('update senders set is_default=0 where company_id=? and user_id is ?').run(q.cid,owner); const r=db.prepare('update senders set is_default=1 where id=? and company_id=? and user_id is ?').run(id,q.cid,owner); if(!r.changes) throw Object.assign(Error('Sender not found'),{status:404}); }); try{tx();s.json({ok:1})}catch(e){bad(s,e.status===404?'Sender not found':'Could not update sender',e.status||400)}});
app.delete('/api/senders/:id',auth('super','admin','user'),(q,s)=>{ if(!requireCompany(q,s))return; const owner=q.u.role==='user'?q.u.id:null; const id=paramId(q,s); if(!id) return; const r=db.prepare('delete from senders where id=? and company_id=? and user_id is ?').run(id,q.cid,owner); if(!r.changes)return bad(s,'Sender not found',404); s.json({ok:1})});

// outlook
const MS='https://login.microsoftonline.com/7b0f59c2-d0d1-4db5-8f82-a0dc5c9e8ee0/oauth2/v2.0/',SC='offline_access Mail.Read Mail.Send User.Read',RED=()=>BASE_URL+'/api/oauth/outlook/callback';const tok=async(p,scope=SC)=>{const body={client_id:MS_CLIENT_ID,client_secret:MS_CLIENT_SECRET,...(scope?{scope}:{}),...p};const r=await fetch(MS+'token',{method:'POST',body:new URLSearchParams(body)}),j=await r.json();if(!r.ok)throw Error(j.error_description||j.error);return j};
app.post('/api/senders/outlook/start',auth('super','admin','user'),credentialLimiter,(q,s)=>{ if(!requireCompany(q,s))return; if(!MS_CLIENT_ID||!MS_CLIENT_SECRET)return bad(s,'Outlook is not configured');
 s.json({url:MS+'authorize?'+new URLSearchParams({client_id:MS_CLIENT_ID,response_type:'code',redirect_uri:RED(),scope:SC,prompt:'select_account',state:jwt.sign({c:q.cid,uid:q.u.role==='user'?q.u.id:null},JS,{expiresIn:'10m'})})})});
app.get('/api/oauth/outlook/callback',async(q,s)=>{try{const{c,uid=null}=jwt.verify(String(q.query.state||''),JS),t=await tok({grant_type:'authorization_code',code:String(q.query.code||''),redirect_uri:RED()});
 const me=await(await fetch('https://graph.microsoft.com/v1.0/me',{headers:{Authorization:'Bearer '+t.access_token}})).json();
 const owner=uid||null,hasSender=db.prepare('select 1 from senders where company_id=? and user_id is ?').get(c,owner);
 db.prepare('insert into senders(company_id,user_id,provider,from_name,from_email,secret,is_default,status) values(?,?,?,?,?,?,?,?)').run(c,owner,'outlook',me.displayName||'',me.mail||me.userPrincipalName||'',enc(t.refresh_token||''),hasSender?0:1,'active'); s.redirect('/#snd')}catch{s.status(400).send('Outlook connection failed. Please try again.')}});

// templates
const keys=t=>[...new Set([...String(t||'').matchAll(/{{\s*(\w+)\s*}}/g)].map(m=>m[1]))];
const normFields=(fields,fallback)=>{ if(fields==null) return fallback; if(!Array.isArray(fields)) return null; const out=[]; for(const f of fields.slice(0,100)){ if(!isPlainObject(f)) continue; const key=trimStr(f.key,60); if(!key) continue; const label=trimStr(f.label,120)||key; const type=enumVal(f.type,['text','date','select'],'text'); const item={key,label,type}; if(Array.isArray(f.options)) item.options=f.options.slice(0,50).map(o=>trimStr(o,120)).filter(Boolean); out.push(item); } return out; };
app.get('/api/templates',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from templates order by id desc').all().map(t=>({...t,fields:JSON.parse(t.fields||'[]')})))} );
app.post('/api/templates',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120), subject=trimStr(b.subject,300), html=asStr(b.html,200000); if(!name||!html.trim())return bad(s,'Name and HTML are required');
  const clean=sanitizeHtml(html,{allowedTags:sanitizeHtml.defaults.allowedTags.concat('img'),allowedAttributes:{'*':['style','class'],a:['href','target','rel'],img:['src','alt','width','height']}});
  const fields=normFields(b.fields,keys(subject+clean).map(k=>({key:k,label:k,type:'text'}))); if(fields===null) return bad(s,'Invalid template fields');
  db.prepare('insert into templates(company_id,name,subject,html,fields) values(?,?,?,?,?)').run(q.cid,name,subject,clean,JSON.stringify(fields)); s.json({ok:1})});
app.put('/api/templates/:id',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120), subject=trimStr(b.subject,300), html=asStr(b.html,200000); if(!name||!html.trim())return bad(s,'Name and HTML are required');
  const clean=sanitizeHtml(html,{allowedTags:sanitizeHtml.defaults.allowedTags.concat('img'),allowedAttributes:{'*':['style','class'],a:['href','target','rel'],img:['src','alt','width','height']}});
 const fields=normFields(b.fields,keys(subject+clean).map(k=>({key:k,label:k,type:'text'}))); if(fields===null) return bad(s,'Invalid template fields');
 const r=db.prepare('update templates set name=?,subject=?,html=?,fields=? where id=? and company_id=?').run(name,subject,clean,JSON.stringify(fields),id,q.cid); if(!r.changes)return bad(s,'Template not found',404); s.json({ok:1})});
app.delete('/api/templates/:id',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const r=db.prepare('delete from templates where id=? and company_id=?').run(id,q.cid); if(!r.changes)return bad(s,'Template not found',404); s.json({ok:1})});
// recipient companies (parent records) & contacts
app.get('/api/recipient-companies',auth(),(q,s)=>{ if(!requireCompany(q,s))return;
  const rows=db.prepare('select rc.*, count(c.id) as contact_count from recipient_companies rc left join contacts c on c.recipient_company_id=rc.id and c.company_id=rc.company_id where rc.company_id=? group by rc.id order by lower(rc.name)').all(q.cid);
  s.json(rows.map(r=>({...r,contacts:db.prepare('select * from contacts where company_id=? and recipient_company_id=? order by lower(coalesce(nullif(name,\'\'),email))').all(q.cid,r.id)})));
});
app.post('/api/recipient-companies',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120); if(!name)return bad(s,'Company name is required'); try{const id=db.prepare('insert into recipient_companies(company_id,name) values(?,?)').run(q.cid,name).lastInsertRowid; s.json({ok:1,id})}catch{return bad(s,'Recipient company already exists')}});
app.put('/api/recipient-companies/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120); if(!name)return bad(s,'Company name is required'); const r=db.prepare('update recipient_companies set name=? where id=? and company_id=?').run(name,id,q.cid); if(!r.changes)return bad(s,'Recipient company not found',404); s.json({ok:1})});
app.delete('/api/recipient-companies/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; db.transaction(()=>{ db.prepare('update contacts set recipient_company_id=null where recipient_company_id=? and company_id=?').run(id,q.cid); const r=db.prepare('delete from recipient_companies where id=? and company_id=?').run(id,q.cid); if(!r.changes) throw Object.assign(Error('Recipient company not found'),{status:404}); })(); s.json({ok:1})});

app.get('/api/contacts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare(`select c.*, rc.name as recipient_company_name from contacts c left join recipient_companies rc on rc.id=c.recipient_company_id and rc.company_id=c.company_id where c.company_id=? order by lower(coalesce(nullif(c.name,''),c.email))`).all(q.cid))});
app.post('/api/contacts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; let email=normEmail(b.email), name=trimStr(b.name,200), category=trimStr(b.category,120), status=enumVal(b.status,['active','unsubscribed','bounced'],'active'); let recipient_company_id=posInt(b.recipient_company_id); if(!okEmail(email))return bad(s,'Valid email is required');
 if(recipient_company_id){ const rc=db.prepare('select id from recipient_companies where id=? and company_id=?').get(recipient_company_id,q.cid); if(!rc)return bad(s,'Recipient company not found',404); } else recipient_company_id=null;
 try{const id=db.prepare('insert into contacts(company_id,recipient_company_id,email,name,category,status) values(?,?,?,?,?,?)').run(q.cid,recipient_company_id,email,name,category,status).lastInsertRowid; s.json({ok:1,id})}catch(e){bad(s,'That email already exists in this company')}});
app.put('/api/contacts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; let email=normEmail(b.email), name=trimStr(b.name,200), category=trimStr(b.category,120), status=enumVal(b.status,['active','unsubscribed','bounced'],'active'); let recipient_company_id=posInt(b.recipient_company_id); if(!okEmail(email))return bad(s,'Valid email is required');
 if(recipient_company_id){ const rc=db.prepare('select id from recipient_companies where id=? and company_id=?').get(recipient_company_id,q.cid); if(!rc)return bad(s,'Recipient company not found',404); } else recipient_company_id=null;
 try{const r=db.prepare('update contacts set recipient_company_id=?,email=?,name=?,category=?,status=? where id=? and company_id=?').run(recipient_company_id,email,name,category,status,id,q.cid); if(!r.changes)return bad(s,'Contact not found',404); s.json({ok:1})}catch{return bad(s,'That email already exists in this company')}});
app.delete('/api/contacts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; db.transaction(()=>{ db.prepare('delete from contact_group_members where contact_id=? and exists(select 1 from contacts c where c.id=? and c.company_id=?)').run(id,id,q.cid); const r=db.prepare('delete from contacts where id=? and company_id=?').run(id,q.cid); if(!r.changes) throw Object.assign(Error('Contact not found'),{status:404}); })(); s.json({ok:1})});
app.post('/api/contacts/import',auth(),importLimiter,(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const list=Array.isArray(b.contacts)?b.contacts.slice(0,5000):null; if(!list||!list.length)return bad(s,'No contacts provided'); let inserted=0,skipped=0; const findRc=db.prepare('select id from recipient_companies where company_id=? and lower(name)=lower(?)'); const insRc=db.prepare('insert or ignore into recipient_companies(company_id,name) values(?,?)'); const ins=db.prepare('insert or ignore into contacts(company_id,recipient_company_id,email,name,category,status) values(?,?,?,?,?,?)');
 db.transaction(()=>{ for(const c of list){ if(!isPlainObject(c)){skipped++; continue;} const email=normEmail(c.email); if(!okEmail(email)){skipped++; continue;} let rcid=null; const rcName=trimStr(c.recipient_company||c.company,120); if(rcName){ insRc.run(q.cid,rcName); rcid=findRc.get(q.cid,rcName)?.id||null; } const info=ins.run(q.cid,rcid,email,trimStr(c.name,200),trimStr(c.category,120),enumVal(c.status,['active','unsubscribed','bounced'],'active')); if(info.changes) inserted++; else skipped++; } })(); s.json({inserted,skipped})});

// groups
app.get('/api/contact-groups',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from contact_groups where company_id=? order by lower(name)').all(q.cid))});
app.post('/api/contact-groups',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120); if(!name)return bad(s,'Group name is required'); try{s.json({ok:1,id:db.prepare('insert into contact_groups(company_id,name) values(?,?)').run(q.cid,name).lastInsertRowid})}catch{return bad(s,'Group already exists')}});
app.put('/api/contact-groups/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const name=trimStr(b.name,120); if(!name)return bad(s,'Group name is required'); const r=db.prepare('update contact_groups set name=? where id=? and company_id=?').run(name,id,q.cid); if(!r.changes)return bad(s,'Group not found',404); s.json({ok:1})});
app.delete('/api/contact-groups/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; db.transaction(()=>{ db.prepare('delete from contact_group_members where group_id=? and exists(select 1 from contact_groups g where g.id=? and g.company_id=?)').run(id,id,q.cid); const r=db.prepare('delete from contact_groups where id=? and company_id=?').run(id,q.cid); if(!r.changes) throw Object.assign(Error('Group not found'),{status:404}); })(); s.json({ok:1})});
app.get('/api/contact-groups/:id/members',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); s.json(db.prepare(`select c.*, rc.name as recipient_company_name from contact_group_members m join contacts c on c.id=m.contact_id left join recipient_companies rc on rc.id=c.recipient_company_id where m.group_id=? and c.company_id=?`).all(id,q.cid))});
app.post('/api/contact-groups/:id/members',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const ids=idArray(b.contactIds,2000); if(ids===null) return bad(s,'Invalid contactIds'); const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); const ins=db.prepare('insert or ignore into contact_group_members(group_id,contact_id) values(?,?)'); const chk=db.prepare('select id from contacts where id=? and company_id=?'); db.transaction(()=>{ ids.forEach(cid=>{ if(chk.get(cid,q.cid)) ins.run(id,cid); }); })(); s.json({ok:1})});
app.delete('/api/contact-groups/:id/members/:cid',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const cid=paramId(q,s,'cid'); if(!cid) return; const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); db.prepare('delete from contact_group_members where group_id=? and contact_id=?').run(id,cid); s.json({ok:1})});

// resolve recipients (deduped)
app.post('/api/contacts/resolve',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; let emails=Array.isArray(b.emails)?b.emails:[]; if(!Array.isArray(emails)) return bad(s,'Invalid emails');
 const contactIds=idArray(b.contactIds,2000); const recipientCompanyIds=idArray(b.recipientCompanyIds,2000); const groupIds=idArray(b.groupIds,2000);
 if(contactIds===null||recipientCompanyIds===null||groupIds===null) return bad(s,'Invalid selection ids');
 const by=new Map(); const add=(email,contact_id=null,source=null)=>{ const e=normEmail(email); if(!okEmail(e))return; if(!by.has(e)) by.set(e,{email:e,contact_id,source}); };
 for(const e of emails.slice(0,2000)) add(e,null,'manual');
 if(contactIds.length){ const rows=db.prepare(`select id,email from contacts where company_id=? and status='active' and id in ()`).all(q.cid,...contactIds); rows.forEach(r=>add(r.email,r.id,'contact')); }
 if(recipientCompanyIds.length){ const rows=db.prepare(`select id,email from contacts where company_id=? and status='active' and recipient_company_id in ()`).all(q.cid,...recipientCompanyIds); rows.forEach(r=>add(r.email,r.id,'recipient_company')); }
 if(groupIds.length){ const rows=db.prepare(`select c.id,c.email from contact_group_members m join contact_groups g on g.id=m.group_id join contacts c on c.id=m.contact_id where g.company_id=? and c.company_id=? and c.status='active' and g.id in ()`).all(q.cid,q.cid,...groupIds); rows.forEach(r=>add(r.email,r.id,'group')); }
 const recipients=[...by.values()]; s.json({recipients,emails:recipients.map(r=>r.email),count:recipients.length});
});

// attachments
app.get('/api/attachments',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from attachments where company_id=? order by id desc').all(q.cid))});
app.post('/api/attachments/upload',auth(),upload.array('files',10),(q,s)=>{ if(!requireCompany(q,s))return; const files=(q.files||[]).slice(0,10); if(!files.length) return bad(s,'No files uploaded'); const rows=[]; for(const f of files){ if(!f||!f.path) continue; const id=db.prepare('insert into attachments(company_id,filename,original_name,mime_type,size,path) values(?,?,?,?,?,?)').run(q.cid,f.filename,trimStr(f.originalname,255)||f.filename,trimStr(f.mimetype,120)||'application/octet-stream',Number(f.size)||0,f.path).lastInsertRowid; rows.push({id,original_name:f.originalname,size:f.size}); } s.json({attachments:rows})});
app.delete('/api/attachments/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const a=db.prepare('select * from attachments where id=? and company_id=?').get(id,q.cid); if(!a)return bad(s,'Attachment not found',404); try{fs.unlinkSync(a.path)}catch{} db.prepare('delete from attachments where id=?').run(a.id); s.json({ok:1})});
app.get('/api/attachments/:id/download',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const a=db.prepare('select * from attachments where id=? and company_id=?').get(id,q.cid); if(!a)return bad(s,'Attachment not found',404); s.download(a.path,a.original_name)});
// helpers, dashboard, sender resolution
const escHtml=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fill=(t,v,htmlMode)=>String(t||'').replace(/{{\s*(\w+)\s*}}/g,(_,k)=>htmlMode?escHtml(v?.[k]):String(v?.[k]??''));
const dashboardStats=(cid)=>{
 if(!cid) return {totalTemplates:0,avgOpenRate:0,sentThisMonth:0,totalSent:0,replies:0,draftsInReview:0,totalContacts:0,campaigns:0,scheduled:0};
 const totalSent=db.prepare(`select count(*) as c from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where c.company_id=? and cr.status='sent'`).get(cid).c||0;
 const now=new Date(), ym=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
 const sentThisMonth=db.prepare(`select count(*) as c from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where c.company_id=? and cr.status='sent' and substr(coalesce(cr.sent_at,c.sent_at,c.updated_at,''),1,7)=?`).get(cid,ym).c||0;
 const totalTemplates=db.prepare('select count(*) as c from templates where company_id=?').get(cid).c||0;
 const totalContacts=db.prepare("select count(*) as c from contacts where company_id=? and status='active'").get(cid).c||0;
 const campaigns=db.prepare('select count(*) as c from campaigns where company_id=?').get(cid).c||0;
 const draftsInReview=db.prepare("select count(*) as c from campaigns where company_id=? and status='draft'").get(cid).c||0;
 const scheduled=db.prepare("select count(*) as c from campaigns where company_id=? and status='scheduled'").get(cid).c||0;
 const opens=db.prepare(`select count(distinct cr.id) as c from email_events e join campaign_recipients cr on cr.id=e.campaign_recipient_id join campaigns c on c.id=cr.campaign_id where c.company_id=? and e.event_type='open' and cr.status='sent'`).get(cid).c||0;
 const avgOpenRate=totalSent?Math.min(100,Math.round(opens/totalSent*100)):0;
 return {totalTemplates,avgOpenRate,sentThisMonth,totalSent,replies:0,draftsInReview,totalContacts,campaigns,scheduled};
};

const getSender=(q,cid,sender_id)=>{
  if(sender_id===undefined||sender_id===null||sender_id==='') return {error:'Choose a sending mailbox for this campaign',status:400};
  const id=Number(sender_id); if(!id) return {error:'Choose a sending mailbox for this campaign',status:400};
  let sd=null;
  if(q.u.role==='user') sd=db.prepare("select * from senders where id=? and company_id=? and status='active' and user_id=?").get(id,cid,q.u.id);
  else sd=db.prepare("select * from senders where id=? and company_id=? and status='active' and user_id is null").get(id,cid);
  if(!sd) return {error:'Sending mailbox not found or not authorized for this company',status:403};
  return {sd};
};

const getCampaign=(q,id)=>db.prepare('select * from campaigns where id=? and company_id=?').get(id,q.cid);
const resolveRecipients=(q,body)=>{ const {emails=[],contactIds=[],recipientCompanyIds=[],groupIds=[]}=body||{}; const by=new Map(); const add=(email,contact_id=null,source='manual')=>{ const e=normEmail(email); if(!okEmail(e))return; if(!by.has(e)) by.set(e,{email:e,contact_id,source}); };
 for(const e of (Array.isArray(emails)?emails:[])) add(e,null,'manual');
 const cids=[...new Set((Array.isArray(contactIds)?contactIds:[]).map(Number).filter(Boolean))];
 if(cids.length){ db.prepare(`select id,email from contacts where company_id=? and status='active' and id in ()`).all(q.cid,...cids).forEach(r=>add(r.email,r.id,'contact')); }
 const rcids=[...new Set((Array.isArray(recipientCompanyIds)?recipientCompanyIds:[]).map(Number).filter(Boolean))];
 if(rcids.length){ db.prepare(`select id,email from contacts where company_id=? and status='active' and recipient_company_id in ()`).all(q.cid,...rcids).forEach(r=>add(r.email,r.id,'recipient_company')); }
 const gids=[...new Set((Array.isArray(groupIds)?groupIds:[]).map(Number).filter(Boolean))];
 if(gids.length){ db.prepare(`select c.id,c.email from contact_group_members m join contact_groups g on g.id=m.group_id join contacts c on c.id=m.contact_id where g.company_id=? and c.company_id=? and c.status='active' and g.id in ()`).all(q.cid,q.cid,...gids).forEach(r=>add(r.email,r.id,'group')); }
 return [...by.values()];
};

async function deliverRecipient({campaign,recipient,sd,subject,html,attachments,fromName,fromEmail,cc=[],bcc=[]}){
 let sendHtml=String(html||'').replace(/(<a[^>]*href=")([^"]*)(")/gi,(m,pre,url,post)=>{ if(url.includes('/api/track/')||url.startsWith('#')||url.startsWith('mailto:'))return m; return pre+`${BASE_URL}/api/track/click/${recipient.tracking_token}?url=${encodeURIComponent(url)}`+post; });
 sendHtml+=`<img src="${BASE_URL}/api/track/open/${recipient.tracking_token}" width="1" height="1" style="display:none" alt="" border="0">`;
  sendHtml+=`<!-- MDTRK:${recipient.tracking_token} -->`;
  const msgId=`<${crypto.randomBytes(16).toString('hex')}@${BASE_URL.replace(/^https?:\/\//,'')}.maildesk>`;
  const to=[recipient.email];
  const payload={from:`"${fromName||''}" <${fromEmail}>`,to,cc,bcc,subject,html:sendHtml,replyTo:fromEmail,attachments:(attachments||[]).map(a=>({filename:a.original_name,path:a.path})),messageId:msgId};
  let err=null, st='sent';
  try{
   if(sd.provider==='smtp'){ await nm.createTransport({host:sd.smtp_host,port:sd.smtp_port,secure:sd.smtp_port===465,auth:{user:sd.smtp_user,pass:dec(sd.secret)}}).sendMail(payload); }
   else { const t2=await tok({grant_type:'refresh_token',refresh_token:dec(sd.secret)},null); if(t2.refresh_token)db.prepare('update senders set secret=?,status=? where id=?').run(enc(t2.refresh_token),'active',sd.id);
     const rr=await fetch('https://graph.microsoft.com/v1.0/me/sendMail',{method:'POST',headers:{Authorization:'Bearer '+t2.access_token,'Content-Type':'application/json'},body:JSON.stringify({message:{subject,body:{contentType:'HTML',content:sendHtml},toRecipients:to.map(a=>({emailAddress:{address:a}})),ccRecipients:cc.map(a=>({emailAddress:{address:a}})),bccRecipients:bcc.map(a=>({emailAddress:{address:a}})),attachments:(attachments||[]).map(a=>({'@odata.type':'#microsoft.graph.fileAttachment',name:a.original_name,contentType:a.mime_type||'application/octet-stream',contentBytes:fs.readFileSync(a.path).toString('base64')})),internetMessageId:msgId},saveToSentItems:true})});
     if(!rr.ok) throw Error((await rr.text()).slice(0,200)); }
  }catch(e){ st='failed'; err=String(e.message||e).slice(0,500); if(AUTH_FAIL_RE.test(err)){ try{db.prepare("update senders set status='needs_reconnect' where id=?").run(sd.id)}catch{} } }
  const now=new Date().toISOString();
  const ccList=[...cc,...bcc.map(e=>`Bcc: ${e}`)].join(', ');
  db.transaction(()=>{
   db.prepare('update campaign_recipients set status=?,sent_at=?,error=?,in_reply_to=? where id=?').run(st,st==='sent'?now:null,err,msgId,recipient.id);
  const existing=db.prepare('select id from sent where campaign_recipient_id=?').get(recipient.id);
  if(existing) db.prepare('update sent set status=?,error=?,at=?,subject=?,sender_id=?,template_id=?,user_id=?,to_list=?,cc_list=? where id=?').run(st,err,now,subject,campaign.sender_id,campaign.template_id||null,campaign.user_id,recipient.email,ccList,existing.id);
  else db.prepare('insert into sent(company_id,user_id,sender_id,template_id,campaign_id,campaign_recipient_id,to_list,cc_list,subject,status,error,scheduled_at,at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)').run(campaign.company_id,campaign.user_id,campaign.sender_id,campaign.template_id||null,campaign.id,recipient.id,recipient.email,ccList,subject,st,err,campaign.scheduled_at||null,now);
 })();
 return {status:st,error:err};
}

async function processCampaign(id){
 const c=db.prepare('select * from campaigns where id=?').get(id); if(!c) return;
 if(!['queued','sending','scheduled'].includes(c.status)) return;
 const now=new Date();
 if(c.status==='scheduled' && c.scheduled_at){ const t=new Date(c.scheduled_at); if(!isNaN(t) && t>now) return; }
 db.prepare("update campaigns set status='sending',updated_at=current_timestamp where id=? and status in ('queued','scheduled','sending')").run(id);
 const campaign=db.prepare('select * from campaigns where id=?').get(id);
 const sd=db.prepare('select * from senders where id=? and company_id=?').get(campaign.sender_id,campaign.company_id);
 if(!sd){ db.prepare("update campaigns set status='failed',error=?,updated_at=current_timestamp where id=?").run('Sending mailbox not found',id); return; }
 const fromEmail=sd.from_email, fromName=sd.from_name||'';
 const attachments=db.prepare("select * from attachments where campaign_id=? and company_id=?").all(campaign.id,campaign.company_id);
 const recipients=db.prepare("select * from campaign_recipients where campaign_id=? and status in ('pending','failed') order by id").all(campaign.id);
 const meta=JSON.parse(campaign.meta||'{}');
 const cc=Array.isArray(meta.cc)?meta.cc:[];
 const bcc=Array.isArray(meta.bcc)?meta.bcc:[];
 let sent=0,failed=0;
 for(const r of recipients){ const res=await deliverRecipient({campaign,recipient:r,sd,subject:campaign.subject,html:campaign.html,attachments,fromName,fromEmail,cc,bcc}); if(res.status==='sent') sent++; else failed++; }
 const total=db.prepare('select count(*) as c from campaign_recipients where campaign_id=?').get(id).c||0;
 const failedAll=db.prepare("select count(*) as c from campaign_recipients where campaign_id=? and status='failed'").get(id).c||0;
 const status=failedAll===total&&total>0?'failed':'sent';
 db.prepare('update campaigns set status=?,sent_at=case when ?=\'sent\' then coalesce(sent_at,current_timestamp) else sent_at end,updated_at=current_timestamp,error=? where id=?').run(status,status,failedAll?`${failedAll} recipient(s) failed`:null,id);
}
if (!IS_TEST) {
  setInterval(()=>{
    try{ const due=db.prepare("select id from campaigns where status='scheduled' and scheduled_at is not null and datetime(scheduled_at)<=datetime('now') order by id limit 20").all();
    for(const c of due) processCampaign(c.id).catch(()=>{});
    }catch{}
    try{ db.prepare("delete from revoked_tokens where datetime(expires_at) <= datetime('now')").run(); }catch{}
  },15000);
}

// campaigns
  app.get('/api/campaigns',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const rows=db.prepare(`select c.*, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id) as recipient_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status='sent') as sent_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status='failed') as failed_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status in ('pending','queued')) as pending_count from campaigns c where c.company_id=? order by c.id desc limit 200`).all(q.cid); s.json(rows.map(c=>({...c,error:c.status==='failed'?'Failed to send campaign.':null})))});
const parseSelection=(b)=>{ const sel=isPlainObject(b?.selection)?b.selection:{}; const emails=emailList(sel.emails??b?.emails??b?.to,2000); if(emails.error) return emails; const contactIds=idArray(sel.contactIds??b?.contactIds,2000); const recipientCompanyIds=idArray(sel.recipientCompanyIds??b?.recipientCompanyIds,2000); const groupIds=idArray(sel.groupIds??b?.groupIds,2000); if(contactIds===null||recipientCompanyIds===null||groupIds===null) return {error:'Invalid recipient selection'}; return {value:{emails:emails.value,contactIds,recipientCompanyIds,groupIds}}; };
const parseCampaignBody=(b,isDraft)=>{ const name=trimStr(b.name||b.subject||'Campaign',120); const template_id=posInt(b.template_id); const sender_id=posInt(b.sender_id); const subject=trimStr(b.subject,300).replace(/[\r\n]+/g,' '); const rawHtml=asStr(b.html||b.draft_html,500000); const html=sanitize(rawHtml); const send_mode=enumVal(b.send_mode,['individual','bulk'],'individual'); const sch=validDate(b.scheduled_at); const fu=validFollowUpDate(b.follow_up_at); const follow_up_repeat_days=clampInt(b.follow_up_repeat_days,1,365,2); const follow_up_max=clampMax(b.follow_up_max,0); if(sch.error||fu.error) return {error:'Invalid date'}; const cc=emailList(b.cc,200); const bcc=emailList(b.bcc,200); if(cc.error||bcc.error) return {error:'Invalid CC/BCC email address'}; const attachment_ids=idArray(b.attachment_ids,50); if(attachment_ids===null) return {error:'Invalid attachment ids'}; const values=isPlainObject(b.values)?Object.fromEntries(Object.entries(b.values).slice(0,200).map(([k,v])=>[trimStr(k,60),asStr(v,2000)])):{}; const selection=parseSelection(b); if(selection.error) return selection; if(!isDraft){ if(!sender_id) return {error:'Choose a sending mailbox for this campaign'}; if(!subject) return {error:'Subject is required'}; if(!html.trim()) return {error:'Email body is required'}; } return {value:{name:name||'Campaign',template_id,sender_id:sender_id||null,subject,html,send_mode,scheduled_at:sch.value,follow_up_at:fu.value,follow_up_note:trimStr(b.follow_up_note,500)||null,follow_up_repeat_days,follow_up_max,attachment_ids,values,cc:cc.value,bcc:bcc.value,selection:selection.value}}; };
  app.get('/api/campaigns/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c)return bad(s,'Campaign not found',404); c.recipients=db.prepare('select * from campaign_recipients where campaign_id=? order by id').all(c.id).map(r=>({...r,error:r.status==='failed'?'Delivery failed.':null})); c.attachment_ids=db.prepare('select id,original_name,size from attachments where campaign_id=? and company_id=?').all(c.id,q.cid); c.error=c.status==='failed'?'Failed to send campaign.':null; s.json(c)});
app.post('/api/campaigns',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const isDraft=boolish(b.draft)||b.status==='draft'; const p=parseCampaignBody(b,isDraft); if(p.error) return bad(s,p.error); const body=p.value;
 let sd=null; if(!isDraft){ const r=getSender(q,q.cid,body.sender_id); if(r.error)return bad(s,r.error,r.status||400); sd=r.sd; } else if(body.sender_id){ const r=db.prepare('select id from senders where id=? and company_id=?').get(body.sender_id,q.cid); if(!r)return bad(s,'Sending mailbox not found for this company',403); }
 const recipients=resolveRecipients(q,body.selection); if(!isDraft && !recipients.length) return bad(s,'Add at least one recipient (duplicates in this campaign are removed automatically)');
 if(body.template_id && !db.prepare('select 1 from templates where id=? and company_id=?').get(body.template_id,q.cid)) return bad(s,'Template not found',404);
 if(body.attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in ()`).get(q.cid,...body.attachment_ids).n; if(n!==body.attachment_ids.length) return bad(s,'Attachment not found',404); }
 const status=isDraft?'draft':(body.scheduled_at?'scheduled':'queued');
 const result=db.transaction(()=>{
  const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,body.sender_id,body.template_id,body.name,body.subject,body.html,body.send_mode,status,body.scheduled_at,JSON.stringify({values:body.values,cc:body.cc,bcc:body.bcc,selection:body.selection,follow_up_at:body.follow_up_at,follow_up_note:body.follow_up_note,follow_up_repeat_days:body.follow_up_repeat_days,follow_up_max:body.follow_up_max})).lastInsertRowid;
  const ins=db.prepare('insert into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max) values(?,?,?,?,?,?,?,?,?)');
  for(const r of recipients) ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'),body.follow_up_at,body.follow_up_note,body.follow_up_repeat_days,body.follow_up_max);
  if(body.attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in ()`).run(id,q.cid,...body.attachment_ids);
  return {id,recipient_count:recipients.length,status};
 })();
 if(result.status==='queued'){ try{ await processCampaign(result.id); }catch(e){ db.prepare("update campaigns set status='failed',error=? where id=?").run(String(e.message||e).slice(0,300),result.id); } const c=db.prepare('select status,error from campaigns where id=?').get(result.id); result.status=c?.status||result.status; if(result.status==='failed') result.error='Failed to send campaign.'; }
 s.json(result);
});

app.get('/api/dashboard',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(dashboardStats(q.cid))});
// campaign send-now, schedule runner already set; drafts as draft campaigns
app.put('/api/campaigns/:id',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); if(c.status!=='draft' && c.status!=='scheduled') return bad(s,'Only draft or scheduled campaigns can be edited');
  const b=bodyObj(q,s); if(!b) return; const meta0=JSON.parse(c.meta||'{}');
  const sender_id=b.sender_id!==undefined?posInt(b.sender_id):c.sender_id; if(b.sender_id!==undefined && b.sender_id!=null && b.sender_id!=='' && !sender_id) return bad(s,'Invalid sender_id'); if(sender_id && !db.prepare('select 1 from senders where id=? and company_id=?').get(sender_id,q.cid)) return bad(s,'Sending mailbox not found for this company',403);
  const template_id=b.template_id!==undefined?posInt(b.template_id):c.template_id; if(b.template_id!==undefined && b.template_id!=null && b.template_id!=='' && !template_id) return bad(s,'Invalid template_id'); if(template_id && !db.prepare('select 1 from templates where id=? and company_id=?').get(template_id,q.cid)) return bad(s,'Template not found',404);
  let recipients=null; if(b.selection!==undefined){ const sel=parseSelection(b); if(sel.error) return bad(s,sel.error); recipients=resolveRecipients(q,sel.value); b._selection=sel.value; }
  const subject=b.subject!==undefined?trimStr(b.subject,300).replace(/[\r\n]+/g,' '):c.subject; const rawHtml=b.html!==undefined?asStr(b.html,500000):c.html; const html=sanitize(rawHtml);
  const name=b.name!==undefined?(trimStr(b.name,120)||subject||'Campaign').slice(0,120):c.name; const send_mode=b.send_mode!==undefined?enumVal(b.send_mode,['individual','bulk'],c.send_mode):c.send_mode;
  const sch=b.scheduled_at!==undefined?validDate(b.scheduled_at):{value:c.scheduled_at}; if(sch.error) return bad(s,'Invalid scheduled_at'); const scheduled_at=sch.value;
  const status=b.status==='draft'?'draft':(scheduled_at?'scheduled':(b.send_now?'queued':c.status));
  const fu=b.follow_up_at!==undefined?validFollowUpDate(b.follow_up_at):{value:meta0.follow_up_at||null}; if(fu.error) return bad(s,'Invalid follow_up_at'); const follow_up_at=fu.value;
  const follow_up_repeat_days=b.follow_up_repeat_days!==undefined?clampInt(b.follow_up_repeat_days,1,365,2):(meta0.follow_up_repeat_days??2);
  const follow_up_max=b.follow_up_max!==undefined?clampMax(b.follow_up_max,0):(meta0.follow_up_max??0);
  const follow_up_note=b.follow_up_note!==undefined?(trimStr(b.follow_up_note,500)||null):(meta0.follow_up_note||null);
  const cc=b.cc!==undefined?emailList(b.cc,200):{value:meta0.cc||[]}; const bccE=b.bcc!==undefined?emailList(b.bcc,200):{value:meta0.bcc||[]}; if(cc.error||bccE.error) return bad(s,'Invalid CC/BCC email address');
  const values=b.values!==undefined?(isPlainObject(b.values)?Object.fromEntries(Object.entries(b.values).slice(0,200).map(([k,v])=>[trimStr(k,60),asStr(v,2000)])):null):meta0.values||{}; if(values===null) return bad(s,'Invalid values');
  const attachment_ids=b.attachment_ids!==undefined?idArray(b.attachment_ids,50):null; if(attachment_ids===null && b.attachment_ids!==undefined) return bad(s,'Invalid attachment ids');
  if(attachment_ids && attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in ()`).get(q.cid,...attachment_ids).n; if(n!==attachment_ids.length) return bad(s,'Attachment not found',404); }
  db.transaction(()=>{
    db.prepare('update campaigns set sender_id=?,template_id=?,name=?,subject=?,html=?,send_mode=?,status=?,scheduled_at=?,meta=?,updated_at=current_timestamp where id=? and company_id=?').run(sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,JSON.stringify({values,cc:cc.value,bcc:bccE.value,selection:b._selection||meta0.selection||null,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max}),id,q.cid);
    if(recipients){ db.prepare('delete from campaign_recipients where campaign_id=? and status not in (\'sent\')').run(id); const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max) values(?,?,?,?,?,\'pending\',?,?,?,?)'); recipients.forEach(r=>ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'),follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max)); } else if(b.follow_up_at!==undefined||b.follow_up_note!==undefined||b.follow_up_repeat_days!==undefined||b.follow_up_max!==undefined){ db.prepare("update campaign_recipients set follow_up_at=?, follow_up_note=?, follow_up_repeat_days=?, follow_up_max=?, follow_up_done_at=null, follow_up_sent_count=0, follow_up_attempts=0, follow_up_reminded_at=null, follow_up_next_retry_at=null, follow_up_last_error=null where campaign_id=? and status not in ('replied')").run(follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max,id); }
    if(attachment_ids){ db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in ()`).run(id,q.cid,...attachment_ids); }
  })();
  if(status==='queued'){ try{ await processCampaign(id); }catch(e){ db.prepare("update campaigns set status='failed',error=? where id=?").run(String(e.message||e).slice(0,300),id); } }
  const out=getCampaign(q,id); out.recipients=db.prepare('select id,email,status,error,sent_at from campaign_recipients where campaign_id=?').all(id); s.json(out);
});
app.post('/api/campaigns/:id/send',auth(),sendLimiter,async(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); const sender=getSender(q,q.cid,c.sender_id); if(sender.error) return bad(s,sender.error,sender.status||400); const count=db.prepare("select count(*) as n from campaign_recipients where campaign_id=? and status in ('pending','failed')").get(id).n; if(!count) return bad(s,'No recipients to send to'); if(!c.subject||!String(c.html||'').trim()) return bad(s,'Subject and body are required'); db.prepare("update campaigns set status='queued',updated_at=current_timestamp where id=?").run(id); await processCampaign(id); const out=db.prepare('select * from campaigns where id=?').get(id); if(out) out.error=out.status==='failed'?'Failed to send campaign.':null; s.json(out); });
app.delete('/api/campaigns/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); db.transaction(()=>{ db.prepare('delete from email_events where campaign_id=?').run(id); db.prepare('update attachments set campaign_id=null, sent_id=null where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from sent where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from campaign_recipients where campaign_id=?').run(id); db.prepare('delete from campaigns where id=? and company_id=?').run(id,q.cid); })(); s.json({ok:1})});

// sent/log per company (derived from campaign recipients)
app.get('/api/sent',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const scopeAll=String(q.query.scope||'')==='all'; const ownOnly=!scopeAll&&q.u.role!=='super'; const rows=db.prepare(`select cr.id, cr.email as to_list, '' as cc_list, c.subject, cr.status, cr.error, coalesce(cr.sent_at,c.updated_at,c.created_at) as at, c.scheduled_at, c.id as campaign_id, c.name as campaign_name, c.send_mode, c.user_id as owner_id, s.from_email as sender_email, cr.follow_up_at, cr.replied_at, cr.follow_up_done_at, cr.follow_up_note, cr.follow_up_repeat_days, cr.follow_up_max, cr.follow_up_sent_count, cr.follow_up_sent_at, cr.follow_up_last_error, cr.follow_up_next_retry_at, cr.follow_up_reminded_at, (select count(*) from email_events e where e.campaign_recipient_id=cr.id and e.event_type='followup') as followups, (select count(*) from email_events e where e.campaign_recipient_id=cr.id and e.event_type='open') as opens, (select count(*) from email_events e where e.campaign_recipient_id=cr.id and e.event_type='click') as clicks, (select count(*) from email_events e where e.campaign_recipient_id=cr.id and e.event_type='reply') as replies from campaign_recipients cr join campaigns c on c.id=cr.campaign_id left join senders s on s.id=c.sender_id where c.company_id=? and c.status!='draft' ${ownOnly?'and c.user_id=?':''} order by cr.id desc limit 200`).all(q.cid,...(ownOnly?[q.u.id]:[])); s.json(rows.map(r=>({...r,error:r.status==='failed'?'Delivery failed.':null})))});
app.get('/api/campaigns/:id/events',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); s.json(db.prepare(`select e.*, cr.email from email_events e left join campaign_recipients cr on cr.id=e.campaign_recipient_id where e.campaign_id=? order by e.id desc limit 500`).all(c.id))});

// tracking by recipient token (scoped to campaign/company through token)
app.get('/api/track/open/:token',(q,s)=>{const token=String(q.params.token||'').slice(0,128); const r=db.prepare('select id,campaign_id from campaign_recipients where tracking_token=?').get(token); if(r){ try{db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,r.id,'open',q.ip,asStr(q.get('User-Agent'),500))}catch{} } s.type('image/gif'); s.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7','base64'));});
app.get('/api/track/click/:token',(q,s)=>{const token=String(q.params.token||'').slice(0,128); const r=db.prepare('select id,campaign_id from campaign_recipients where tracking_token=?').get(token); if(r){ try{db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,r.id,'click',q.ip,asStr(q.get('User-Agent'),500))}catch{} } const url=String(q.query.url||'/').slice(0,2000); s.redirect(/^https?:\/\//i.test(url)?url:'/');});
app.get('/api/track/events/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const rows=db.prepare(`select e.*, cr.email, cr.follow_up_at, cr.replied_at, cr.follow_up_done_at, cr.follow_up_sent_count, cr.follow_up_max, cr.follow_up_last_error, cr.follow_up_sent_at from email_events e join campaign_recipients cr on cr.id=e.campaign_recipient_id join campaigns c on c.id=cr.campaign_id where c.company_id=? and (cr.id=? or c.id=?) order by e.id desc`).all(q.cid,id,id); s.json(rows)});

// follow-up and reply tracking
app.put('/api/campaign-recipients/:id/follow-up',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const r=db.prepare('select cr.* from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where cr.id=? and c.company_id=?').get(id,q.cid); if(!r) return bad(s,'Recipient not found',404); const b=bodyObj(q,s); if(!b) return; const fu=validFollowUpDate(b.follow_up_at); if(fu.error) return bad(s,'Invalid follow_up_at'); const follow_up_at=fu.value; const follow_up_note=b.follow_up_note!==undefined?trimStr(b.follow_up_note,500):r.follow_up_note; const follow_up_repeat_days=clampInt(b.follow_up_repeat_days,1,365,r.follow_up_repeat_days||2); const follow_up_max=clampMax(b.follow_up_max,(r.follow_up_max||0)); const follow_up_done_at=boolish(b.done)?new Date().toISOString():((boolish(b.clear_done)||follow_up_at)?null:r.follow_up_done_at); const snooze=boolish(b.snooze); const scheduleChanged=!snooze&&((b.follow_up_at!==undefined&&follow_up_at!==r.follow_up_at)||(b.follow_up_repeat_days!==undefined&&follow_up_repeat_days!==(r.follow_up_repeat_days||2))||(b.follow_up_max!==undefined&&follow_up_max!==(r.follow_up_max||0))||(b.follow_up_at!==undefined&&!follow_up_at)); const follow_up_sent_count=scheduleChanged?0:(r.follow_up_sent_count||0); const remindedAt=(snooze||scheduleChanged)?null:r.follow_up_reminded_at; db.prepare('update campaign_recipients set follow_up_at=?, follow_up_note=?, follow_up_repeat_days=?, follow_up_max=?, follow_up_done_at=?, follow_up_sent_count=?, follow_up_attempts=0, follow_up_reminded_at=?, follow_up_next_retry_at=null, follow_up_last_error=null where id=?').run(follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max,follow_up_done_at,follow_up_sent_count,remindedAt,id); s.json(db.prepare('select cr.id,cr.email,cr.follow_up_at,cr.replied_at,cr.follow_up_done_at,cr.follow_up_note,cr.follow_up_repeat_days,cr.follow_up_max,cr.follow_up_sent_count,cr.follow_up_sent_at,cr.follow_up_last_error from campaign_recipients cr where cr.id=?').get(id)); });
app.post('/api/campaign-recipients/:id/reply',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const r=db.prepare('select cr.*, c.company_id as cid from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where cr.id=? and c.company_id=?').get(id,q.cid); if(!r) return bad(s,'Recipient not found',404); const b=bodyObj(q,s); if(!b) return; const note=trimStr(b.note,500); const at=new Date().toISOString(); db.transaction(()=>{ db.prepare('update campaign_recipients set replied_at=coalesce(replied_at,?), follow_up_note=? where id=?').run(at,note||r.follow_up_note,id); db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,id,'reply',q.ip,note||asStr(q.get('User-Agent'),500)); })(); s.json(db.prepare('select cr.id,cr.email,cr.follow_up_at,cr.replied_at,cr.follow_up_done_at,cr.follow_up_note,cr.follow_up_repeat_days,cr.follow_up_max,cr.follow_up_sent_count,cr.follow_up_sent_at,cr.follow_up_last_error from campaign_recipients cr where cr.id=?').get(id)); });

// compatibility: drafts endpoints map to draft campaigns for existing UI
app.get('/api/drafts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const rows=db.prepare(`select c.id, c.updated_at as at, coalesce((select group_concat(email, ', ') from (select email from campaign_recipients cr where cr.campaign_id=c.id limit 20)), '') as to_list, '' as cc_list, c.subject, c.sender_id, c.template_id, c.scheduled_at, c.send_mode from campaigns c where c.company_id=? and c.status='draft' order by c.id desc`).all(q.cid); s.json(rows)});
app.get('/api/drafts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); const meta=JSON.parse(c.meta||'{}'); s.json({id:c.id,to_list:db.prepare("select group_concat(email, ', ') as v from campaign_recipients where campaign_id=?").get(c.id).v||'',cc_list:(meta.cc||[]).join(', '),bcc_list:(meta.bcc||[]).join(', '),subject:c.subject,template_id:c.template_id,sender_id:c.sender_id,scheduled_at:c.scheduled_at,draft_html:c.html,values:meta.values||{},attachment_ids:db.prepare('select id from attachments where campaign_id=? and company_id=?').all(c.id,q.cid).map(a=>a.id),attachments:db.prepare('select id,original_name,size from attachments where campaign_id=? and company_id=?').all(c.id,q.cid),send_mode:c.send_mode,selection:meta.selection||null,follow_up_at:meta.follow_up_at||db.prepare('select follow_up_at from campaign_recipients where campaign_id=? limit 1').get(c.id)?.follow_up_at||null,follow_up_note:meta.follow_up_note||db.prepare('select follow_up_note from campaign_recipients where campaign_id=? limit 1').get(c.id)?.follow_up_note||'',follow_up_repeat_days:meta.follow_up_repeat_days??db.prepare('select follow_up_repeat_days from campaign_recipients where campaign_id=? limit 1').get(c.id)?.follow_up_repeat_days??3,follow_up_max:meta.follow_up_max??db.prepare('select follow_up_max from campaign_recipients where campaign_id=? limit 1').get(c.id)?.follow_up_max??3})});
app.put('/api/drafts/:id',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const b=bodyObj(q,s); if(!b) return; const c=getCampaign(q,id); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); try{
    const sel=parseSelection(b); if(sel.error) return bad(s,sel.error); const recipients=resolveRecipients(q,sel.value);
    const attachment_ids=idArray(b.attachment_ids,50); if(attachment_ids===null) return bad(s,'Invalid attachment ids');
    if(attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in ()`).get(q.cid,...attachment_ids).n; if(n!==attachment_ids.length) return bad(s,'Attachment not found',404); }
    const sch=validDate(b.scheduled_at), fu=validFollowUpDate(b.follow_up_at); if(sch.error||fu.error) return bad(s,'Invalid date'); const follow_up_repeat_days=clampInt(b.follow_up_repeat_days,1,365,2); const follow_up_max=clampMax(b.follow_up_max,0);
    const cc=emailList(b.cc,200), bcc=emailList(b.bcc,200); if(cc.error||bcc.error) return bad(s,'Invalid CC/BCC email address');
    const values=isPlainObject(b.values)?Object.fromEntries(Object.entries(b.values).slice(0,200).map(([k,v])=>[trimStr(k,60),asStr(v,2000)])):{};
    const rawDraftHtml = asStr(b.html,500000);
    const draftHtml = sanitize(rawDraftHtml);
    db.transaction(()=>{ db.prepare('update campaigns set sender_id=?,template_id=?,subject=?,html=?,send_mode=?,scheduled_at=?,meta=?,updated_at=current_timestamp where id=? and company_id=?').run(posInt(b.sender_id),posInt(b.template_id),trimStr(b.subject,300).replace(/[\r\n]+/g,' '),draftHtml,enumVal(b.send_mode,['individual','bulk'],c.send_mode),sch.value,JSON.stringify({values,cc:cc.value,bcc:bcc.value,selection:sel.value,follow_up_at:fu.value,follow_up_note:trimStr(b.follow_up_note,500)||null,follow_up_repeat_days,follow_up_max}),id,q.cid); db.prepare('delete from campaign_recipients where campaign_id=?').run(id); const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max) values(?,?,?,?,?,\'pending\',?,?,?,?)'); recipients.forEach(r=>ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'),fu.value,trimStr(b.follow_up_note,500)||null,follow_up_repeat_days,follow_up_max)); db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in ()`).run(id,q.cid,...attachment_ids); })(); s.json({ok:1,id}); }catch{bad(s,'Could not save draft')} });
app.delete('/api/drafts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=paramId(q,s); if(!id) return; const c=getCampaign(q,id); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); db.transaction(()=>{ db.prepare('delete from campaign_recipients where campaign_id=?').run(id); db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from campaigns where id=? and company_id=?').run(id,q.cid); })(); s.json({ok:1})});

// legacy send endpoint -> create/send campaign (keeps old clients minimally working)
app.post('/api/send',auth(),sendLimiter,async(q,s)=>{ if(!requireCompany(q,s))return; const b=bodyObj(q,s); if(!b) return; const isDraft=boolish(b.draft); const p=parseCampaignBody(b,isDraft); if(p.error) return bad(s,p.error); const body=p.value;
  if(isDraft){ const recipients=resolveRecipients(q,body.selection); const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,body.sender_id,body.template_id,body.name,body.subject,body.html,body.send_mode,'draft',body.scheduled_at,JSON.stringify({values:body.values,cc:body.cc,bcc:body.bcc,selection:body.selection,follow_up_at:body.follow_up_at,follow_up_note:body.follow_up_note,follow_up_repeat_days:body.follow_up_repeat_days,follow_up_max:body.follow_up_max})).lastInsertRowid; const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max) values(?,?,?,?,?,\'pending\',?,?,?,?)'); recipients.forEach(x=>ins.run(id,q.cid,x.contact_id||null,x.email,crypto.randomBytes(16).toString('hex'),body.follow_up_at,body.follow_up_note,body.follow_up_repeat_days,body.follow_up_max)); if(body.attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in ()`).run(id,q.cid,...body.attachment_ids); return s.json({status:'draft',id}); }
  const recipients=resolveRecipients(q,body.selection); if(!recipients.length) return bad(s,'Add at least one recipient (duplicates in this campaign are removed automatically)');
  const sender=getSender(q,q.cid,body.sender_id); if(sender.error) return bad(s,sender.error,sender.status||400);
  if(body.template_id && !db.prepare('select 1 from templates where id=? and company_id=?').get(body.template_id,q.cid)) return bad(s,'Template not found',404);
  if(body.attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in ()`).get(q.cid,...body.attachment_ids).n; if(n!==body.attachment_ids.length) return bad(s,'Attachment not found',404); }
  const campaignId=db.transaction(()=>{ const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,body.sender_id,body.template_id,body.name,body.subject,body.html,body.send_mode,body.scheduled_at?'scheduled':'queued',body.scheduled_at,JSON.stringify({values:body.values,cc:body.cc,bcc:body.bcc,selection:body.selection,follow_up_at:body.follow_up_at,follow_up_note:body.follow_up_note,follow_up_repeat_days:body.follow_up_repeat_days,follow_up_max:body.follow_up_max})).lastInsertRowid; const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status,follow_up_at,follow_up_note,follow_up_repeat_days,follow_up_max) values(?,?,?,?,?,\'pending\',?,?,?,?)'); recipients.forEach(x=>ins.run(id,q.cid,x.contact_id||null,x.email,crypto.randomBytes(16).toString('hex'),body.follow_up_at,body.follow_up_note,body.follow_up_repeat_days,body.follow_up_max)); if(body.attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in ()`).run(id,q.cid,...body.attachment_ids); return id; })();
  if(body.scheduled_at){ return s.json({status:'scheduled',id:campaignId}); }
  await processCampaign(campaignId); const c=db.prepare('select status,error from campaigns where id=?').get(campaignId); s.json({status:c?.status||'sent',id:campaignId,error:c?.status==='failed'?'Failed to send campaign.':null});
});

// follow-up reminder emails: notify the relevant sender's mailbox when a follow-up is due
const htmlEsc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function sendRawEmail(sd,fromName,fromEmail,to,subject,html){
  if(sd.provider==='smtp'){ await nm.createTransport({host:sd.smtp_host,port:sd.smtp_port,secure:sd.smtp_port===465,auth:{user:sd.smtp_user,pass:dec(sd.secret)}}).sendMail({from:`"${fromName||''}" <${fromEmail}>`,to,subject,html}); return; }
  const t2=await tok({grant_type:'refresh_token',refresh_token:dec(sd.secret)},null); if(t2.refresh_token)db.prepare('update senders set secret=?,status=? where id=?').run(enc(t2.refresh_token),'active',sd.id);
  const rr=await fetch('https://graph.microsoft.com/v1.0/me/sendMail',{method:'POST',headers:{Authorization:'Bearer '+t2.access_token,'Content-Type':'application/json'},body:JSON.stringify({message:{subject,body:{contentType:'HTML',content:html},toRecipients:[{emailAddress:{address:to}}]},saveToSentItems:true})});
  if(!rr.ok) throw Error((await rr.text()).slice(0,200));
}
async function processFollowUpReminders(){
  try{
    const rows=db.prepare(`select cr.id,cr.email,cr.follow_up_at,cr.follow_up_note,cr.follow_up_repeat_days,cr.follow_up_max,cr.follow_up_sent_count,cr.follow_up_attempts,cr.follow_up_next_retry_at,cr.follow_up_reminded_at,
      c.id as campaign_id,c.subject as campaign_subject,c.company_id,c.user_id,u.email as owner_email,
      s.id as sender_id,s.provider,s.from_name,s.from_email,s.secret,s.smtp_host,s.smtp_port,s.smtp_user
      from campaign_recipients cr join campaigns c on c.id=cr.campaign_id left join senders s on s.id=c.sender_id left join users u on u.id=c.user_id
      where cr.follow_up_at is not null and cr.replied_at is null and cr.follow_up_done_at is null and c.status!='draft' limit 500`).all();
    const now=Date.now();
    const nowIso=new Date().toISOString();
    for(const r of rows){
      const due=new Date(r.follow_up_at).getTime(); if(Number.isNaN(due)||due>now) continue;
      const max=Math.min(20,Number(r.follow_up_max)||0);
      const sentCount=Number(r.follow_up_sent_count)||0;
      if(max>0 && sentCount>=max) continue;
      const attempts=Number(r.follow_up_attempts)||0;
      if(r.follow_up_reminded_at && r.follow_up_reminded_at!=='retry'){
        const claimedAt=new Date(r.follow_up_reminded_at).getTime();
        const stale=!Number.isNaN(claimedAt) && (now-claimedAt)>10*60*1000 && attempts<5;
        if(!stale) continue;
      }
      if(r.follow_up_reminded_at==='retry'){
        const retryAt=r.follow_up_next_retry_at?new Date(r.follow_up_next_retry_at).getTime():0;
        if(retryAt>now) continue;
      }
      const claim=db.prepare(`update campaign_recipients set follow_up_reminded_at=?, follow_up_attempts=coalesce(follow_up_attempts,0)+1 where id=? and replied_at is null and follow_up_done_at is null and (follow_up_reminded_at is null or follow_up_reminded_at='retry') and follow_up_at=?`).run(nowIso,r.id,r.follow_up_at);
      if(!claim.changes) continue;
      let usedSenderId=r.sender_id;
      try{
        let to=r.from_email;
        if(!to){
          const def=db.prepare("select from_email from senders where company_id=? and status='active' order by is_default desc,id desc limit 1").get(r.company_id);
          to=(def&&def.from_email)||r.owner_email||null;
        }
        const actives=db.prepare("select * from senders where company_id=? and status='active' order by is_default desc,id desc").all(r.company_id);
        let sd=actives.find(x=>x.from_email && (!to || x.from_email.toLowerCase()!==String(to).toLowerCase())) || actives[0] || {id:r.sender_id,provider:r.provider,from_name:r.from_name,from_email:r.from_email,secret:r.secret,smtp_host:r.smtp_host,smtp_port:r.smtp_port,smtp_user:r.smtp_user};
        usedSenderId=sd.id;
        if(!sd.id || !sd.from_email || !to) throw Error('No sending mailbox or sender address for follow-up');
        const subject=`[MailDesk] Follow-up reminder: ${r.campaign_subject||'(no subject)'}`;
        const html=`<p>Follow-up reminder</p><p><b>To:</b> ${htmlEsc(r.email)}</p><p><b>Subject:</b> ${htmlEsc(r.campaign_subject||'')}</p><p><b>From:</b> ${htmlEsc(sd.from_email)}</p><p><b>Due:</b> ${htmlEsc(String(r.follow_up_at).replace('T',' '))}</p>${r.follow_up_note?`<p><b>Note:</b> ${htmlEsc(r.follow_up_note)}</p>`:''}<p><a href="${BASE_URL}/#trk">Open MailDesk Tracking</a></p>`;
        console.log(`follow-up reminder: cr=${r.id} to=${to} from=${sd.from_email} sender_id=${sd.id} (${sentCount+1}${max>0?'/'+max:''})`);
        await sendRawEmail(sd,sd.from_name,sd.from_email,to,subject,html);
        const nextSent=sentCount+1;
        const final=max>0 && nextSent>=max;
        const repeatDays=Math.max(1,Math.min(365,Number(r.follow_up_repeat_days)||2));
        let nextMs=due+repeatDays*86400000; if(nextMs<=now) nextMs=now+repeatDays*86400000;
        const nextAt=final?null:new Date(nextMs).toISOString();
        db.prepare('update campaign_recipients set follow_up_sent_count=?, follow_up_sent_at=?, follow_up_attempts=0, follow_up_next_retry_at=null, follow_up_last_error=null, follow_up_reminded_at=?, follow_up_at=? where id=?').run(nextSent,nowIso,final?'done':null,nextAt,r.id);
        try{db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,r.id,'followup',null,`reminder ${nextSent}${max>0?'/'+max:''}`);}catch{}
        console.log(`follow-up reminder sent: cr=${r.id} to=${to} from=${sd.from_email} (${nextSent}${max>0?'/'+max:''})${final?' final':''}`);
      }catch(e){
        const msg=String(e.message||e);
        console.error('follow-up reminder failed:',msg);
        if(AUTH_FAIL_RE.test(msg)){
          try{db.prepare("update senders set status='needs_reconnect' where id=?").run(usedSenderId);}catch{}
          db.prepare("update campaign_recipients set follow_up_reminded_at='blocked', follow_up_last_error=?, follow_up_next_retry_at=null where id=?").run(msg.slice(0,500),r.id);
        } else {
          const attempt=attempts+1;
          const transient=/timeout|ECONN|ENOTFOUND|EAI_AGAIN|socket hang up|fetch failed|network|5\d\d|429|rate limit/i.test(msg);
          if(transient && attempt<5){
            const backoff=[60,300,1800,7200,21600][Math.min(attempt-1,4)]*1000;
            const nextRetry=new Date(now+backoff).toISOString();
            db.prepare("update campaign_recipients set follow_up_reminded_at='retry', follow_up_next_retry_at=?, follow_up_last_error=? where id=?").run(nextRetry,msg.slice(0,500),r.id);
            console.log(`follow-up reminder retry ${attempt}/5: cr=${r.id} at ${nextRetry}`);
          } else {
            db.prepare("update campaign_recipients set follow_up_reminded_at='blocked', follow_up_last_error=?, follow_up_next_retry_at=null where id=?").run(msg.slice(0,500),r.id);
          }
        }
      }
    }
  }catch(e){ console.error('follow-up reminder job failed:',e.message); }
}
if (!IS_TEST) {
  setInterval(processFollowUpReminders,60*1000);
}

// outlook reply scanner: read active outlook mailboxes and mark replies to sent campaigns
async function scanOutlookReplies(){
  try{
    const list=db.prepare("select * from senders where provider='outlook' and status='active'").all();
    for(const sd of list){
      let access;
      try{
        const t2=await tok({grant_type:'refresh_token',refresh_token:dec(sd.secret)},null);
        if(t2.refresh_token) db.prepare('update senders set secret=?,status=? where id=?').run(enc(t2.refresh_token),'active',sd.id);
        access=t2.access_token;
      }catch{ continue; }
      let data;
      try{
        const rr=await fetch('https://graph.microsoft.com/v1.0/me/messages?$top=50&$orderby=receivedDateTime desc&$select=subject,from,receivedDateTime,inReplyTo,internetMessageId,body,internetMessageHeaders',{headers:{Authorization:'Bearer '+access}});
        if(!rr.ok) continue;
        data=await rr.json();
      }catch{ continue; }
      const msgs=Array.isArray(data.value)?data.value:[];
      for(const m of msgs){
        const subj=String(m.subject||'');
        const from=String((m.from&&m.from.emailAddress&&m.from.emailAddress.address)||'').toLowerCase();
        if(!from) continue;
        const at=m.receivedDateTime||new Date().toISOString();
        let rec=null;
        // 1) In-Reply-To / Message-ID header match
        const irt=String(m.inReplyTo||m.internetMessageId||'').trim().toLowerCase();
        if(irt){
          rec=db.prepare(`select cr.id, cr.campaign_id from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where c.company_id=? and lower(cr.in_reply_to)=? and cr.status='sent' and cr.replied_at is null order by cr.id desc limit 1`).get(sd.company_id,irt);
        }
        // 2) MDTRK token in body
        if(!rec){
          const body=String(m.body&&m.body.content||'');
          const tk=(body.match(/MDTRK:([0-9a-f]{32})/i)||[])[1];
          if(tk){
            rec=db.prepare(`select cr.id, cr.campaign_id from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where c.company_id=? and lower(cr.tracking_token)=? and cr.status='sent' and cr.replied_at is null order by cr.id desc limit 1`).get(sd.company_id,tk.toLowerCase());
          }
        }
        // 3) Fallback: subject Re: + sender email
        if(!rec && /^\s*re\s*:/i.test(subj)){
          rec=db.prepare(`select cr.id, cr.campaign_id from campaign_recipients cr join campaigns c on c.id=cr.campaign_id where c.company_id=? and lower(cr.email)=? and cr.status='sent' and cr.replied_at is null and (cr.sent_at is null or datetime(cr.sent_at)<=datetime(?)) order by cr.id desc limit 1`).get(sd.company_id,from,at);
        }
        if(!rec) continue;
        const upd=db.prepare('update campaign_recipients set replied_at=coalesce(replied_at,?) where id=? and replied_at is null').run(at,rec.id);
        if(!upd.changes) continue;
        try{ db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,rec.campaign_id,rec.id,'reply',null,'outlook'); }catch{}
        console.log(`outlook reply detected: cr=${rec.id} from=${from} subject="${subj.slice(0,60)}"`);
      }
    }
  }catch(e){ console.error('outlook reply scan failed:',e.message); }
}
if (!IS_TEST) {
  setInterval(()=>{ scanOutlookReplies().catch(()=>{}); },5*60*1000);
}
app.post('/api/track/scan',auth('super'),async(q,s)=>{ await scanOutlookReplies(); s.json({ok:1}); });

app.use((req,res)=>{ if(req.path.startsWith('/api')) return res.status(404).json({error:'Not found'}); if(fs.existsSync(path.join(FRONTEND_DIR,'index.html'))) return res.sendFile(path.join(FRONTEND_DIR,'index.html')); res.status(404).json({error:'Frontend not found'}); });
module.exports={app,db,dashboardStats};
if(require.main===module){ app.listen(PORT,()=>console.log(`Backend running at http://localhost:${PORT}`)); }
