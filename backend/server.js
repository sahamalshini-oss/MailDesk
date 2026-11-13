require('dotenv').config();
const express=require('express'),Db=require('better-sqlite3'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),nm=require('nodemailer'),sanitize=require('sanitize-html'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const ROOT=__dirname,FRONTEND_DIR=process.env.FRONTEND_DIR||path.join(ROOT,'..','frontend');
const UPLOAD_DIR=process.env.UPLOAD_DIR||path.join(ROOT,'uploads');
if(!fs.existsSync(UPLOAD_DIR))fs.mkdirSync(UPLOAD_DIR,{recursive:true});
const multer=require('multer');
const storage=multer.diskStorage({destination:(req,f,cb)=>cb(null,UPLOAD_DIR),filename:(req,f,cb)=>cb(null,Date.now()+'-'+f.originalname.replace(/\s+/g,'_'))});
const upload=multer({storage,limits:{fileSize:25*1024*1024}});
const {JWT_SECRET:JS='dev',ENC_KEY='dev-key',MS_CLIENT_ID,MS_CLIENT_SECRET,BASE_URL='http://localhost:3000',PORT=3000}=process.env;
const key=crypto.createHash('sha256').update(ENC_KEY).digest();
const enc=t=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key,iv),b=Buffer.concat([c.update(t,'utf8'),c.final()]);return [iv,c.getAuthTag(),b].map(x=>x.toString('base64')).join('.')};
const dec=s=>{const[iv,tag,b]=s.split('.').map(x=>Buffer.from(x,'base64')),d=crypto.createDecipheriv('aes-256-gcm',key,iv);d.setAuthTag(tag);return Buffer.concat([d.update(b),d.final()]).toString('utf8')};
const db=new Db(process.env.DB_PATH||path.join(ROOT,'data.db'));
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
create table if not exists email_events(id integer primary key,sent_id int,campaign_id int,campaign_recipient_id int,event_type text,event_at text default current_timestamp,ip text,user_agent text);`);
const ensureCol=(table,col,type)=>{const cols=new Set(db.pragma(`table_info(${table})`).map(c=>c.name));if(!cols.has(col))db.exec(`alter table ${table} add column ${col} ${type}`)};
ensureCol('senders','user_id','int');
for(const[column,type]of Object.entries({draft_html:'text',draft_values:'text',draft_attachments:'text',campaign_id:'int',campaign_recipient_id:'int'}))ensureCol('sent',column,type);
for(const[column,type]of Object.entries({campaign_id:'int',campaign_recipient_id:'int'}))ensureCol('email_events',column,type);
for(const[column,type]of Object.entries({recipient_company_id:'int'}))ensureCol('contacts',column,type);
for(const[column,type]of Object.entries({campaign_id:'int'}))ensureCol('attachments',column,type);
if(!db.prepare('select 1 from users').get()){
  const h=p=>bcrypt.hashSync(p,10);
  const superId=db.prepare('insert into users(company_id,role,email,hash) values(?,?,?,?)').run(null,'super','admin@maildesk.com',h('admin123')).lastInsertRowid;
  ['GreekLanka Maritime Solutions','OCEANIC SHIP CHANDLERS (PVT) LTD','Navigator Crew Managment (PVT)LTD'].forEach(n=>{
    const cid=db.prepare('insert into companies(name) values(?)').run(n).lastInsertRowid;
    db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(superId,cid);
  });
}
try{db.prepare('select id,company_id from users where company_id is not null').all().forEach(u=>db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(u.id,u.company_id))}catch{}
try{db.exec('create unique index if not exists idx_contacts_company_email on contacts(company_id,lower(email)) where email is not null');}catch{}
try{db.exec('create unique index if not exists idx_campaign_recipient_email on campaign_recipients(campaign_id,lower(email))');}catch{}

const app=express();app.use(express.json({limit:'2mb'}));app.use('/uploads',express.static(UPLOAD_DIR));if(fs.existsSync(FRONTEND_DIR))app.use(express.static(FRONTEND_DIR));
const bad=(s,m,c=400)=>s.status(c).json({error:m});
const okEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e||'').trim());
const normEmail=e=>String(e||'').trim().toLowerCase();
const canAccessCompany=(u,cid)=>{if(!cid)return false;if(u.role==='super')return !!db.prepare('select 1 from companies where id=?').get(cid);return !!db.prepare('select 1 from user_companies where user_id=? and company_id=?').get(u.id,cid)};
const resolveCid=(q)=>{const raw=q.query.company_id??q.body?.company_id??q.headers['x-company-id']; if(raw!==undefined&&raw!==null&&raw!=='')return Number(raw)||null; if(q.u.role!=='super')return q.u.company_id??(db.prepare('select company_id from user_companies where user_id=? order by company_id limit 1').get(q.u.id)?.company_id??null); return null;};
const auth=(...roles)=>(q,s,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').slice(7),JS)}catch{return s.sendStatus(401)}
 if(roles.length&&!roles.includes(q.u.role))return s.sendStatus(403);
 const cid=resolveCid(q); if(cid){ if(!canAccessCompany(q.u,cid))return bad(s,'Company access denied',403); q.cid=cid; } else { q.cid=null; }
 n()};
const requireCompany=(q,s)=>{if(!q.cid){bad(s,'Select a company');return false}return true};

app.post('/api/login',(q,s)=>{const u=db.prepare('select * from users where email=?').get(q.body.email);
 if(!u||!bcrypt.compareSync(q.body.password||'',u.hash))return bad(s,'Wrong email or password',401);
 const companies=u.role==='super'?db.prepare('select id,name from companies order by name collate nocase').all():db.prepare('select c.id,c.name from companies c join user_companies uc on uc.company_id=c.id where uc.user_id=? order by c.name collate nocase').all(u.id);
 const companyId=u.role==='super'?null:(u.company_id&&companies.find(c=>c.id===u.company_id)?u.company_id:(companies[0]?.id??null));
 const company=companies.find(c=>c.id===companyId)?.name||'';
 s.json({token:jwt.sign({id:u.id,role:u.role,company_id:companyId},JS,{expiresIn:'8h'}),role:u.role,company_id:companyId,company,companies})});

app.get('/api/me/companies',auth(),(q,s)=>{
 const rows=q.u.role==='super'?db.prepare('select id,name from companies order by name collate nocase').all():db.prepare('select c.id,c.name from companies c join user_companies uc on uc.company_id=c.id where uc.user_id=? order by c.name collate nocase').all(q.u.id);
 s.json(rows);
});

app.get('/api/companies',auth(),(q,s)=>{
 if(q.u.role==='super' || q.u.role==='admin'){
  const rows=db.prepare(`select c.id,c.name,count(distinct case when s.status='sent' then s.id end) as sent_count,count(distinct uc.user_id) as user_count from companies c left join sent s on s.company_id=c.id left join user_companies uc on uc.company_id=c.id ${q.u.role==='admin'?'where uc.user_id=?':''} group by c.id order by c.name collate nocase`).all(...(q.u.role==='admin'?[q.u.id]:[]));
  return s.json(rows);
 }
 return s.json(db.prepare('select c.id,c.name from companies c join user_companies uc on uc.company_id=c.id where uc.user_id=? order by c.name collate nocase').all(q.u.id));
});
app.post('/api/companies',auth('super','admin'),(q,s)=>{const name=String(q.body.name||'').trim();if(!name)return bad(s,'Company name is required');try{const cid=db.prepare('insert into companies(name) values(?)').run(name).lastInsertRowid; db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)').run(q.u.id,cid); s.json({id:cid})}catch(e){bad(s,'A company with that name already exists',409)}});
app.put('/api/companies/:id',auth('super','admin'),(q,s)=>{const name=String(q.body.name||'').trim(),id=Number(q.params.id);if(!name)return bad(s,'Company name is required');if(!canAccessCompany(q.u,id)&&q.u.role!=='super')return bad(s,'Company access denied',403);try{const r=db.prepare('update companies set name=? where id=?').run(name,id);if(!r.changes)return bad(s,'Company not found',404);s.json({ok:1})}catch(e){bad(s,'A company with that name already exists',409)}});
app.delete('/api/companies/:id',auth('super'),(q,s)=>{const id=Number(q.params.id);if(!db.prepare('select 1 from companies where id=?').get(id))return bad(s,'Company not found',404);db.transaction(()=>{db.prepare('delete from email_events where campaign_id in (select id from campaigns where company_id=?) or sent_id in (select id from sent where company_id=?)').run(id,id);db.prepare('delete from campaign_recipients where company_id=?').run(id);db.prepare('delete from campaigns where company_id=?').run(id);db.prepare('delete from sent where company_id=?').run(id);db.prepare('delete from contact_group_members where group_id in (select id from contact_groups where company_id=?)').run(id);db.prepare('delete from contact_groups where company_id=?').run(id);db.prepare('delete from contacts where company_id=?').run(id);db.prepare('delete from recipient_companies where company_id=?').run(id);db.prepare('delete from templates where company_id=?').run(id);db.prepare('delete from senders where company_id=?').run(id);db.prepare('delete from user_companies where company_id=?').run(id);db.prepare('delete from attachments where company_id=?').run(id);db.prepare('delete from companies where id=?').run(id)})();s.json({ok:1})});

app.get('/api/users',auth('super','admin'),(q,s)=>{
 if(q.u.role==='super'){
  const users=db.prepare("select u.id,u.role,u.email,u.company_id,group_concat(c.name, ', ') as companies from users u left join user_companies uc on uc.user_id=u.id left join companies c on c.id=uc.company_id group by u.id order by u.role,u.email").all();
  return s.json(users.map(u=>({...u,company_ids:db.prepare('select company_id from user_companies where user_id=?').all(u.id).map(x=>x.company_id)})));
 }
 if(!requireCompany(q,s))return;
 s.json(db.prepare('select u.id,u.role,u.email from users u join user_companies uc on uc.user_id=u.id where uc.company_id=? order by u.email').all(q.cid));
});
app.post('/api/users',auth('super','admin'),(q,s)=>{const{email,password,role,company_ids}=q.body; if(!email||!password)return bad(s,'Email and password are required');
 const ids=q.u.role==='super'?(Array.isArray(company_ids)?company_ids.map(Number).filter(Boolean):[]):(q.cid?[q.cid]:[]);
 if(!ids.length)return bad(s,'At least one company is required');
 try{db.transaction(()=>{const uid=db.prepare('insert into users(company_id,role,email,hash) values(?,?,?,?)').run(ids[0],role==='admin'?'admin':'user',email,bcrypt.hashSync(password,10)).lastInsertRowid; const ins=db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)'); ids.forEach(cid=>ins.run(uid,cid));})(); s.json({ok:1})}catch{bad(s,'That email already exists')}});
app.put('/api/users/:id/companies',auth('super','admin'),(q,s)=>{const id=Number(q.params.id), ids=q.u.role==='super'?(Array.isArray(q.body.company_ids)?q.body.company_ids.map(Number).filter(Boolean):[]):(q.cid?[q.cid]:[]); if(!ids.length)return bad(s,'At least one company is required'); const allowed=q.u.role==='super'?ids:ids.filter(cid=>cid===q.cid); if(!allowed.length)return bad(s,'Company access denied',403); db.transaction(()=>{const del=db.prepare('delete from user_companies where user_id=? and company_id=?'); const ins=db.prepare('insert or ignore into user_companies(user_id,company_id) values(?,?)'); allowed.forEach(cid=>ins.run(id,cid)); const first=db.prepare('select company_id from user_companies where user_id=? order by company_id limit 1').get(id)?.company_id??null; db.prepare('update users set company_id=? where id=?').run(first,id);})(); s.json({ok:1})});
// senders/mailboxes (company context required)
app.get('/api/senders',auth(),(q,s)=>{ if(!requireCompany(q,s))return;
  const rows=q.u.role==='user'
   ?db.prepare('select id,provider,from_name,from_email,status,is_default,case when user_id=? then 1 else 0 end as is_personal from senders where company_id=? and (user_id is null or user_id=?) order by is_default desc,id desc').all(q.u.id,q.cid,q.u.id)
   :db.prepare('select id,provider,from_name,from_email,status,is_default,0 as is_personal from senders where company_id=? and user_id is null order by is_default desc,id desc').all(q.cid);
  s.json(rows);
});
app.post('/api/senders/smtp',auth('super','admin','user'),async(q,s)=>{ if(!requireCompany(q,s))return; const b=q.body||{};
 try{await nm.createTransport({host:b.host,port:+b.port,secure:+b.port===465,auth:{user:b.user,pass:b.pass}}).verify()}catch(e){return bad(s,'SMTP test failed: '+e.message)}
 const owner=q.u.role==='user'?q.u.id:null,hasSender=db.prepare('select 1 from senders where company_id=? and user_id is ?').get(q.cid,owner);
 db.prepare('insert into senders(company_id,user_id,provider,from_name,from_email,secret,smtp_host,smtp_port,smtp_user,is_default,status) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,owner,'smtp',b.name||'',b.email||'',enc(b.pass||''),b.host||'',+b.port||587,b.user||'',hasSender?0:1,'active'); s.json({ok:1})});
app.post('/api/senders/:id/default',auth('super','admin','user'),(q,s)=>{ if(!requireCompany(q,s))return; const owner=q.u.role==='user'?q.u.id:null,id=Number(q.params.id);
 const tx=db.transaction(()=>{ db.prepare('update senders set is_default=0 where company_id=? and user_id is ?').run(q.cid,owner); const r=db.prepare('update senders set is_default=1 where id=? and company_id=? and user_id is ?').run(id,q.cid,owner); if(!r.changes) throw Object.assign(Error('Sender not found'),{status:404}); }); try{tx();s.json({ok:1})}catch(e){bad(s,e.message,e.status||400)}});
app.delete('/api/senders/:id',auth('super','admin','user'),(q,s)=>{ if(!requireCompany(q,s))return; const owner=q.u.role==='user'?q.u.id:null,r=db.prepare('delete from senders where id=? and company_id=? and user_id is ?').run(Number(q.params.id),q.cid,owner); if(!r.changes)return bad(s,'Sender not found',404); s.json({ok:1})});

// outlook
const MS='https://login.microsoftonline.com/7b0f59c2-d0d1-4db5-8f82-a0dc5c9e8ee0/oauth2/v2.0/',SC='offline_access Mail.Send User.Read',RED=()=>BASE_URL+'/api/oauth/outlook/callback';const tok=async p=>{const r=await fetch(MS+'token',{method:'POST',body:new URLSearchParams({client_id:MS_CLIENT_ID,client_secret:MS_CLIENT_SECRET,scope:SC,...p})}),j=await r.json();if(!r.ok)throw Error(j.error_description||j.error);return j};
app.post('/api/senders/outlook/start',auth('super','admin','user'),(q,s)=>{ if(!requireCompany(q,s))return; if(!MS_CLIENT_ID||!MS_CLIENT_SECRET)return bad(s,'Outlook is not configured');
 s.json({url:MS+'authorize?'+new URLSearchParams({client_id:MS_CLIENT_ID,response_type:'code',redirect_uri:RED(),scope:SC,prompt:'select_account',state:jwt.sign({c:q.cid,uid:q.u.role==='user'?q.u.id:null},JS,{expiresIn:'10m'})})})});
app.get('/api/oauth/outlook/callback',async(q,s)=>{try{const{c,uid=null}=jwt.verify(String(q.query.state||''),JS),t=await tok({grant_type:'authorization_code',code:String(q.query.code||''),redirect_uri:RED()});
 const me=await(await fetch('https://graph.microsoft.com/v1.0/me',{headers:{Authorization:'Bearer '+t.access_token}})).json();
 const owner=uid||null,hasSender=db.prepare('select 1 from senders where company_id=? and user_id is ?').get(c,owner);
 db.prepare('insert into senders(company_id,user_id,provider,from_name,from_email,secret,is_default,status) values(?,?,?,?,?,?,?,?)').run(c,owner,'outlook',me.displayName||'',me.mail||me.userPrincipalName||'',enc(t.refresh_token||''),hasSender?0:1,'active'); s.redirect('/#snd')}catch(e){s.status(400).send('Outlook connect failed: '+e.message)}});

// templates
const keys=t=>[...new Set([...String(t||'').matchAll(/{{\s*(\w+)\s*}}/g)].map(m=>m[1]))];
app.get('/api/templates',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from templates where company_id=? order by id desc').all(q.cid).map(t=>({...t,fields:JSON.parse(t.fields||'[]')})))} );
app.post('/api/templates',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const{name,subject='',html,fields}=q.body||{}; if(!name||!html)return bad(s,'Name and HTML are required');
 const clean=sanitize(String(html),{allowedTags:sanitize.defaults.allowedTags.concat('img'),allowedAttributes:{'*':['style','class'],a:['href','target','rel'],img:['src','alt','width','height']}});
 db.prepare('insert into templates(company_id,name,subject,html,fields) values(?,?,?,?,?)').run(q.cid,String(name).trim(),String(subject||''),clean,JSON.stringify(fields||keys(subject+clean).map(k=>({key:k,label:k,type:'text'})))); s.json({ok:1})});
app.put('/api/templates/:id',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const{name,subject='',html,fields}=q.body||{},id=Number(q.params.id); if(!name||!html)return bad(s,'Name and HTML are required');
 const clean=sanitize(String(html),{allowedTags:sanitize.defaults.allowedTags.concat('img'),allowedAttributes:{'*':['style','class'],a:['href','target','rel'],img:['src','alt','width','height']}});
 const r=db.prepare('update templates set name=?,subject=?,html=?,fields=? where id=? and company_id=?').run(String(name).trim(),String(subject||''),clean,JSON.stringify(fields||keys(subject+clean).map(k=>({key:k,label:k,type:'text'}))),id,q.cid); if(!r.changes)return bad(s,'Template not found',404); s.json({ok:1})});
app.delete('/api/templates/:id',auth('super','admin'),(q,s)=>{ if(!requireCompany(q,s))return; const r=db.prepare('delete from templates where id=? and company_id=?').run(Number(q.params.id),q.cid); if(!r.changes)return bad(s,'Template not found',404); s.json({ok:1})});
// recipient companies (parent records) & contacts
app.get('/api/recipient-companies',auth(),(q,s)=>{ if(!requireCompany(q,s))return;
  const rows=db.prepare('select rc.*, count(c.id) as contact_count from recipient_companies rc left join contacts c on c.recipient_company_id=rc.id and c.company_id=rc.company_id where rc.company_id=? group by rc.id order by lower(rc.name)').all(q.cid);
  s.json(rows.map(r=>({...r,contacts:db.prepare('select * from contacts where company_id=? and recipient_company_id=? order by lower(coalesce(nullif(name,\'\'),email))').all(q.cid,r.id)})));
});
app.post('/api/recipient-companies',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const name=String(q.body?.name||'').trim(); if(!name)return bad(s,'Company name is required'); try{const id=db.prepare('insert into recipient_companies(company_id,name) values(?,?)').run(q.cid,name).lastInsertRowid; s.json({ok:1,id})}catch{return bad(s,'Recipient company already exists')}});
app.put('/api/recipient-companies/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const name=String(q.body?.name||'').trim(),id=Number(q.params.id); if(!name)return bad(s,'Company name is required'); const r=db.prepare('update recipient_companies set name=? where id=? and company_id=?').run(name,id,q.cid); if(!r.changes)return bad(s,'Recipient company not found',404); s.json({ok:1})});
app.delete('/api/recipient-companies/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id); db.transaction(()=>{ db.prepare('update contacts set recipient_company_id=null where recipient_company_id=? and company_id=?').run(id,q.cid); const r=db.prepare('delete from recipient_companies where id=? and company_id=?').run(id,q.cid); if(!r.changes) throw Object.assign(Error('Recipient company not found'),{status:404}); })(); s.json({ok:1})});

app.get('/api/contacts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare(`select c.*, rc.name as recipient_company_name from contacts c left join recipient_companies rc on rc.id=c.recipient_company_id and rc.company_id=c.company_id where c.company_id=? order by lower(coalesce(nullif(c.name,''),c.email))`).all(q.cid))});
app.post('/api/contacts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; let {email,name,category,status,recipient_company_id}=q.body||{}; email=normEmail(email); if(!okEmail(email))return bad(s,'Valid email is required');
 if(recipient_company_id){ const rc=db.prepare('select id from recipient_companies where id=? and company_id=?').get(Number(recipient_company_id),q.cid); if(!rc)return bad(s,'Recipient company not found',404); recipient_company_id=rc.id; } else recipient_company_id=null;
 try{const id=db.prepare('insert into contacts(company_id,recipient_company_id,email,name,category,status) values(?,?,?,?,?,?)').run(q.cid,recipient_company_id,email,String(name||'').trim(),String(category||'').trim(),status||'active').lastInsertRowid; s.json({ok:1,id})}catch(e){bad(s,'That email already exists in this company')}});
app.put('/api/contacts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id); let {email,name,category,status,recipient_company_id}=q.body||{}; email=normEmail(email); if(!okEmail(email))return bad(s,'Valid email is required');
 if(recipient_company_id){ const rc=db.prepare('select id from recipient_companies where id=? and company_id=?').get(Number(recipient_company_id),q.cid); if(!rc)return bad(s,'Recipient company not found',404); recipient_company_id=rc.id; } else recipient_company_id=null;
 try{const r=db.prepare('update contacts set recipient_company_id=?,email=?,name=?,category=?,status=? where id=? and company_id=?').run(recipient_company_id,email,String(name||'').trim(),String(category||'').trim(),status||'active',id,q.cid); if(!r.changes)return bad(s,'Contact not found',404); s.json({ok:1})}catch{return bad(s,'That email already exists in this company')}});
app.delete('/api/contacts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; db.transaction(()=>{ db.prepare('delete from contact_group_members where contact_id=? and exists(select 1 from contacts c where c.id=? and c.company_id=?)').run(Number(q.params.id),Number(q.params.id),q.cid); const r=db.prepare('delete from contacts where id=? and company_id=?').run(Number(q.params.id),q.cid); if(!r.changes) throw Object.assign(Error('Contact not found'),{status:404}); })(); s.json({ok:1})});
app.post('/api/contacts/import',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const list=Array.isArray(q.body?.contacts)?q.body.contacts:[]; if(!list.length)return bad(s,'No contacts provided'); let inserted=0,skipped=0; const findRc=db.prepare('select id from recipient_companies where company_id=? and lower(name)=lower(?)'); const insRc=db.prepare('insert or ignore into recipient_companies(company_id,name) values(?,?)'); const ins=db.prepare('insert or ignore into contacts(company_id,recipient_company_id,email,name,category,status) values(?,?,?,?,?,?)');
 db.transaction(()=>{ for(const c of list){ const email=normEmail(c?.email); if(!okEmail(email)){skipped++; continue;} let rcid=null; const rcName=String(c?.recipient_company||c?.company||'').trim(); if(rcName){ insRc.run(q.cid,rcName); rcid=findRc.get(q.cid,rcName)?.id||null; } const info=ins.run(q.cid,rcid,email,String(c?.name||'').trim(),String(c?.category||'').trim(),c?.status||'active'); if(info.changes) inserted++; else skipped++; } })(); s.json({inserted,skipped})});

// groups
app.get('/api/contact-groups',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from contact_groups where company_id=? order by lower(name)').all(q.cid))});
app.post('/api/contact-groups',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const name=String(q.body?.name||'').trim(); if(!name)return bad(s,'Group name is required'); try{s.json({ok:1,id:db.prepare('insert into contact_groups(company_id,name) values(?,?)').run(q.cid,name).lastInsertRowid})}catch{return bad(s,'Group already exists')}});
app.put('/api/contact-groups/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const name=String(q.body?.name||'').trim(),id=Number(q.params.id); if(!name)return bad(s,'Group name is required'); const r=db.prepare('update contact_groups set name=? where id=? and company_id=?').run(name,id,q.cid); if(!r.changes)return bad(s,'Group not found',404); s.json({ok:1})});
app.delete('/api/contact-groups/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id); db.transaction(()=>{ db.prepare('delete from contact_group_members where group_id=? and exists(select 1 from contact_groups g where g.id=? and g.company_id=?)').run(id,id,q.cid); const r=db.prepare('delete from contact_groups where id=? and company_id=?').run(id,q.cid); if(!r.changes) throw Object.assign(Error('Group not found'),{status:404}); })(); s.json({ok:1})});
app.get('/api/contact-groups/:id/members',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id); const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); s.json(db.prepare(`select c.*, rc.name as recipient_company_name from contact_group_members m join contacts c on c.id=m.contact_id left join recipient_companies rc on rc.id=c.recipient_company_id where m.group_id=? and c.company_id=?`).all(id,q.cid))});
app.post('/api/contact-groups/:id/members',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), ids=Array.isArray(q.body?.contactIds)?q.body.contactIds.map(Number).filter(Boolean):[]; const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); const ins=db.prepare('insert or ignore into contact_group_members(group_id,contact_id) values(?,?)'); const chk=db.prepare('select id from contacts where id=? and company_id=?'); db.transaction(()=>{ ids.forEach(cid=>{ if(chk.get(cid,q.cid)) ins.run(id,cid); }); })(); s.json({ok:1})});
app.delete('/api/contact-groups/:id/members/:cid',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), cid=Number(q.params.cid); const g=db.prepare('select id from contact_groups where id=? and company_id=?').get(id,q.cid); if(!g)return bad(s,'Group not found',404); db.prepare('delete from contact_group_members where group_id=? and contact_id=?').run(id,cid); s.json({ok:1})});

// resolve recipients (deduped)
app.post('/api/contacts/resolve',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const b=q.body||{}; const emails=Array.isArray(b.emails)?b.emails:[]; const contactIds=Array.isArray(b.contactIds)?b.contactIds.map(Number).filter(Boolean):[]; const recipientCompanyIds=Array.isArray(b.recipientCompanyIds)?b.recipientCompanyIds.map(Number).filter(Boolean):[]; const groupIds=Array.isArray(b.groupIds)?b.groupIds.map(Number).filter(Boolean):[];
 const by=new Map(); const add=(email,contact_id=null,source=null)=>{ const e=normEmail(email); if(!okEmail(e))return; if(!by.has(e)) by.set(e,{email:e,contact_id,source}); };
 for(const e of emails) add(e,null,'manual');
 if(contactIds.length){ const rows=db.prepare(`select id,email from contacts where company_id=? and status='active' and id in (${contactIds.map(()=>'?').join(',')})`).all(q.cid,...contactIds); rows.forEach(r=>add(r.email,r.id,'contact')); }
 if(recipientCompanyIds.length){ const rows=db.prepare(`select id,email from contacts where company_id=? and status='active' and recipient_company_id in (${recipientCompanyIds.map(()=>'?').join(',')})`).all(q.cid,...recipientCompanyIds); rows.forEach(r=>add(r.email,r.id,'recipient_company')); }
 if(groupIds.length){ const rows=db.prepare(`select c.id,c.email from contact_group_members m join contact_groups g on g.id=m.group_id join contacts c on c.id=m.contact_id where g.company_id=? and c.company_id=? and c.status='active' and g.id in (${groupIds.map(()=>'?').join(',')})`).all(q.cid,q.cid,...groupIds); rows.forEach(r=>add(r.email,r.id,'group')); }
 const recipients=[...by.values()]; s.json({recipients,emails:recipients.map(r=>r.email),count:recipients.length});
});

// attachments
app.get('/api/attachments',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(db.prepare('select * from attachments where company_id=? order by id desc').all(q.cid))});
app.post('/api/attachments/upload',auth(),upload.array('files',10),(q,s)=>{ if(!requireCompany(q,s))return; const rows=[]; for(const f of (q.files||[])){ const id=db.prepare('insert into attachments(company_id,filename,original_name,mime_type,size,path) values(?,?,?,?,?,?)').run(q.cid,f.filename,f.originalname,f.mimetype,f.size,f.path).lastInsertRowid; rows.push({id,original_name:f.originalname,size:f.size}); } s.json({attachments:rows})});
app.delete('/api/attachments/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const a=db.prepare('select * from attachments where id=? and company_id=?').get(Number(q.params.id),q.cid); if(!a)return bad(s,'Attachment not found',404); try{fs.unlinkSync(a.path)}catch{} db.prepare('delete from attachments where id=?').run(a.id); s.json({ok:1})});
app.get('/api/attachments/:id/download',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const a=db.prepare('select * from attachments where id=? and company_id=?').get(Number(q.params.id),q.cid); if(!a)return bad(s,'Attachment not found',404); s.download(a.path,a.original_name)});
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
 if(q.u.role==='user') sd=db.prepare("select * from senders where id=? and company_id=? and status='active' and (user_id is null or user_id=?)").get(id,cid,q.u.id);
 else sd=db.prepare("select * from senders where id=? and company_id=? and status='active' and user_id is null").get(id,cid);
 if(!sd) return {error:'Sending mailbox not found or not authorized for this company',status:403};
 return {sd};
};

const getCampaign=(q,id)=>db.prepare('select * from campaigns where id=? and company_id=?').get(id,q.cid);
const resolveRecipients=(q,body)=>{ const {emails=[],contactIds=[],recipientCompanyIds=[],groupIds=[]}=body||{}; const by=new Map(); const add=(email,contact_id=null,source='manual')=>{ const e=normEmail(email); if(!okEmail(e))return; if(!by.has(e)) by.set(e,{email:e,contact_id,source}); };
 for(const e of (Array.isArray(emails)?emails:[])) add(e,null,'manual');
 const cids=[...new Set((Array.isArray(contactIds)?contactIds:[]).map(Number).filter(Boolean))];
 if(cids.length){ db.prepare(`select id,email from contacts where company_id=? and status='active' and id in (${cids.map(()=>'?').join(',')})`).all(q.cid,...cids).forEach(r=>add(r.email,r.id,'contact')); }
 const rcids=[...new Set((Array.isArray(recipientCompanyIds)?recipientCompanyIds:[]).map(Number).filter(Boolean))];
 if(rcids.length){ db.prepare(`select id,email from contacts where company_id=? and status='active' and recipient_company_id in (${rcids.map(()=>'?').join(',')})`).all(q.cid,...rcids).forEach(r=>add(r.email,r.id,'recipient_company')); }
 const gids=[...new Set((Array.isArray(groupIds)?groupIds:[]).map(Number).filter(Boolean))];
 if(gids.length){ db.prepare(`select c.id,c.email from contact_group_members m join contact_groups g on g.id=m.group_id join contacts c on c.id=m.contact_id where g.company_id=? and c.company_id=? and c.status='active' and g.id in (${gids.map(()=>'?').join(',')})`).all(q.cid,q.cid,...gids).forEach(r=>add(r.email,r.id,'group')); }
 return [...by.values()];
};

async function deliverRecipient({campaign,recipient,sd,subject,html,attachments,fromName,fromEmail}){
 let sendHtml=String(html||'').replace(/(<a[^>]*href=")([^"]*)(")/gi,(m,pre,url,post)=>{ if(url.includes('/api/track/')||url.startsWith('#')||url.startsWith('mailto:'))return m; return pre+`${BASE_URL}/api/track/click/${recipient.tracking_token}?url=${encodeURIComponent(url)}`+post; });
 sendHtml+=`<img src="${BASE_URL}/api/track/open/${recipient.tracking_token}" width="1" height="1" style="display:none" alt="" border="0">`;
 const to=[recipient.email], cc=[]; const payload={from:`"${fromName||''}" <${fromEmail}>`,to,cc,subject,html:sendHtml,replyTo:fromEmail,attachments:(attachments||[]).map(a=>({filename:a.original_name,path:a.path}))};
 let err=null, st='sent';
 try{
  if(sd.provider==='smtp'){ await nm.createTransport({host:sd.smtp_host,port:sd.smtp_port,secure:sd.smtp_port===465,auth:{user:sd.smtp_user,pass:dec(sd.secret)}}).sendMail(payload); }
  else { const t2=await tok({grant_type:'refresh_token',refresh_token:dec(sd.secret)}); if(t2.refresh_token)db.prepare('update senders set secret=?,status=? where id=?').run(enc(t2.refresh_token),'active',sd.id);
    const rr=await fetch('https://graph.microsoft.com/v1.0/me/sendMail',{method:'POST',headers:{Authorization:'Bearer '+t2.access_token,'Content-Type':'application/json'},body:JSON.stringify({message:{subject,body:{contentType:'HTML',content:sendHtml},toRecipients:to.map(a=>({emailAddress:{address:a}})),ccRecipients:[],attachments:(attachments||[]).map(a=>({'@odata.type':'#microsoft.graph.fileAttachment',name:a.original_name,contentType:a.mime_type||'application/octet-stream',contentBytes:fs.readFileSync(a.path).toString('base64')}))},saveToSentItems:true})});
    if(!rr.ok) throw Error((await rr.text()).slice(0,200)); }
 }catch(e){ st='failed'; err=String(e.message||e).slice(0,500); if(/invalid_grant|AADSTS/.test(err)){ try{db.prepare("update senders set status='needs_reconnect' where id=?").run(sd.id)}catch{} } }
 const now=new Date().toISOString();
 db.transaction(()=>{
  db.prepare('update campaign_recipients set status=?,sent_at=?,error=? where id=?').run(st,st==='sent'?now:null,err,recipient.id);
  const existing=db.prepare('select id from sent where campaign_recipient_id=?').get(recipient.id);
  if(existing) db.prepare('update sent set status=?,error=?,at=?,subject=?,sender_id=?,template_id=?,user_id=?,to_list=? where id=?').run(st,err,now,subject,campaign.sender_id,campaign.template_id||null,campaign.user_id,recipient.email,existing.id);
  else db.prepare('insert into sent(company_id,user_id,sender_id,template_id,campaign_id,campaign_recipient_id,to_list,cc_list,subject,status,error,scheduled_at,at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(campaign.company_id,campaign.user_id,campaign.sender_id,campaign.template_id||null,campaign.id,recipient.id,recipient.email,'',subject,st,err,campaign.scheduled_at||null,now);
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
 let sent=0,failed=0;
 for(const r of recipients){ const res=await deliverRecipient({campaign,recipient:r,sd,subject:campaign.subject,html:campaign.html,attachments,fromName,fromEmail}); if(res.status==='sent') sent++; else failed++; }
 const total=db.prepare('select count(*) as c from campaign_recipients where campaign_id=?').get(id).c||0;
 const failedAll=db.prepare("select count(*) as c from campaign_recipients where campaign_id=? and status='failed'").get(id).c||0;
 const status=failedAll===total&&total>0?'failed':'sent';
 db.prepare('update campaigns set status=?,sent_at=case when ?="sent" then coalesce(sent_at,current_timestamp) else sent_at end,updated_at=current_timestamp,error=? where id=?').run(status,status,failedAll?`${failedAll} recipient(s) failed`:null,id);
}

setInterval(()=>{
 try{ const due=db.prepare("select id from campaigns where status='scheduled' and scheduled_at is not null and datetime(scheduled_at)<=datetime('now') order by id limit 20").all();
  for(const c of due) processCampaign(c.id).catch(()=>{});
 }catch{}
},15000);

// campaigns
app.get('/api/campaigns',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const rows=db.prepare(`select c.*, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id) as recipient_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status='sent') as sent_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status='failed') as failed_count, (select count(*) from campaign_recipients cr where cr.campaign_id=c.id and cr.status in ('pending','queued')) as pending_count from campaigns c where c.company_id=? order by c.id desc limit 200`).all(q.cid); s.json(rows)});
app.get('/api/campaigns/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const c=getCampaign(q,Number(q.params.id)); if(!c)return bad(s,'Campaign not found',404); c.recipients=db.prepare('select * from campaign_recipients where campaign_id=? order by id').all(c.id); c.attachment_ids=db.prepare('select id,original_name,size from attachments where campaign_id=? and company_id=?').all(c.id,q.cid); s.json(c)});
app.post('/api/campaigns',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const b=q.body||{}; const isDraft=b.draft===1||b.draft===true||b.status==='draft';
 const sender_id=b.sender_id?Number(b.sender_id):null; let sd=null; if(!isDraft){ const r=getSender(q,q.cid,sender_id); if(r.error)return bad(s,r.error,r.status||400); sd=r.sd; } else if(sender_id){ const r=db.prepare('select id from senders where id=? and company_id=?').get(sender_id,q.cid); if(!r)return bad(s,'Sending mailbox not found for this company',403); }
 const recipients=resolveRecipients(q,b); if(!isDraft && !recipients.length) return bad(s,'Add at least one recipient (duplicates in this campaign are removed automatically)');
 const template_id=b.template_id?Number(b.template_id):null; if(template_id && !db.prepare('select 1 from templates where id=? and company_id=?').get(template_id,q.cid)) return bad(s,'Template not found',404);
 const send_mode=['individual','bulk'].includes(b.send_mode)?b.send_mode:'individual';
 const scheduled_at=b.scheduled_at?String(b.scheduled_at):null;
 const subject=String(b.subject||'').replace(/[\r\n]+/g,' ').trim(); const html=String(b.html||''); if(!isDraft && !subject) return bad(s,'Subject is required'); if(!isDraft && !html.trim()) return bad(s,'Email body is required');
 const status=isDraft?'draft':(scheduled_at?'scheduled':'queued');
 const name=String(b.name||subject||'Campaign').slice(0,120);
 const attachment_ids=[...new Set((Array.isArray(b.attachment_ids)?b.attachment_ids:[]).map(Number).filter(Boolean))];
 if(attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).get(q.cid,...attachment_ids).n; if(n!==attachment_ids.length) return bad(s,'Attachment not found',404); }
 const result=db.transaction(()=>{
  const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,JSON.stringify({values:b.values||{},cc:Array.isArray(b.cc)?b.cc:[],selection:b.selection||null})).lastInsertRowid;
  const ins=db.prepare('insert into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token) values(?,?,?,?,?)');
  for(const r of recipients) ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'));
  if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).run(id,q.cid,...attachment_ids);
  return {id,recipient_count:recipients.length,status};
 })();
 if(result.status==='queued'){ try{ await processCampaign(result.id); }catch(e){ db.prepare("update campaigns set status='failed',error=? where id=?").run(String(e.message||e).slice(0,300),result.id); } const c=db.prepare('select status,error from campaigns where id=?').get(result.id); result.status=c?.status||result.status; result.error=c?.error||null; }
 s.json(result);
});

app.get('/api/dashboard',auth(),(q,s)=>{ if(!requireCompany(q,s))return; s.json(dashboardStats(q.cid))});
// campaign send-now, schedule runner already set; drafts as draft campaigns
app.put('/api/campaigns/:id',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); if(c.status!=='draft' && c.status!=='scheduled') return bad(s,'Only draft or scheduled campaigns can be edited');
  const b=q.body||{}; const sender_id=b.sender_id!==undefined?(b.sender_id?Number(b.sender_id):null):c.sender_id; if(sender_id && !db.prepare('select 1 from senders where id=? and company_id=?').get(sender_id,q.cid)) return bad(s,'Sending mailbox not found for this company',403);
  const template_id=b.template_id!==undefined?(b.template_id?Number(b.template_id):null):c.template_id; if(template_id && !db.prepare('select 1 from templates where id=? and company_id=?').get(template_id,q.cid)) return bad(s,'Template not found',404);
  const recipients=b.selection?resolveRecipients(q,b.selection):null; const subject=b.subject!==undefined?String(b.subject||'').replace(/[\r\n]+/g,' ').trim():c.subject; const html=b.html!==undefined?String(b.html||''):c.html; const name=b.name!==undefined?String(b.name||subject||'Campaign').slice(0,120):c.name; const send_mode=['individual','bulk'].includes(b.send_mode)?b.send_mode:c.send_mode; const scheduled_at=b.scheduled_at!==undefined?(b.scheduled_at?String(b.scheduled_at):null):c.scheduled_at; const status=b.status==='draft'?'draft':(scheduled_at?'scheduled':(b.send_now?'queued':c.status));
  const attachment_ids=b.attachment_ids!==undefined?[...new Set((Array.isArray(b.attachment_ids)?b.attachment_ids:[]).map(Number).filter(Boolean))]:null;
  if(attachment_ids && attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).get(q.cid,...attachment_ids).n; if(n!==attachment_ids.length) return bad(s,'Attachment not found',404); }
  db.transaction(()=>{
    db.prepare('update campaigns set sender_id=?,template_id=?,name=?,subject=?,html=?,send_mode=?,status=?,scheduled_at=?,meta=?,updated_at=current_timestamp where id=? and company_id=?').run(sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,JSON.stringify({values:b.values||JSON.parse(c.meta||'{}').values||{},cc:Array.isArray(b.cc)?b.cc:JSON.parse(c.meta||'{}').cc||[],selection:b.selection||JSON.parse(c.meta||'{}').selection||null}),id,q.cid);
    if(recipients){ db.prepare('delete from campaign_recipients where campaign_id=? and status not in (\'sent\')').run(id); const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status) values(?,?,?,?,?,\'pending\')'); recipients.forEach(r=>ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'))); }
    if(attachment_ids){ db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).run(id,q.cid,...attachment_ids); }
  })();
  if(status==='queued'){ try{ await processCampaign(id); }catch(e){ db.prepare("update campaigns set status='failed',error=? where id=?").run(String(e.message||e).slice(0,300),id); } }
  const out=getCampaign(q,id); out.recipients=db.prepare('select id,email,status,error,sent_at from campaign_recipients where campaign_id=?').all(id); s.json(out);
});
app.post('/api/campaigns/:id/send',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); const sender=getSender(q,q.cid,c.sender_id); if(sender.error) return bad(s,sender.error,sender.status||400); const count=db.prepare("select count(*) as n from campaign_recipients where campaign_id=? and status in ('pending','failed')").get(id).n; if(!count) return bad(s,'No recipients to send to'); if(!c.subject||!String(c.html||'').trim()) return bad(s,'Subject and body are required'); db.prepare("update campaigns set status='queued',updated_at=current_timestamp where id=?").run(id); await processCampaign(id); s.json(db.prepare('select * from campaigns where id=?').get(id)); });
app.delete('/api/campaigns/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), c=getCampaign(q,id); if(!c) return bad(s,'Campaign not found',404); db.transaction(()=>{ db.prepare('delete from email_events where campaign_id=?').run(id); db.prepare('update attachments set campaign_id=null, sent_id=null where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from sent where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from campaign_recipients where campaign_id=?').run(id); db.prepare('delete from campaigns where id=? and company_id=?').run(id,q.cid); })(); s.json({ok:1})});

// sent/log per company (derived from campaign recipients)
app.get('/api/sent',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const rows=db.prepare(`select cr.id, cr.email as to_list, '' as cc_list, c.subject, cr.status, cr.error, coalesce(cr.sent_at,c.updated_at,c.created_at) as at, c.scheduled_at, c.id as campaign_id, c.name as campaign_name, c.send_mode, s.from_email as sender_email from campaign_recipients cr join campaigns c on c.id=cr.campaign_id left join senders s on s.id=c.sender_id where c.company_id=? and c.status!='draft' order by cr.id desc limit 200`).all(q.cid); s.json(rows)});
app.get('/api/campaigns/:id/events',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const c=getCampaign(q,Number(q.params.id)); if(!c) return bad(s,'Campaign not found',404); s.json(db.prepare(`select e.*, cr.email from email_events e left join campaign_recipients cr on cr.id=e.campaign_recipient_id where e.campaign_id=? order by e.id desc limit 500`).all(c.id))});

// tracking by recipient token (scoped to campaign/company through token)
app.get('/api/track/open/:token',(q,s)=>{const r=db.prepare('select id,campaign_id from campaign_recipients where tracking_token=?').get(String(q.params.token||'')); if(r){ try{db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,r.id,'open',q.ip,q.get('User-Agent')||'')}catch{} } s.type('image/gif'); s.send(Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7','base64'));});
app.get('/api/track/click/:token',(q,s)=>{const r=db.prepare('select id,campaign_id from campaign_recipients where tracking_token=?').get(String(q.params.token||'')); if(r){ try{db.prepare('insert into email_events(sent_id,campaign_id,campaign_recipient_id,event_type,ip,user_agent) values(?,?,?,?,?,?)').run(null,r.campaign_id,r.id,'click',q.ip,q.get('User-Agent')||'')}catch{} } const url=String(q.query.url||'/'); s.redirect(/^https?:\/\//i.test(url)?url:'/');});
app.get('/api/track/events/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id); const rows=db.prepare(`select e.*, cr.email from email_events e join campaign_recipients cr on cr.id=e.campaign_recipient_id join campaigns c on c.id=cr.campaign_id where c.company_id=? and (cr.id=? or c.id=?) order by e.id desc`).all(q.cid,id,id); s.json(rows)});

// compatibility: drafts endpoints map to draft campaigns for existing UI
app.get('/api/drafts',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const rows=db.prepare(`select c.id, c.updated_at as at, coalesce((select group_concat(email, ', ') from (select email from campaign_recipients cr where cr.campaign_id=c.id limit 20)), '') as to_list, '' as cc_list, c.subject, c.sender_id, c.template_id, c.scheduled_at, c.send_mode from campaigns c where c.company_id=? and c.status='draft' order by c.id desc`).all(q.cid); s.json(rows)});
app.get('/api/drafts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const c=getCampaign(q,Number(q.params.id)); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); const meta=JSON.parse(c.meta||'{}'); s.json({id:c.id,to_list:db.prepare("select group_concat(email, ', ') as v from campaign_recipients where campaign_id=?").get(c.id).v||'',cc_list:(meta.cc||[]).join(', '),subject:c.subject,template_id:c.template_id,sender_id:c.sender_id,scheduled_at:c.scheduled_at,draft_html:c.html,values:meta.values||{},attachment_ids:db.prepare('select id from attachments where campaign_id=? and company_id=?').all(c.id,q.cid).map(a=>a.id),attachments:db.prepare('select id,original_name,size from attachments where campaign_id=? and company_id=?').all(c.id,q.cid),send_mode:c.send_mode,selection:meta.selection||null})});
app.put('/api/drafts/:id',auth(),async(q,s)=>{ q.url; // reuse campaign update
  q.params.id=String(q.params.id); const b=q.body||{}; const body={...b,status:'draft',selection:b.selection||{emails:b.to||[],contactIds:[],recipientCompanyIds:[],groupIds:[]},subject:b.subject,html:b.html,values:b.values,attachment_ids:b.attachment_ids,scheduled_at:b.scheduled_at,send_mode:b.send_mode,template_id:b.template_id,sender_id:b.sender_id}; q.body=body; // delegate
  const id=Number(q.params.id), c=getCampaign(q,id); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); try{ // call update logic
    const selection=body.selection; const recipients=resolveRecipients(q,selection); const attachment_ids=[...new Set((Array.isArray(body.attachment_ids)?body.attachment_ids:[]).map(Number).filter(Boolean))]; if(attachment_ids.length){ const n=db.prepare(`select count(*) as n from attachments where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).get(q.cid,...attachment_ids).n; if(n!==attachment_ids.length) return bad(s,'Attachment not found',404); }
    db.transaction(()=>{ db.prepare('update campaigns set sender_id=?,template_id=?,subject=?,html=?,send_mode=?,scheduled_at=?,meta=?,updated_at=current_timestamp where id=? and company_id=?').run(body.sender_id||null,body.template_id||null,String(body.subject||'').replace(/[\r\n]+/g,' ').trim(),String(body.html||''),['individual','bulk'].includes(body.send_mode)?body.send_mode:c.send_mode,body.scheduled_at||null,JSON.stringify({values:body.values||{},cc:Array.isArray(body.cc)?body.cc:[],selection}),id,q.cid); db.prepare('delete from campaign_recipients where campaign_id=?').run(id); const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status) values(?,?,?,?,?,\'pending\')'); recipients.forEach(r=>ins.run(id,q.cid,r.contact_id||null,r.email,crypto.randomBytes(16).toString('hex'))); db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).run(id,q.cid,...attachment_ids); })(); s.json({ok:1,id}); }catch(e){bad(s,e.message||'Could not save draft')} });
app.delete('/api/drafts/:id',auth(),(q,s)=>{ if(!requireCompany(q,s))return; const id=Number(q.params.id), c=getCampaign(q,id); if(!c||c.status!=='draft') return bad(s,'Draft not found',404); db.transaction(()=>{ db.prepare('delete from campaign_recipients where campaign_id=?').run(id); db.prepare('update attachments set campaign_id=null where campaign_id=? and company_id=?').run(id,q.cid); db.prepare('delete from campaigns where id=? and company_id=?').run(id,q.cid); })(); s.json({ok:1})});

// legacy send endpoint -> create/send campaign (keeps old clients minimally working)
app.post('/api/send',auth(),async(q,s)=>{ if(!requireCompany(q,s))return; const b=q.body||{}; const isDraft=b.draft===1||b.draft===true; const selection=b.selection||{emails:Array.isArray(b.to)?b.to:String(b.to||'').split(',').map(x=>x.trim()).filter(Boolean),contactIds:Array.isArray(b.contactIds)?b.contactIds:[],recipientCompanyIds:Array.isArray(b.recipientCompanyIds)?b.recipientCompanyIds:[],groupIds:Array.isArray(b.groupIds)?b.groupIds:[]}; selection.emails=Array.isArray(selection.emails)?selection.emails:(Array.isArray(b.to)?b.to:[]); selection.contactIds=Array.isArray(selection.contactIds)?selection.contactIds.map(Number).filter(Boolean):[]; selection.recipientCompanyIds=Array.isArray(selection.recipientCompanyIds)?selection.recipientCompanyIds.map(Number).filter(Boolean):[]; selection.groupIds=Array.isArray(selection.groupIds)?selection.groupIds.map(Number).filter(Boolean):[]; const body={name:String(b.name||b.subject||'Campaign').slice(0,120),template_id:b.template_id||null,sender_id:b.sender_id||null,subject:String(b.subject||'').replace(/[\r\n]+/g,' ').trim(),html:String(b.html||b.draft_html||''),send_mode:['individual','bulk'].includes(b.send_mode)?b.send_mode:'individual',scheduled_at:b.scheduled_at||null,attachment_ids:Array.isArray(b.attachment_ids)?b.attachment_ids:[],values:b.values||{},cc:Array.isArray(b.cc)?b.cc:[],draft:isDraft,selection};
  if(isDraft){ const recipients=resolveRecipients(q,selection); const attachment_ids=[...new Set(body.attachment_ids.map(Number).filter(Boolean))]; const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,body.sender_id||null,body.template_id||null,body.name,body.subject,body.html,body.send_mode,'draft',body.scheduled_at||null,JSON.stringify({values:body.values,cc:body.cc,selection})).lastInsertRowid; const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status) values(?,?,?,?,?,\'pending\')'); recipients.forEach(x=>ins.run(id,q.cid,x.contact_id||null,x.email,crypto.randomBytes(16).toString('hex'))); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).run(id,q.cid,...attachment_ids); return s.json({status:'draft',id}); }
  if(!body.sender_id) return bad(s,'Choose a sending mailbox for this campaign'); if(!body.html.trim()||!body.subject) return bad(s,'Subject and body are required');
  const recipients=resolveRecipients(q,selection); if(!recipients.length) return bad(s,'Add at least one recipient (duplicates in this campaign are removed automatically)');
  const sender=getSender(q,q.cid,body.sender_id); if(sender.error) return bad(s,sender.error,sender.status||400);
  const attachment_ids=[...new Set(body.attachment_ids.map(Number).filter(Boolean))];
  const campaignId=db.transaction(()=>{ const id=db.prepare('insert into campaigns(company_id,user_id,sender_id,template_id,name,subject,html,send_mode,status,scheduled_at,meta) values(?,?,?,?,?,?,?,?,?,?,?)').run(q.cid,q.u.id,Number(body.sender_id),body.template_id||null,body.name,body.subject,body.html,body.send_mode,body.scheduled_at?'scheduled':'queued',body.scheduled_at||null,JSON.stringify({values:body.values,cc:body.cc,selection})).lastInsertRowid; const ins=db.prepare('insert or ignore into campaign_recipients(campaign_id,company_id,contact_id,email,tracking_token,status) values(?,?,?,?,?,\'pending\')'); recipients.forEach(x=>ins.run(id,q.cid,x.contact_id||null,x.email,crypto.randomBytes(16).toString('hex'))); if(attachment_ids.length) db.prepare(`update attachments set campaign_id=? where company_id=? and id in (${attachment_ids.map(()=>'?').join(',')})`).run(id,q.cid,...attachment_ids); return id; })();
  if(body.scheduled_at){ return s.json({status:'scheduled',id:campaignId}); }
  await processCampaign(campaignId); const c=db.prepare('select status,error from campaigns where id=?').get(campaignId); s.json({status:c?.status||'sent',id:campaignId,error:c?.error||null});
});

app.use((req,res)=>{ if(req.path.startsWith('/api')) return res.status(404).json({error:'Not found'}); if(fs.existsSync(path.join(FRONTEND_DIR,'index.html'))) return res.sendFile(path.join(FRONTEND_DIR,'index.html')); res.status(404).json({error:'Frontend not found'}); });
module.exports={app,db,dashboardStats};
if(require.main===module){ app.listen(PORT,()=>console.log(`Backend running at http://localhost:${PORT}`)); }
