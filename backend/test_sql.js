const Db = require('better-sqlite3');
const db = new Db(':memory:');
db.exec(`create table users(id integer primary key, company_id int, role text, email text);
create table companies(id integer primary key, name text);
create table user_companies(id integer primary key, user_id int, company_id int);
insert into users(id,company_id,role,email) values(1,null,'super','a@b.com');
insert into companies(id,name) values(1,'GreekLanka');
insert into user_companies(user_id,company_id) values(1,1);`);

try {
  const r = db.prepare('select u.id,u.role,u.email,u.company_id,group_concat(c.name, ", ") as companies from users u left join user_companies uc on uc.user_id=u.id left join companies c on c.id=uc.company_id group by u.id order by u.role,u.email').all();
  console.log('OK:', JSON.stringify(r));
} catch (e) {
  console.log('ERR1:', e.message);
}

try {
  const r = db.prepare("select u.id,u.role,u.email,u.company_id,group_concat(c.name, ', ') as companies from users u left join user_companies uc on uc.user_id=u.id left join companies c on c.id=uc.company_id group by u.id order by u.role,u.email").all();
  console.log('OK2:', JSON.stringify(r));
} catch (e) {
  console.log('ERR2:', e.message);
}