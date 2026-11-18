const Database = require('better-sqlite3-multiple-ciphers');
const db = new Database('./data.db');

const users = db.prepare("select id from users where role != 'super'").all();
const companies = db.prepare('select id from companies').all();

console.log('Users:', users.map(u => u.id));
console.log('Companies:', companies.map(c => c.id));

users.forEach(u => {
  companies.forEach(c => {
    db.prepare('INSERT OR IGNORE INTO user_companies (user_id, company_id) VALUES (?, ?)').run(u.id, c.id);
  });
  db.prepare('UPDATE users SET company_id = ? WHERE id = ?').run(companies[0].id, u.id);
});

console.log('Done. Updated user_companies:');
db.prepare('select * from user_companies').all().forEach(uc => console.log(uc));