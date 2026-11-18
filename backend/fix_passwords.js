const Database = require('better-sqlite3-multiple-ciphers');
const bcrypt = require('bcryptjs');
const db = new Database('./data.db');

const users = db.prepare("select id, email from users where role != 'super'").all();
users.forEach(u => {
  const hash = bcrypt.hashSync('admin123', 12);
  db.prepare('UPDATE users SET hash = ? WHERE id = ?').run(hash, u.id);
  console.log('Updated password for:', u.email);
});