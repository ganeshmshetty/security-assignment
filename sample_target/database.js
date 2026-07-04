const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
  // Create users table
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT,
      api_key TEXT
    )
  `);

  // Insert mock users (with plain text passwords for vulnerability test)
  const users = [
    ['admin', 'admin123', 'admin', 'sk_test_51Nz1234567890abcdefghijklmnopqrstuvwxyz'],
    ['user1', 'password123', 'user', 'sk_live_user1_token_12345abcde'],
    ['user2', 'user2pass', 'user', 'sk_live_user2_token_67890fghij']
  ];

  const stmt = db.prepare("INSERT INTO users (username, password, role, api_key) VALUES (?, ?, ?, ?)");
  for (const u of users) {
    stmt.run(u);
  }
  stmt.finalize();

  // Create orders table for IDOR
  db.run(`
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      product TEXT,
      price REAL,
      status TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  const orders = [
    [1, 'Premium Enterprise Security Subscription', 9999.99, 'paid'],
    [2, 'Basic Scan Credits', 49.00, 'pending'],
    [3, 'API Integration Addon', 199.00, 'paid']
  ];

  const orderStmt = db.prepare("INSERT INTO orders (user_id, product, price, status) VALUES (?, ?, ?, ?)");
  for (const o of orders) {
    orderStmt.run(o);
  }
  orderStmt.finalize();
});

module.exports = db;
