const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const port = 3000;

// Vulnerable in-memory database setup
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
  db.run("INSERT INTO users VALUES (1, 'admin', 'supersecret', 'admin')");
  db.run("INSERT INTO users VALUES (2, 'guest', 'password123', 'user')");
});

app.use(express.json());

// VULNERABILITY 1: SQL Injection
// Unsafe parameter concatenation
app.get('/api/users/search', (req, res) => {
  const username = req.query.username;
  const query = `SELECT id, username, role FROM users WHERE username = '${username}'`;
  
  db.all(query, [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(rows);
  });
});

// VULNERABILITY 2: Hardcoded API Key (GitLeaks should find this)
const STRIPE_SECRET_KEY = "STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY";

app.listen(port, () => {
  console.log(`Vulnerable sample app listening on port ${port}`);
});

module.exports = app;
