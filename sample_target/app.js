const express = require('express');
const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded Secret / API Key (Vulnerability: CWE-798)
const STRIPE_SECRET_KEY = "sk_test_51Nz1234567890abcdefghijklmnopqrstuvwxyz";

// Basic landing route
app.get('/', (req, res) => {
  res.send('<h1>Vulnerable Sample Target Application</h1><p>Running for security analysis testing.</p>');
});

// SQL Injection (Vulnerability: CWE-89)
// Directly concatenates user input into the SQL query string
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.get(query, (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }
    if (row) {
      res.json({ success: true, user: { username: row.username, role: row.role } });
    } else {
      res.status(401).json({ success: false, message: "Invalid credentials", query });
    }
  });
});

// Command Injection (Vulnerability: CWE-78)
// Executes an arbitrary shell command constructed with user inputs
app.get('/api/ping', (req, res) => {
  const { host } = req.query;
  if (!host) {
    return res.status(400).json({ error: "Missing 'host' query parameter" });
  }

  // Construct a shell command unsafely using dynamic parameter concatenation
  const cmd = `ping -c 2 ${host}`;
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      return res.status(500).json({ error: err.message, stdout, stderr });
    }
    res.json({ output: stdout });
  });
});

// Path Traversal / LFI (Vulnerability: CWE-22)
// Accesses files directly using user-supplied path components without sanitization
app.get('/api/download', (req, res) => {
  const { file } = req.query;
  if (!file) {
    return res.status(400).json({ error: "Missing 'file' parameter" });
  }

  // Unsafely resolves target file path, enabling directory traversal (e.g. file=../../etc/passwd or ../package.json)
  const targetPath = path.join(__dirname, 'public', file);
  
  fs.readFile(targetPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).json({ error: `File not found: ${err.message}`, path: targetPath });
    }
    res.send(data);
  });
});

// Insecure Direct Object Reference (IDOR) (Vulnerability: CWE-639)
// Directly queries order data by ID without checking ownership or session authentication
app.get('/api/orders/:id', (req, res) => {
  const orderId = req.params.id;
  const query = `SELECT * FROM orders WHERE id = ?`;

  db.get(query, [orderId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!row) {
      return res.status(404).json({ error: "Order not found" });
    }
    // Vulnerability: No ownership check. Any user can query any order.
    res.json(row);
  });
});

app.listen(PORT, () => {
  console.log(`Vulnerable app listening on port ${PORT}`);
});
