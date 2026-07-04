# Security Audit Report

This report consolidates the security vulnerabilities and dependency issues identified and verified in the codebase. 

---

## 1. Verified Source Code Vulnerabilities

### [HIGH] SQL Injection via URL Query Parameter in User Search
* **Vulnerability Type:** SQL Injection (CWE-89)
* **Location:** [app.js:L18-29](file:///Users/ganesh/dev/razorpay_assignment/sample_target/app.js#L18-L29)
* **Status:** VERIFIED

#### Description
The root cause of this vulnerability is the direct concatenation of user-supplied data (`req.query.username`) into an SQL query string on line 20: 
```javascript
`SELECT id, username, role FROM users WHERE username = '${username}'`
```
Because this string is executed directly by SQLite via `db.all` on line 22 without sanitization or parameterized inputs, an attacker can input crafted SQL syntax to manipulate the query, potentially bypassing authentication, retrieving unauthorized data, or modifying the database contents.

#### Proof of Concept (PoC)
The vulnerability was successfully verified using the following supertest code:

```javascript
const request = require('supertest');
const app = require('./app');

describe('SQL Injection in /api/users/search', () => {
  test('should verify SQL Injection vulnerability via response', async () => {
    // A regular query returns guest with role user
    const normalRes = await request(app).get("/api/users/search?username=guest");
    expect(normalRes.status).toBe(200);
    expect(normalRes.body).toBeInstanceOf(Array);
    
    // Inject SQL payload targeting sqlite: guest' OR '1'='1
    const sqlInjectionRes = await request(app).get("/api/users/search?username=guest'+OR+'1'='1");
    expect(sqlInjectionRes.status).toBe(200);
    expect(sqlInjectionRes.body).toBeInstanceOf(Array);
    
    // The query becomes: SELECT id, username, role FROM users WHERE username = 'guest' OR '1'='1'
    // Since '1'='1' is always true, it must return all users (admin & guest), including roles.
    const users = sqlInjectionRes.body;
    expect(users.length).toBeGreaterThan(1);
    
    // Ensure both guest and admin are returned in the response
    const usernames = users.map(u => u.username);
    expect(usernames).toContain('admin');
    expect(usernames).toContain('guest');
  });
});
```

#### Remediation
To mitigate SQL injection, rewrite the database query to use parameterized inputs (prepared statements) instead of string concatenation:
```javascript
// Recommended safe implementation
const query = 'SELECT id, username, role FROM users WHERE username = ?';
db.all(query, [username], (err, rows) => { ... });
```

---

## 2. Dependency Vulnerabilities

An audit of the dependencies in [/Users/ganesh/dev/razorpay_assignment/sample_target](file:///Users/ganesh/dev/razorpay_assignment/sample_target) has been conducted using Trivy. 

### Vulnerability Findings

| Dependency Block File | Package | Installed Version | Fixed Version | Severity | Vulnerability ID | Description |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [package.json](file:///Users/ganesh/dev/razorpay_assignment/sample_target/package.json) | `express` | `4.18.2` | `4.18.3` | **HIGH** | [CVE-2022-29217](https://nvd.nist.gov/vuln/detail/CVE-2022-29217) | Express.js potential prototype pollution |

### Recommendation
> [!IMPORTANT]
> To resolve this security issue, it is highly recommended to upgrade `express` to version **4.18.3** or higher in [package.json](file:///Users/ganesh/dev/razorpay_assignment/sample_target/package.json).