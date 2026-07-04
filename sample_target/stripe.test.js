const fs = require('fs');
const path = require('path');

describe('Hardcoded Secret Verification', () => {
  it('should verify that the hardcoded STRIPE_SECRET_KEY is present in app.js', () => {
    const appPath = path.resolve(__dirname, 'app.js');
    const content = fs.readFileSync(appPath, 'utf8');

    // Verify the static placeholder or a hardcoded token is present
    expect(content).toContain('STRIPE_SECRET_KEY');
    expect(content).toContain('STRIPE_SECRET_KEY_PLACEHOLDER_NOT_A_REAL_KEY');

    // Confirm it is not using process.env for this specific variable
    const matchLine = content.split('\n').find(line => line.includes('STRIPE_SECRET_KEY'));
    expect(matchLine).not.toContain('process.env.STRIPE_SECRET_KEY');
  });
});
