// tests/hibp.test.js
// using node crypto to simulate browser API for tests

const crypto = require('crypto');

async function hashSHA1(text) {
    // Node.js implementation of the browser crypto logic
    const hash = crypto.createHash('sha1');
    hash.update(text);
    return hash.digest('hex').toUpperCase();
}

describe('HIBP Local Hashing (k-Anonymity)', () => {
    test('Should generate correct SHA-1 hash length', async () => {
        const hash = await hashSHA1('password123');
        expect(hash).toHaveLength(40);
    });

    test('Should consistently hash the same password', async () => {
        const hash1 = await hashSHA1('securePassword!');
        const hash2 = await hashSHA1('securePassword!');
        expect(hash1).toBe(hash2);
    });

    test('Prefix and suffix should be split correctly for k-Anonymity', async () => {
        const hash = await hashSHA1('test');
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        expect(prefix).toHaveLength(5);
        expect(suffix).toHaveLength(35);
        expect(prefix + suffix).toBe(hash);
    });
});
