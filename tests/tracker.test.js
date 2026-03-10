// tests/tracker.test.js
const fs = require('fs');
const path = require('path');

describe('Declarative Net Request Tracker Rules', () => {
    test('tracker-rules.json should be valid JSON and contain required keys', () => {
        const rulesPath = path.join(__dirname, '../rules/tracker-rules.json');
        const rulesData = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));

        expect(Array.isArray(rulesData)).toBe(true);
        expect(rulesData.length).toBeGreaterThan(0);

        const firstRule = rulesData[0];
        expect(firstRule).toHaveProperty('id');
        expect(firstRule).toHaveProperty('priority');
        expect(firstRule).toHaveProperty('action');
        expect(firstRule).toHaveProperty('condition');
        expect(firstRule.action.type).toBe('block');
    });

    test('Rule IDs should be unique', () => {
        const rulesPath = path.join(__dirname, '../rules/tracker-rules.json');
        const rulesData = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));

        const ids = rulesData.map(r => r.id);
        const uniqueSet = new Set(ids);

        expect(ids.length).toBe(uniqueSet.size);
    });
});
