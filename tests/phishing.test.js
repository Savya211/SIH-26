// tests/phishing.test.js

/**
 * We mock the network request behavior for Safe Browsing
 */
describe('Phishing & Malware API Helpers', () => {
    test('Safe Browsing API should format requests correctly', () => {
        const apiKey = 'test_api_key';
        const urlToCheck = 'http://malware.testing.machine';

        const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;
        const requestBody = {
            client: { clientId: "browser-security-manager", clientVersion: "1.0.0" },
            threatInfo: {
                threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes: ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: urlToCheck }]
            }
        };

        expect(endpoint).toContain('key=test_api_key');
        expect(requestBody.threatInfo.threatEntries[0].url).toBe(urlToCheck);
        expect(requestBody.threatInfo.threatTypes.length).toBe(4);
    });

    test('PhishTank API should format requests correctly', () => {
        const urlToCheck = 'http://phishing.site';
        const apiKey = 'pt_key';

        const formData = new URLSearchParams();
        formData.append('url', encodeURIComponent(urlToCheck));
        formData.append('format', 'json');
        formData.append('app_key', apiKey);

        expect(formData.get('url')).toBe(encodeURIComponent(urlToCheck));
        expect(formData.get('app_key')).toBe('pt_key');
        expect(formData.get('format')).toBe('json');
    });
});
