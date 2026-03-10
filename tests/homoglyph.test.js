// tests/homoglyph.test.js

/**
 * We mock the homoglyph logic from content/homoglyph-detector.js to test pure logic
 */
const SUSPICIOUS_CHAR_MAPPINGS = {
    '1': ['l', 'i'],
    '0': ['o'],
    'q': ['g'],
    'rn': ['m'],
    'vv': ['w'],
    'cl': ['d']
};

const POPULAR_DOMAINS = [
    'google.com', 'paypal.com', 'apple.com', 'microsoft.com'
];

function isLookalike(hostname) {
    const withoutSub = hostname.split('.').slice(-2).join('.');
    if (POPULAR_DOMAINS.includes(withoutSub)) return false;

    for (const popDomain of POPULAR_DOMAINS) {
        const popBase = popDomain.split('.')[0];
        const subBase = withoutSub.split('.')[0];

        if (popBase === subBase) continue;
        if (Math.abs(popBase.length - subBase.length) > 1) continue;

        let substituted = subBase;
        for (const [susChar, validChars] of Object.entries(SUSPICIOUS_CHAR_MAPPINGS)) {
            validChars.forEach(valid => {
                substituted = substituted.split(susChar).join(valid);
            });
        }

        if (substituted === popBase) {
            return { target: popDomain, lookalike: withoutSub };
        }
    }
    return false;
}

describe('Homoglyph Detection', () => {
    test('Should allow legitimate domains', () => {
        expect(isLookalike('google.com')).toBe(false);
        expect(isLookalike('paypal.com')).toBe(false);
        expect(isLookalike('mail.google.com')).toBe(false);
    });

    test('Should detect number substitutions', () => {
        const result = isLookalike('g00gle.com');
        expect(result).toBeTruthy();
        expect(result.target).toBe('google.com');
    });

    test('Should detect multiple common substitutions', () => {
        const result = isLookalike('paypa1.com');
        expect(result).toBeTruthy();
        expect(result.target).toBe('paypal.com');

        const result2 = isLookalike('micr0s0ft.com');
        expect(result2).toBeTruthy();
        expect(result2.target).toBe('microsoft.com');
    });

    test('Should ignore unrelated domains', () => {
        expect(isLookalike('randomsite.com')).toBe(false);
        expect(isLookalike('example.org')).toBe(false);
    });
});
