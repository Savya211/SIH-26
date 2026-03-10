/**
 * content/homoglyph-detector.js
 * Scans the current document domain for IDN/homoglyph attacks (lookalike characters).
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
    'google.com', 'paypal.com', 'apple.com', 'microsoft.com',
    'amazon.com', 'facebook.com', 'twitter.com', 'netflix.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'github.com'
];

function isLookalike(hostname) {
    const withoutSub = hostname.split('.').slice(-2).join('.'); // e.g., 'g00gle.com'
    if (POPULAR_DOMAINS.includes(withoutSub)) return false; // Allowed

    for (const popDomain of POPULAR_DOMAINS) {
        // Compare string distances or regular expression mappings
        // Basic heuristic: check substituting chars
        const popBase = popDomain.split('.')[0];
        const subBase = withoutSub.split('.')[0];

        if (popBase === subBase) continue;
        if (Math.abs(popBase.length - subBase.length) > 1) continue;

        // Count character differences mapped
        let lookalikeScore = 0;
        let pIndex = 0;
        let sIndex = 0;

        // Basic character substitution check
        // e.g. p->p, a->a, y->y, p->p, a->a, 1->l
        let substituted = subBase;
        for (const [susChar, validChars] of Object.entries(SUSPICIOUS_CHAR_MAPPINGS)) {
            validChars.forEach(valid => {
                // Replace sus chars with valid ones recursively and check
                substituted = substituted.split(susChar).join(valid);
            });
        }

        if (substituted === popBase) {
            return { target: popDomain, lookalike: withoutSub };
        }
    }

    return false;
}

// Perform check on page load
setTimeout(() => {
    chrome.storage.local.get(['settings'], (result) => {
        if (result.settings && result.settings.enablePhishingCheck === false) return;

        const lookalikeResult = isLookalike(window.location.hostname);
        if (lookalikeResult) {
            chrome.runtime.sendMessage({
                type: 'THREAT_DETECTED',
                threatType: 'HOMOGLYPH_DOMAIN',
                details: lookalikeResult
            });
        }
    });
}, 1000);
