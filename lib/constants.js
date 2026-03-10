/**
 * lib/constants.js
 * Shared constants across content scripts, background worker, and backend.
 */

const DANGEROUS_DOMAINS = [
    'oceanofgames.com', 'oceanofgames.net',
    'igg-games.com', 'steamunlocked.net', 'skidrowreloaded.com',
    'fitgirl-repacks.site', 'getintopc.com',
    'filecr.com', 'crackingcity.com',
    'grabify.link', 'iplogger.org',
    'bit-url.com',
    'softonic.com', 'download.cnet.com',
    'freewarefiles.com',
    'bitcoinprofit.com', 'cryptoboom.com',
    'cleanmypc-now.com', 'fix-your-pc.com',
    'rewardsurvey.com', 'prizesurvey.com',
];

const SUSPICIOUS_KEYWORDS = [
    'verify your account', 'confirm your identity', 'update your payment',
    'you have won', 'congratulations', 'claim your prize', 'act now',
    'limited time offer', 'click here immediately', 'your account has been',
    'suspended', 'unusual activity', 'verify now', 'free iphone',
    'bitcoin generator', 'double your crypto', 'wire transfer',
    'download crack', 'free key generator', 'serial key',
    'virus detected', 'your computer is infected', 'call this number',
    'tech support', 'microsoft alert',
];

// Export for Node.js (Backend) or ES Module environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DANGEROUS_DOMAINS, SUSPICIOUS_KEYWORDS };
} else if (typeof exports !== 'undefined') {
    exports.DANGEROUS_DOMAINS = DANGEROUS_DOMAINS;
    exports.SUSPICIOUS_KEYWORDS = SUSPICIOUS_KEYWORDS;
}
