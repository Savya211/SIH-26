/**
 * routes/check-urls.js
 * Batch URL safety check - fast threat-list + TLD lookup only (no AI).
 * Used by the search-scanner content script to annotate search results.
 */

import { isInThreatList } from '../services/threat-lists.js';

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.club', '.gq', '.ml', '.tk', '.cf', '.ga', '.work', '.click', '.loan', '.download'];

const DANGEROUS_DOMAINS = [
    'oceanofgames.com', 'oceanofgames.net',
    'igg-games.com', 'steamunlocked.net', 'skidrowreloaded.com',
    'fitgirl-repacks.site', 'getintopc.com',
    'filecr.com', 'crackingcity.com',
    'grabify.link', 'iplogger.org', 'bit-url.com',
    'softonic.com', 'download.cnet.com', 'freewarefiles.com',
    'bitcoinprofit.com', 'cryptoboom.com',
    'cleanmypc-now.com', 'fix-your-pc.com',
    'rewardsurvey.com', 'prizesurvey.com',
];

function checkSingleUrl(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase().replace('www.', '');

        // Layer 1: Community threat lists (URLhaus + OpenPhish)
        if (isInThreatList(url)) {
            return { verdict: 'dangerous', reason: 'Found in community threat database (URLhaus/OpenPhish)' };
        }

        // Layer 2: Local dangerous domains
        if (DANGEROUS_DOMAINS.includes(hostname) || DANGEROUS_DOMAINS.some(d => hostname.endsWith('.' + d))) {
            return { verdict: 'dangerous', reason: 'Known dangerous domain' };
        }

        // Layer 3: Suspicious TLD
        for (const tld of SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                return { verdict: 'suspicious', reason: `Suspicious top-level domain (${tld})` };
            }
        }

        // Layer 4: IP address as domain
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
            return { verdict: 'suspicious', reason: 'IP address used instead of domain name' };
        }

        // Layer 5: No HTTPS
        if (parsed.protocol === 'http:') {
            return { verdict: 'suspicious', reason: 'No HTTPS encryption' };
        }

        return { verdict: 'safe', reason: null };
    } catch (e) {
        return { verdict: 'safe', reason: null };
    }
}

export default function checkUrlsRoute(app) {
    app.post('/api/check-urls', (req, res) => {
        const { urls } = req.body;

        if (!Array.isArray(urls)) {
            return res.status(400).json({ error: 'urls must be an array' });
        }

        if (urls.length > 50) {
            return res.status(400).json({ error: 'Maximum 50 URLs per request' });
        }

        const results = {};
        for (const url of urls) {
            if (typeof url === 'string') {
                results[url] = checkSingleUrl(url);
            }
        }

        res.json({ results });
    });
}
