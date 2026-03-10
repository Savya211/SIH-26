/**
 * services/scorer.js
 * Heuristic scoring engine - runs BEFORE the AI, catches obvious threats fast
 */

const KNOWN_SAFE_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
    'reddit.com', 'amazon.com', 'wikipedia.org', 'microsoft.com',
    'apple.com', 'netflix.com', 'spotify.com', 'paypal.com',
    'chase.com', 'bankofamerica.com', 'wellsfargo.com',
    'yahoo.com', 'bing.com', 'duckduckgo.com', 'ecosia.org',
    'whatsapp.com', 'telegram.org', 'discord.com', 'slack.com',
    'zoom.us', 'twitch.tv', 'tiktok.com', 'pinterest.com',
    'ebay.com', 'walmart.com', 'target.com', 'bestbuy.com',
    'dropbox.com', 'notion.so', 'figma.com', 'canva.com',
    'medium.com', 'quora.com', 'tumblr.com', 'wordpress.com',
    'cloudflare.com', 'npmjs.com', 'pypi.org', 'gitlab.com', 'bitbucket.org',
];

import { SUSPICIOUS_KEYWORDS } from '../../lib/constants.js';

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.club', '.gq', '.ml', '.tk', '.cf', '.ga', '.work', '.click', '.loan', '.download', '.bid', '.racing', '.win', '.stream'];

export function heuristicScore(signals) {
    let score = 100;
    const reasons = [];

    // Known safe domains get an automatic pass
    if (isKnownDomain(signals.url)) {
        return { score: 100, verdict: 'safe', reasons: [] };
    }

    // --- Critical Exploit Detection ---
    if (signals.hasBeefHook || signals.hasBeefObject) {
        return {
            score: 0,
            verdict: 'dangerous',
            reasons: ['Browser Exploitation Framework (BeEF) payload detected on this page']
        };
    }

    // 1. SSL Check
    if (signals.isHTTPS === false) {
        score -= 10;
        reasons.push('Site uses insecure HTTP connection');
    }

    // 2. Password fields on non-known domains
    if (signals.passwordFields > 0) {
        score -= 15;
        reasons.push('Login form detected on unfamiliar domain');
    }

    // 3. Credit card fields on non-known domains
    if (signals.creditCardFields > 0) {
        score -= 25;
        reasons.push('Credit card input on unfamiliar domain');
    }

    // 4. Hidden iframes (only flag 3+, single hidden iframes are common for analytics)
    if (signals.hiddenIframes > 2) {
        score -= Math.min(signals.hiddenIframes * 5, 20);
        reasons.push(`${signals.hiddenIframes} hidden iframe(s) detected`);
    }

    // 5. Excessive external scripts (raised threshold - modern sites often have many)
    if (signals.externalScripts > 25) {
        score -= 10;
        reasons.push('Excessive external scripts loaded');
    }

    // 6. Suspicious keywords (only flag if 3+ matches to reduce false positives)
    if (signals.suspiciousKeywords && signals.suspiciousKeywords.length >= 3) {
        const deduction = Math.min(signals.suspiciousKeywords.length * 3, 15);
        score -= deduction;
        reasons.push(`Suspicious content: "${signals.suspiciousKeywords.slice(0, 3).join('", "')}"`);
    }

    // 7. Auto-downloads
    if (signals.autoDownloads > 0) {
        score -= 25;
        reasons.push('Page attempted automatic file download');
    }

    // 8. Suspicious TLD
    try {
        const hostname = new URL(signals.url).hostname;
        for (const tld of SUSPICIOUS_TLDS) {
            if (hostname.endsWith(tld)) {
                score -= 15;
                reasons.push(`Suspicious top-level domain (${tld})`);
                break;
            }
        }
    } catch (e) { }

    // 9. Redirect chains
    if (signals.redirectCount > 3) {
        score -= 15;
        reasons.push(`Excessive redirects (${signals.redirectCount})`);
    }

    // Clamp score
    score = Math.max(0, Math.min(100, score));

    let verdict = 'safe';
    if (score < 30) verdict = 'dangerous';
    else if (score < 60) verdict = 'suspicious';

    return { score, verdict, reasons };
}

function isKnownDomain(urlStr) {
    try {
        const hostname = new URL(urlStr).hostname.replace('www.', '');
        return KNOWN_SAFE_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d));
    } catch (e) {
        return false;
    }
}

export { SUSPICIOUS_KEYWORDS };
