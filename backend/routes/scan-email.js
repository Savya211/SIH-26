/**
 * routes/scan-email.js
 * POST /api/scan-email
 * Receives links and image URLs extracted from a Gmail email body
 * and returns per-URL threat verdicts.
 *
 * ZPhisher awareness:
 *  - Raw IP addresses as hosts (e.g. http://192.168.1.x/login)
 *  - ngrok / serveo tunnels used to expose ZPhisher pages
 *  - Port-based URLs (e.g. http://host:8080/gmail-login)
 *  - HTTP (non-TLS) fake login pages cloning Google/Facebook/etc.
 *  - Paths mimicking legit sites: /gmail/login, /account/verify, /secure/update
 */

import { isInThreatList } from '../services/threat-lists.js';
import { heuristicScore } from '../services/scorer.js';

// Known tunnel/phishing infrastructure used by ZPhisher and similar
const PHISHING_TUNNEL_PATTERNS = [
    /\.ngrok\.io$/,
    /\.ngrok-free\.app$/,
    /\.serveo\.net$/,
    /\.loclx\.io$/,
    /\.trycloudflare\.com$/,
    /\.localxpose\.io$/,
    /\.bohr\.io$/,
];

// Phishing URL path patterns (ZPhisher clones typically use these)
const PHISHING_PATH_PATTERNS = [
    /\/(gmail|google|facebook|fb|instagram|ig|twitter|paypal|apple|microsoft|amazon|netflix|bank|secure|account|login|signin|verify|update|confirm|validate|recovery|password|credential)(\/|$|-|\?)/i,
];

// Raw IPv4 pattern
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

// Allowlist of safe image domains for email (not scanned for phishing)
const SAFE_IMAGE_DOMAINS = [
    'googleusercontent.com', 'googleapis.com', 'gstatic.com',
    'gmail.com', 'google.com',
    'gravatar.com', 'cloudfront.net', 'amazonaws.com',
    'cdn.jsdelivr.net', 'unpkg.com',
];

/**
 * Scores a single URL for phishing risk.
 * Returns { url, score, verdict, reasons, source }
 */
function scoreEmailUrl(rawUrl) {
    const result = {
        url: rawUrl,
        score: 100,
        verdict: 'safe',
        reasons: [],
        source: 'heuristic'
    };

    let parsedUrl;
    try {
        parsedUrl = new URL(rawUrl);
    } catch {
        // Can't parse — treat as suspicious
        result.score = 40;
        result.verdict = 'suspicious';
        result.reasons.push('Malformed or unparseable URL');
        return result;
    }

    const { hostname, protocol, port, pathname } = parsedUrl;

    // 1. Layer 1 — community threat list
    if (isInThreatList(rawUrl)) {
        result.score = 0;
        result.verdict = 'dangerous';
        result.reasons.push('URL found in community malware/phishing threat database');
        result.source = 'threat-list';
        return result;
    }

    // 2. HTTP (no TLS) — heavy penalty in email context
    if (protocol === 'http:') {
        result.score -= 30;
        result.reasons.push('Link uses insecure HTTP (no encryption)');
    }

    // 3. Raw IP address host — major ZPhisher signal
    if (IPV4_REGEX.test(hostname)) {
        result.score -= 50;
        result.reasons.push(`Raw IP address used as host (${hostname}) — typical ZPhisher pattern`);
    }

    // 4. Known tunnel domains (ngrok, serveo, etc.) — ZPhisher exposes pages via these
    for (const pattern of PHISHING_TUNNEL_PATTERNS) {
        if (pattern.test(hostname)) {
            result.score -= 55;
            result.reasons.push(`Tunnel domain detected (${hostname}) — commonly used by phishing kits`);
            break;
        }
    }

    // 5. Non-standard ports (ZPhisher often serves on 8080, 5000, etc.)
    if (port && !['80', '443', ''].includes(port)) {
        result.score -= 20;
        result.reasons.push(`Non-standard port (${port}) — suspicious in email links`);
    }

    // 6. Phishing path patterns (clone login pages)
    for (const pattern of PHISHING_PATH_PATTERNS) {
        if (pattern.test(pathname)) {
            result.score -= 25;
            result.reasons.push('URL path resembles a credential-harvesting login page clone');
            break;
        }
    }

    // 7. Run standard heuristic scorer (covers TLDs, keywords, etc.)
    try {
        const heuristic = heuristicScore({
            url: rawUrl,
            isHTTPS: protocol === 'https:',
            passwordFields: 0,   // we don't have page DOM here
            creditCardFields: 0,
            hiddenIframes: 0,
            externalScripts: 0,
            suspiciousKeywords: [],
            autoDownloads: 0,
            redirectCount: 0,
        });
        // Blend: take the worse score
        if (heuristic.score < result.score) {
            result.score = heuristic.score;
            result.reasons.push(...heuristic.reasons.filter(r => !result.reasons.includes(r)));
        }
    } catch { /* scorer unavailable */ }

    // Clamp
    result.score = Math.max(0, Math.min(100, result.score));

    // Verdict thresholds
    if (result.score < 30) result.verdict = 'dangerous';
    else if (result.score < 60) result.verdict = 'suspicious';
    else result.verdict = 'safe';

    return result;
}

export default function scanEmailRoute(app) {
    /**
     * POST /api/scan-email
     * Body: { links: string[], images: string[] }
     * Response: { results: Array<{ url, score, verdict, reasons, source }> }
     */
    app.post('/api/scan-email', async (req, res) => {
        const { links = [], images = [] } = req.body;

        if (!Array.isArray(links) && !Array.isArray(images)) {
            return res.status(400).json({ error: 'links or images array required' });
        }

        const allUrls = [
            ...links.map(u => ({ url: u, type: 'link' })),
            ...images
                .filter(u => !SAFE_IMAGE_DOMAINS.some(d => u.includes(d)))
                .map(u => ({ url: u, type: 'image' }))
        ];

        console.log(`[ScanEmail] Scanning ${links.length} links + ${images.length} images`);

        const results = allUrls.map(({ url, type }) => ({
            ...scoreEmailUrl(url),
            urlType: type
        }));

        const dangerous = results.filter(r => r.verdict === 'dangerous').length;
        const suspicious = results.filter(r => r.verdict === 'suspicious').length;

        console.log(`[ScanEmail] Results: ${dangerous} dangerous, ${suspicious} suspicious, ${results.length - dangerous - suspicious} safe`);

        return res.json({
            results,
            summary: { total: results.length, dangerous, suspicious, safe: results.length - dangerous - suspicious }
        });
    });
}
