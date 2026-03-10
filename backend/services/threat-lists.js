/**
 * services/threat-lists.js
 * Loads and caches community threat lists from URLhaus and OpenPhish
 */

let cachedThreats = new Set();
let lastFetchTime = 0;
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

export async function loadThreatLists() {
    const now = Date.now();
    if (now - lastFetchTime < CACHE_DURATION && cachedThreats.size > 0) {
        return; // Use cache
    }

    console.log('[ThreatLists] Fetching community threat feeds...');

    try {
        // URLhaus - Known malware distribution URLs
        const urlhausRes = await fetch('https://urlhaus.abuse.ch/downloads/text_online/', {
            signal: AbortSignal.timeout(10000)
        });
        if (urlhausRes.ok) {
            const text = await urlhausRes.text();
            const lines = text.split('\n').filter(l => l && !l.startsWith('#'));
            lines.forEach(url => {
                try {
                    const hostname = new URL(url.trim()).hostname;
                    cachedThreats.add(hostname);
                } catch (e) { }
            });
            console.log(`[ThreatLists] Loaded ${lines.length} entries from URLhaus`);
        }
    } catch (e) {
        console.warn('[ThreatLists] Failed to fetch URLhaus:', e.message);
    }

    try {
        // OpenPhish - Known phishing URLs
        const openphishRes = await fetch('https://openphish.com/feed.txt', {
            signal: AbortSignal.timeout(10000)
        });
        if (openphishRes.ok) {
            const text = await openphishRes.text();
            const lines = text.split('\n').filter(l => l.trim());
            lines.forEach(url => {
                try {
                    const hostname = new URL(url.trim()).hostname;
                    cachedThreats.add(hostname);
                } catch (e) { }
            });
            console.log(`[ThreatLists] Loaded ${lines.length} entries from OpenPhish`);
        }
    } catch (e) {
        console.warn('[ThreatLists] Failed to fetch OpenPhish:', e.message);
    }

    lastFetchTime = now;
    console.log(`[ThreatLists] Total unique threat domains cached: ${cachedThreats.size}`);
}

export function isInThreatList(urlStr) {
    try {
        const hostname = new URL(urlStr).hostname.replace('www.', '');
        return cachedThreats.has(hostname);
    } catch (e) {
        return false;
    }
}

export function getThreatListSize() {
    return cachedThreats.size;
}
