/**
 * content/search-scanner.js
 * Bitdefender TrafficLight-style search result annotations.
 * Shows green ticks, red crosses, and yellow warnings next to search result links.
 */

// DANGEROUS_DOMAINS loaded from lib/constants.js (injected before this script)

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.buzz', '.club', '.gq', '.ml', '.tk', '.cf', '.ga', '.work', '.click', '.loan', '.download'];

// Search engine configs
const ENGINES = {
    google:     { results: 'a[href][data-ved], a[href] h3', skip: ['google.', 'googleapis.com', 'gstatic.com', 'youtube.com'], container: '.g' },
    bing:       { results: '.b_algo a, .b_title a', skip: ['bing.', 'microsoft.', 'msn.'], container: '.b_algo' },
    duckduckgo: { results: '[data-testid="result"] a[href], .result__a', skip: ['duckduckgo.com'], container: '.result' },
    yahoo:      { results: '.compTitle a, .algo a', skip: ['yahoo.', 'yimg.com'], container: '.algo' },
    ecosia:     { results: '.mainline-results a[href], .result a[href]', skip: ['ecosia.org'], container: '.mainline-results__result' },
    brave:      { results: '.snippet a[href]', skip: ['brave.com', 'search.brave.com'], container: '.snippet' },
};

function detectEngine() {
    const h = window.location.hostname;
    if (h.includes('google.'))       return 'google';
    if (h.includes('bing.'))         return 'bing';
    if (h.includes('duckduckgo.'))   return 'duckduckgo';
    if (h.includes('search.yahoo.')) return 'yahoo';
    if (h.includes('ecosia.'))       return 'ecosia';
    if (h.includes('search.brave.')) return 'brave';
    return null;
}

// --- Local instant check ---
function isDangerous(hostname) {
    const domain = hostname.toLowerCase().replace('www.', '');

    if (typeof DANGEROUS_DOMAINS !== 'undefined') {
        if (DANGEROUS_DOMAINS.includes(domain)) {
            return { dangerous: true, reason: 'Known dangerous domain' };
        }
        for (const d of DANGEROUS_DOMAINS) {
            if (domain.endsWith('.' + d)) {
                return { dangerous: true, reason: 'Subdomain of known dangerous site' };
            }
        }
    }

    for (const tld of SUSPICIOUS_TLDS) {
        if (domain.endsWith(tld)) {
            return { suspicious: true, reason: 'Suspicious top-level domain' };
        }
    }

    return { dangerous: false, suspicious: false };
}

// --- Inject styles once ---
function injectStyles() {
    if (document.getElementById('tte-scan-styles')) return;
    const s = document.createElement('style');
    s.id = 'tte-scan-styles';
    s.textContent = `
        @keyframes tte-pulse { 0%,100%{opacity:.4} 50%{opacity:1} }
        .tte-icon {
            display:inline-flex; align-items:center; justify-content:center;
            width:18px; height:18px; border-radius:50%;
            font-size:12px; font-weight:700;
            font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
            margin-left:6px; vertical-align:middle; cursor:help;
            flex-shrink:0; line-height:1; transition:transform .15s ease;
        }
        .tte-icon:hover { transform:scale(1.3); }
        .tte-icon[data-v="loading"] { animation:tte-pulse 1.2s ease-in-out infinite; }
        .tte-icon[data-v="safe"]       { background:rgba(16,185,129,.15); color:#10b981; border:1.5px solid rgba(16,185,129,.4); }
        .tte-icon[data-v="suspicious"] { background:rgba(245,158,11,.15); color:#f59e0b; border:1.5px solid rgba(245,158,11,.4); }
        .tte-icon[data-v="dangerous"]  { background:rgba(239,68,68,.15);  color:#ef4444; border:1.5px solid rgba(239,68,68,.4); }
        .tte-icon[data-v="loading"]    { background:rgba(148,163,184,.1); color:#94a3b8; border:1.5px solid rgba(148,163,184,.25); }
        .tte-dimmed { opacity:0.55; border-left:3px solid #ef4444 !important; padding-left:8px !important; }
    `;
    document.head.appendChild(s);
}

const SYMBOLS = {
    safe: '\u2713',       // checkmark
    suspicious: '\u26A0', // warning
    dangerous: '\u2717',  // cross
    loading: '\u22EF',    // dots
};

const TITLES = {
    safe: 'No threats detected - Safe',
    suspicious: null,     // uses reason
    dangerous: null,      // uses reason
    loading: 'Checking safety...',
};

function createIcon(verdict, reason) {
    const icon = document.createElement('span');
    icon.className = 'tte-icon';
    icon.dataset.v = verdict;
    icon.textContent = SYMBOLS[verdict];
    icon.title = reason || TITLES[verdict] || verdict;
    return icon;
}

function updateIcon(icon, verdict, reason) {
    icon.dataset.v = verdict;
    icon.textContent = SYMBOLS[verdict];
    icon.title = reason || TITLES[verdict] || verdict;
}

function insertIcon(el, anchor, verdict, reason, engine) {
    const icon = createIcon(verdict, reason);

    if (el.tagName === 'H3') {
        el.appendChild(icon);
    } else {
        anchor.parentElement.insertBefore(icon, anchor.nextSibling);
    }

    if (verdict === 'dangerous') {
        const container = anchor.closest(engine.container) || anchor.parentElement;
        if (container) container.classList.add('tte-dimmed');
    }

    return icon;
}

// --- Cache (in-memory per page load, backed by chrome.storage) ---
const CACHE_KEY = 'tte_url_cache';
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

async function getCache() {
    return new Promise(resolve => {
        chrome.storage.local.get([CACHE_KEY], r => resolve(r[CACHE_KEY] || {}));
    });
}

async function saveCache(entries) {
    const cache = await getCache();
    const now = Date.now();
    for (const [host, data] of Object.entries(entries)) {
        cache[host] = { ...data, t: now };
    }
    // Prune expired
    for (const host of Object.keys(cache)) {
        if (now - cache[host].t > CACHE_TTL) delete cache[host];
    }
    chrome.storage.local.set({ [CACHE_KEY]: cache });
}

function getCached(cache, hostname) {
    const e = cache[hostname];
    if (!e || Date.now() - e.t > CACHE_TTL) return null;
    return e;
}

// --- Main scan ---
async function scanSearchResults() {
    const engineName = detectEngine();
    if (!engineName) return;

    injectStyles();

    const engine = ENGINES[engineName];
    const links = document.querySelectorAll(engine.results);
    const cache = await getCache();

    const urlsToCheck = [];
    const pendingIcons = new Map(); // url -> icon[]

    for (const el of links) {
        const anchor = el.tagName === 'A' ? el : el.closest('a');
        if (!anchor || !anchor.href || anchor.dataset.tteScanned) continue;
        anchor.dataset.tteScanned = '1';

        try {
            const url = new URL(anchor.href);
            if (engine.skip.some(d => url.hostname.includes(d))) continue;
            if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;

            const hostname = url.hostname.toLowerCase().replace('www.', '');

            // Tier 1: Instant local check
            const local = isDangerous(hostname);
            if (local.dangerous) { insertIcon(el, anchor, 'dangerous', local.reason, engine); continue; }
            if (local.suspicious) { insertIcon(el, anchor, 'suspicious', local.reason, engine); continue; }

            // Tier 2: Cache hit
            const cached = getCached(cache, hostname);
            if (cached) { insertIcon(el, anchor, cached.verdict, cached.reason, engine); continue; }

            // Tier 3: Queue for backend batch check, show loading
            const icon = insertIcon(el, anchor, 'loading', null, engine);
            if (!pendingIcons.has(anchor.href)) {
                pendingIcons.set(anchor.href, []);
                urlsToCheck.push(anchor.href);
            }
            pendingIcons.get(anchor.href).push(icon);
        } catch (e) { /* invalid URL */ }
    }

    // Batch backend check
    if (urlsToCheck.length === 0) return;

    try {
        chrome.runtime.sendMessage({ type: 'CHECK_URLS', urls: urlsToCheck }, async (response) => {
            if (chrome.runtime.lastError || !response || !response.success) {
                // Backend offline - mark as safe (fail-open)
                for (const [, icons] of pendingIcons) {
                    icons.forEach(ic => updateIcon(ic, 'safe', 'Backend offline - unverified'));
                }
                return;
            }

            const results = response.results;
            const cacheEntries = {};

            for (const [url, icons] of pendingIcons) {
                const result = results[url] || { verdict: 'safe', reason: null };
                const hostname = new URL(url).hostname.toLowerCase().replace('www.', '');

                icons.forEach(ic => {
                    updateIcon(ic, result.verdict, result.reason);
                    // Dim container if dangerous
                    if (result.verdict === 'dangerous') {
                        const container = ic.closest(engine.container) || ic.parentElement;
                        if (container) container.classList.add('tte-dimmed');
                    }
                });

                cacheEntries[hostname] = { verdict: result.verdict, reason: result.reason };
            }

            await saveCache(cacheEntries);
        });
    } catch (e) {
        // Extension context invalidated, fail silently
    }
}

// Check current page domain
function checkCurrentPage() {
    const result = isDangerous(window.location.hostname);
    if (result.dangerous) {
        chrome.runtime.sendMessage({
            type: 'THREAT_DETECTED',
            threatType: 'LOCAL_BLOCKLIST',
            details: { url: window.location.href, reason: result.reason }
        });
    }
}

// --- Init ---
function init() {
    chrome.storage.local.get(['settings'], (r) => {
        const settings = r.settings || {};
        if (settings.enableSearchAnnotations === false) return;

        scanSearchResults();
        checkCurrentPage();

        // Re-scan on dynamic content (debounced)
        let timer = null;
        const obs = new MutationObserver(() => {
            clearTimeout(timer);
            timer = setTimeout(scanSearchResults, 300);
        });
        if (document.body) {
            obs.observe(document.body, { childList: true, subtree: true });
        }
    });
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
