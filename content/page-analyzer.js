/**
 * content/page-analyzer.js
 * Extracts security-relevant signals from the current page and sends them to the backend for AI analysis.
 * No actual form VALUES (passwords, credit cards) are ever extracted — only structural counts.
 */

// Suspicious keywords are now loaded from lib/constants.js

function extractPageSignals() {
    const signals = {};

    // URL & Title
    signals.url = window.location.href;
    signals.title = document.title || '';
    signals.isHTTPS = window.location.protocol === 'https:';

    // Forms
    const forms = document.querySelectorAll('form');
    signals.totalForms = forms.length;
    signals.passwordFields = document.querySelectorAll('input[type="password"]').length;

    // Detect credit card fields by name/id/autocomplete patterns
    const ccPatterns = /card|cc-number|cardnumber|credit|cvc|cvv|expir/i;
    const allInputs = document.querySelectorAll('input');
    signals.creditCardFields = Array.from(allInputs).filter(inp => {
        return ccPatterns.test(inp.name || '') ||
            ccPatterns.test(inp.id || '') ||
            ccPatterns.test(inp.autocomplete || '');
    }).length;

    // Hidden iframes
    const iframes = document.querySelectorAll('iframe');
    signals.hiddenIframes = Array.from(iframes).filter(f => {
        const style = window.getComputedStyle(f);
        return style.display === 'none' ||
            style.visibility === 'hidden' ||
            f.width === '0' || f.height === '0' ||
            parseInt(style.width) <= 1 || parseInt(style.height) <= 1;
    }).length;

    // External scripts
    const scripts = document.querySelectorAll('script[src]');
    const externalScripts = Array.from(scripts).filter(s => {
        // Explicitly check for default BeEF hook filename
        if (s.src.endsWith('/hook.js') || s.src.includes('beef')) {
            signals.hasBeefHook = true;
        }

        try {
            return new URL(s.src).hostname !== window.location.hostname;
        } catch (e) { return false; }
    });
    signals.externalScripts = externalScripts.length;
    signals.uniqueScriptDomains = new Set(externalScripts.map(s => {
        try { return new URL(s.src).hostname; } catch (e) { return ''; }
    })).size;

    // Direct object detection (BeEF creates window.beef)
    signals.hasBeefObject = typeof window.beef !== 'undefined';

    // Auto-download detection
    signals.autoDownloads = document.querySelectorAll('a[download], a[href$=".exe"], a[href$=".msi"], a[href$=".bat"], a[href$=".cmd"], a[href$=".scr"]').length;

    // Suspicious keyword scanning (only scan visible text, limited)
    const bodyText = (document.body?.innerText || '').toLowerCase().slice(0, 5000);
    signals.suspiciousKeywords = SUSPICIOUS_KEYWORDS.filter(kw => bodyText.includes(kw));

    // Text snippet (first 200 chars of visible text for AI context)
    signals.textSnippet = bodyText.slice(0, 200).replace(/\n/g, ' ').trim();

    // Redirect count (basic - check if URL changed from what was initially typed)
    signals.redirectCount = window.performance?.getEntriesByType('navigation')?.[0]?.redirectCount || 0;

    // Known domain check
    const KNOWN_SAFE = ['google.com', 'youtube.com', 'facebook.com', 'github.com', 'amazon.com', 'microsoft.com', 'apple.com'];
    const hostname = window.location.hostname.replace('www.', '');
    signals.isKnownDomain = KNOWN_SAFE.some(d => hostname === d || hostname.endsWith('.' + d));

    return signals;
}

// Run analysis after the page finishes loading
function runAnalysis() {
    // Skip internal/extension pages
    if (window.location.protocol === 'chrome:' || window.location.protocol === 'chrome-extension:') return;

    // Skip known safe domains to reduce noise and false positives
    const hostname = window.location.hostname.replace('www.', '');
    const SKIP_DOMAINS = [
        'google.com', 'youtube.com', 'chrome.google.com', 'bing.com',
        'yahoo.com', 'duckduckgo.com', 'ecosia.org', 'search.brave.com',
        'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
        'linkedin.com', 'github.com', 'stackoverflow.com', 'reddit.com',
        'amazon.com', 'wikipedia.org', 'microsoft.com', 'apple.com',
        'netflix.com', 'spotify.com', 'paypal.com', 'ebay.com',
        'whatsapp.com', 'telegram.org', 'discord.com', 'slack.com',
        'zoom.us', 'twitch.tv', 'tiktok.com', 'pinterest.com',
        'dropbox.com', 'notion.so', 'figma.com', 'canva.com',
        'medium.com', 'quora.com', 'wordpress.com', 'tumblr.com',
        'cloudflare.com', 'npmjs.com', 'pypi.org', 'gitlab.com',
        'walmart.com', 'target.com', 'bestbuy.com', 'bitbucket.org',
    ];
    if (SKIP_DOMAINS.some(d => hostname === d || hostname.endsWith('.' + d))) return;

    // Check if feature is enabled
    chrome.storage.local.get(['settings'], (result) => {
        if (result.settings && result.settings.enablePhishingCheck === false) return;

        const signals = extractPageSignals();

        // Send to background for backend analysis
        chrome.runtime.sendMessage({
            type: 'ANALYZE_PAGE',
            signals: signals
        }, (response) => {
            if (chrome.runtime.lastError) {
                // Backend might not be running — that's ok
                return;
            }
            // The background script handles the response (blocking, badge, notifications)
        });
    });
}

// Wait for page to fully load before extracting signals
if (document.readyState === 'complete') {
    setTimeout(runAnalysis, 1500);
} else {
    window.addEventListener('load', () => setTimeout(runAnalysis, 1500));
}
