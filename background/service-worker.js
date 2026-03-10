// Background Service Worker

// Fallback: use chrome.storage.session if available, otherwise chrome.storage.local
const sessionStore = chrome.storage.session || chrome.storage.local;

chrome.runtime.onInstalled.addListener(() => {
    console.log('Browser Security Manager Extension Installed');

    chrome.storage.local.get(['settings'], (result) => {
        const defaultSettings = {
            enablePasswordCheck: true,
            enablePhishingCheck: true,
            enableTrackerBlocker: true,
            enableAdBlocker: true,
            enableWebRTCProtect: true,
            enableCookieAutoDelete: false,
            enableDoH: false,
            enableSearchAnnotations: true,
            enableGmailScanner: true,
            safeBrowsingApiKey: '',
            phishtankApiKey: ''
        };

        if (!result.settings) {
            chrome.storage.local.set({ settings: defaultSettings });
        }

        // Apply initial policies
        const currentSettings = result.settings || defaultSettings;
        if (currentSettings.enableWebRTCProtect && chrome.privacy && chrome.privacy.network) {
            chrome.privacy.network.webRTCIPHandlingPolicy.set({
                value: 'disable_non_proxied_udp'
            });
        }
        if (currentSettings.enableDoH && chrome.privacy && chrome.privacy.network && chrome.privacy.network.dnsOverHttpsMode) {
            chrome.privacy.network.dnsOverHttpsMode.set({ value: 'automatic' });
        }
    });
});

// Listener for messages from content scripts or popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'TEST_MESSAGE') {
        sendResponse({ status: 'ok' });
    }

    // --- AI/Backend Page Analysis ---
    if (request.type === 'ANALYZE_PAGE') {
        const { signals } = request;

        fetch('http://localhost:3000/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signals)
        })
            .then(res => res.json())
            .then(data => {
                // Only block on high-confidence dangerous verdicts (threat-list or very low score)
                if (data.blocked && data.verdict === 'dangerous' && (data.source === 'threat-list' || data.score <= 20)) {
                    const threatSource = data.source === 'threat-list' ? 'Community Threat Database' :
                        data.source === 'ai+heuristic' ? 'AI Security Analysis' : 'Security Heuristics';
                    const redirectUrl = chrome.runtime.getURL(`pages/warning.html?url=${encodeURIComponent(signals.url)}&source=${encodeURIComponent(threatSource)}&type=MALWARE`);

                    chrome.tabs.update(sender.tab.id, { url: redirectUrl });

                    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
                    chrome.action.setBadgeText({ text: '!' });

                    chrome.notifications.create('', {
                        type: 'basic',
                        iconUrl: '../assets/icons/icon128.png',
                        title: 'Dangerous Site Blocked!',
                        message: `Blocked access to ${new URL(signals.url).hostname}. Reason: ${data.reasons?.[0] || 'Malicious behavior detected'}`,
                        priority: 2
                    });

                    // Log threat
                    chrome.storage.local.get(['threatLog'], (res) => {
                        const log = res.threatLog || [];
                        log.push({ url: signals.url, source: threatSource, timestamp: Date.now() });
                        chrome.storage.local.set({ threatLog: log });
                    });
                } else if (data.verdict === 'suspicious' && data.score < 50) {
                    // Only show yellow badge for genuinely suspicious sites
                    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
                    chrome.action.setBadgeText({ text: '?' });
                } else {
                    // Clear any previous badge for safe sites
                    chrome.action.setBadgeText({ text: '' });
                }
                sendResponse({ success: true, analysis: data });
            })
            .catch(err => {
                console.error('[ServiceWorker] Backend analysis failed:', err);
                sendResponse({ success: false, error: err.toString() });
            });

        return true; // async response
    }

    // --- Batch URL Safety Check (for search result annotations) ---
    if (request.type === 'CHECK_URLS') {
        fetch('http://localhost:3000/api/check-urls', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: request.urls }),
            signal: AbortSignal.timeout(5000)
        })
            .then(res => res.json())
            .then(data => sendResponse({ success: true, results: data.results }))
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }

    // --- HIBP Password Breach Checker ---
    if (request.type === 'CHECK_HIBP') {
        fetch(`https://api.pwnedpasswords.com/range/${request.prefix}`)
            .then(res => res.ok ? res.text() : Promise.reject('HIBP Error'))
            .then(data => sendResponse({ success: true, data: data }))
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true; // Keep message channel open for async response
    }

    if (request.type === 'BREACH_DETECTED') {
        const { url, count } = request;

        // Store the breach locally
        chrome.storage.local.get(['breaches'], (res) => {
            const breaches = res.breaches || [];
            const existing = breaches.find(b => b.url === url);

            if (!existing) {
                breaches.push({ url, count, timestamp: Date.now() });
            } else {
                existing.count = count;
                existing.timestamp = Date.now();
            }
            chrome.storage.local.set({ breaches });
        });

        chrome.notifications.create('', {
            type: 'basic',
            iconUrl: '../assets/icons/icon128.png',
            title: 'Password Breach Detected!',
            message: `⚠️ Your password for ${url} has been found in ${count.toLocaleString()} data breaches. Please change it immediately.`,
            priority: 2
        });
    }

    if (request.type === 'THREAT_DETECTED') {
        const { threatType, details } = request;

        let source = 'Security Manager';
        let targetUrl = details.lookalike || details.url || 'Unknown';
        let redirectUrl = chrome.runtime.getURL(`pages/warning.html?url=${encodeURIComponent(targetUrl)}&source=${encodeURIComponent(source)}&type=${threatType}`);

        // Update badge
        chrome.action.setBadgeBackgroundColor({ color: '#ef4444' }); // Red
        chrome.action.setBadgeText({ text: '!' });

        chrome.notifications.create('', {
            type: 'basic',
            iconUrl: '../assets/icons/icon128.png',
            title: 'Dangerous Site Blocked',
            message: `Blocked access to ${targetUrl}`,
            priority: 2
        });

        chrome.tabs.update(sender.tab.id, { url: redirectUrl });
    }

    // --- Header Retrieval ---
    if (request.type === 'GET_HEADERS') {
        sessionStore.get([`headers_${request.tabId}`], (result) => {
            sendResponse({ success: true, data: result[`headers_${request.tabId}`] || null });
        });
        return true;
    }

    // --- Mixed Content ---
    if (request.type === 'MIXED_CONTENT_REPORT') {
        sessionStore.set({ [`mixed_${sender.tab.id}`]: request.data });
        sendResponse({ success: true });
        return true;
    }

    if (request.type === 'GET_MIXED_CONTENT') {
        sessionStore.get([`mixed_${request.tabId}`], (result) => {
            sendResponse({ success: true, data: result[`mixed_${request.tabId}`] || null });
        });
        return true;
    }

    // --- Domain Reputation ---
    if (request.type === 'GET_DOMAIN_REPUTATION') {
        const domain = request.domain;
        const isBlocked = isLocallyBlocked('https://' + domain);

        // Try backend for WHOIS/Tranco data, fall back gracefully
        fetch(`http://localhost:3000/api/reputation/${encodeURIComponent(domain)}`)
            .then(r => r.json())
            .then(backendData => {
                sendResponse({ success: true, domain, inBlocklist: isBlocked, backendData });
            })
            .catch(() => {
                sendResponse({ success: true, domain, inBlocklist: isBlocked, backendData: null });
            });
        return true;
    }

    // --- Cookie Management ---
    if (request.type === 'GET_COOKIES') {
        try {
            chrome.cookies.getAll({ url: request.url }, (cookies) => {
                if (chrome.runtime.lastError) {
                    sendResponse({ success: false, error: chrome.runtime.lastError.message });
                } else {
                    sendResponse({ success: true, cookies: cookies });
                }
            });
        } catch (e) {
            sendResponse({ success: false, error: e.message });
        }
        return true;
    }
    if (request.type === 'DELETE_COOKIE') {
        try {
            chrome.cookies.remove({ url: request.url, name: request.name }, () => {
                if (chrome.runtime.lastError) {
                    sendResponse({ success: false, error: chrome.runtime.lastError.message });
                } else {
                    sendResponse({ success: true });
                }
            });
        } catch (e) {
            sendResponse({ success: false, error: e.message });
        }
        return true;
    }
    if (request.type === 'CLEAR_COOKIES') {
        try {
            chrome.cookies.getAll({ url: request.url }, (cookies) => {
                if (chrome.runtime.lastError) {
                    sendResponse({ success: false, error: chrome.runtime.lastError.message });
                    return;
                }

                let deletedCount = 0;
                if (!cookies || cookies.length === 0) {
                    sendResponse({ success: true });
                    return;
                }
                cookies.forEach(c => {
                    chrome.cookies.remove({ url: request.url, name: c.name }, () => {
                        deletedCount++;
                        if (deletedCount === cookies.length) {
                            sendResponse({ success: true });
                        }
                    });
                });
            });
        } catch (e) {
            sendResponse({ success: false, error: e.message });
        }
        return true;
    }

    // --- Gmail Phishing Scanner Threat Logging ---
    if (request.type === 'GMAIL_PHISHING_DETECTED') {
        const { url, verdict, reasons } = request;

        // Log to threat log
        chrome.storage.local.get(['threatLog'], (res) => {
            const log = res.threatLog || [];
            log.push({
                url,
                source: 'Gmail Scanner',
                verdict,
                reasons,
                timestamp: Date.now()
            });
            chrome.storage.local.set({ threatLog: log });
        });

        // Show browser notification
        chrome.notifications.create('', {
            type: 'basic',
            iconUrl: 'assets/icons/icon128.png',
            title: verdict === 'dangerous' ? '⛔ Phishing Email Link Blocked!' : '⚠️ Suspicious Email Link',
            message: `TheThirdEye intercepted a ${verdict} link in Gmail:\n${reasons?.[0] || 'Phishing pattern detected'}`,
            priority: verdict === 'dangerous' ? 2 : 1
        });

        // Update badge
        chrome.action.setBadgeBackgroundColor({ color: verdict === 'dangerous' ? '#ef4444' : '#f59e0b' });
        chrome.action.setBadgeText({ text: verdict === 'dangerous' ? '!' : '?' });
    }
});

// --- Phishing / Malware Handling ---
// INLINED API functions (importScripts path resolution is unreliable in MV3 service workers)

async function checkUrlSafeBrowsing(url, apiKey) {
    if (!apiKey) {
        console.warn('[SecurityManager] Google Safe Browsing API key missing. Skipping check.');
        return { isSafe: true };
    }

    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

    const requestBody = {
        client: {
            clientId: "browser-security-manager",
            clientVersion: "1.0.0"
        },
        threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [
                { url: url }
            ]
        }
    };

    try {
        console.log('[SecurityManager] Checking URL with Safe Browsing:', url);
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestBody)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('[SecurityManager] Safe Browsing API Error:', response.status, errorText);
            throw new Error(`API returned ${response.status}`);
        }

        const data = await response.json();
        console.log('[SecurityManager] Safe Browsing Response:', JSON.stringify(data));

        if (data && data.matches && data.matches.length > 0) {
            return {
                isSafe: false,
                threats: data.matches.map(m => m.threatType)
            };
        }

        return { isSafe: true };
    } catch (e) {
        console.error('[SecurityManager] Safe Browsing fetch error:', e);
        return { isSafe: true };
    }
}

async function checkUrlPhishTank(url, apiKey) {
    const encodedUrl = encodeURIComponent(url);
    const endpoint = 'https://checkurl.phishtank.com/checkurl/';

    const formData = new URLSearchParams();
    formData.append('url', encodedUrl);
    formData.append('format', 'json');
    if (apiKey) {
        formData.append('app_key', apiKey);
    }

    try {
        console.log('[SecurityManager] Checking URL with PhishTank:', url);
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString()
        });

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        const data = await response.json();

        if (data && data.results && data.results.in_database && data.results.valid) {
            return { isSafe: false, source: 'PhishTank' };
        }

        return { isSafe: true };
    } catch (e) {
        console.error('[SecurityManager] PhishTank fetch error:', e);
        return { isSafe: true };
    }
}

console.log('[SecurityManager] API functions loaded successfully.');

// Fetch shared constants
try {
    importScripts('/lib/constants.js');
} catch (e) {
    console.error('[SecurityManager] Failed to load constants:', e);
}

function isLocallyBlocked(urlString) {
    try {
        const url = new URL(urlString);
        const hostname = url.hostname.toLowerCase().replace('www.', '');
        for (const d of DANGEROUS_DOMAINS) {
            if (hostname === d || hostname.endsWith('.' + d)) {
                return true;
            }
        }
    } catch (e) { }
    return false;
}

// Background web navigation listener 
if (chrome.webNavigation && chrome.webNavigation.onBeforeNavigate) {
    chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
        if (details.frameId !== 0) return;
        if (details.url.startsWith('chrome://') || details.url.startsWith('chrome-extension://')) return;

        chrome.storage.local.get(['settings', 'whitelist'], async (result) => {
            if (!result.settings || result.settings.enablePhishingCheck === false) return;

            const now = Date.now();
            let whitelist = result.whitelist || [];

            // Filter out old string formats or expired entries
            const validEntries = whitelist.filter(w => typeof w === 'object' && w.expires > now);

            // Check whitelist by both exact URL and hostname
            let navHostname = '';
            try { navHostname = new URL(details.url).hostname.toLowerCase().replace('www.', ''); } catch (e) { }
            const isWhitelisted = validEntries.some(w =>
                w.url === details.url || w.hostname === navHostname
            );
            if (isWhitelisted) return;

            // --- Step 1: LOCAL blocklist check (instant, no API needed) ---
            if (isLocallyBlocked(details.url)) {
                console.log('[SecurityManager] BLOCKED by local blocklist:', details.url);
                const redirectUrl = chrome.runtime.getURL(`pages/warning.html?url=${encodeURIComponent(details.url)}&source=${encodeURIComponent('Local Threat Database')}&type=MALWARE`);
                chrome.tabs.update(details.tabId, { url: redirectUrl });

                // Update badge
                chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
                chrome.action.setBadgeText({ text: '!' });

                chrome.notifications.create('', {
                    type: 'basic',
                    iconUrl: 'assets/icons/icon128.png',
                    title: '⛔ Dangerous Site Blocked!',
                    message: `Blocked access to ${details.url}. This site is known to distribute malware or fraudulent content.`,
                    priority: 2
                });

                // Log threat
                chrome.storage.local.get(['threatLog'], (res) => {
                    const log = res.threatLog || [];
                    log.push({ url: details.url, source: 'Local Blocklist', timestamp: Date.now() });
                    chrome.storage.local.set({ threatLog: log });
                });
                return;
            }

            // --- Step 2: Pre-navigation reputation check (backend threat lists) ---
            try {
                const hostname = new URL(details.url).hostname.replace('www.', '');
                const RISKY_TLDS = ['.xyz', '.top', '.buzz', '.club', '.gq', '.ml', '.tk', '.cf', '.ga', '.work', '.click', '.loan', '.download', '.bid', '.racing', '.win', '.stream'];
                const hasRiskyTld = RISKY_TLDS.some(tld => hostname.endsWith(tld));

                // Check backend threat lists ONLY (URLhaus + OpenPhish)
                // We only use threat-list matches here — heuristics/AI need full page
                // signals from the content script, so they run post-load instead.
                let backendBlocked = false;
                let backendSource = '';
                try {
                    const backendRes = await fetch('http://localhost:3000/api/analyze', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: details.url, isHTTPS: details.url.startsWith('https://') }),
                        signal: AbortSignal.timeout(3000)
                    });
                    if (backendRes.ok) {
                        const data = await backendRes.json();
                        // Only block on confirmed threat-list match, not heuristic/AI guesses
                        if (data.source === 'threat-list' && data.blocked) {
                            backendBlocked = true;
                            backendSource = 'Community Threat Database (URLhaus/OpenPhish)';
                        }
                    }
                } catch (e) { /* backend unavailable, continue to API checks */ }

                if (backendBlocked) {
                    console.log('[SecurityManager] BLOCKED by pre-nav check:', details.url, backendSource);
                    const redirectUrl = chrome.runtime.getURL(`pages/warning.html?url=${encodeURIComponent(details.url)}&source=${encodeURIComponent(backendSource)}&type=MALWARE`);
                    chrome.tabs.update(details.tabId, { url: redirectUrl });

                    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
                    chrome.action.setBadgeText({ text: '!' });

                    chrome.notifications.create('', {
                        type: 'basic',
                        iconUrl: 'assets/icons/icon128.png',
                        title: 'Dangerous Site Blocked!',
                        message: `Blocked ${hostname} - found in ${backendSource}.`,
                        priority: 2
                    });

                    chrome.storage.local.get(['threatLog'], (res) => {
                        const log = res.threatLog || [];
                        log.push({ url: details.url, source: backendSource, timestamp: Date.now() });
                        chrome.storage.local.set({ threatLog: log });
                    });
                    return;
                }

                // Risky TLD — warn via badge (not block, since it's just a TLD signal)
                if (hasRiskyTld) {
                    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId: details.tabId });
                    chrome.action.setBadgeText({ text: '?', tabId: details.tabId });
                }
            } catch (e) {
                console.warn('[SecurityManager] Pre-nav reputation check error:', e.message);
            }

            // --- Step 3: API-based checks (Google Safe Browsing + PhishTank) ---
            const sbKey = result.settings.safeBrowsingApiKey;
            const ptKey = result.settings.phishtankApiKey;

            const [sbResult, ptResult] = await Promise.all([
                sbKey ? checkUrlSafeBrowsing(details.url, sbKey) : { isSafe: true },
                ptKey ? checkUrlPhishTank(details.url, ptKey) : { isSafe: true }
            ]);

            if (!sbResult.isSafe || !ptResult.isSafe) {
                const threatSource = !sbResult.isSafe ? 'Google Safe Browsing' : 'PhishTank';
                console.log('[SecurityManager] BLOCKED by API:', details.url, threatSource);
                const redirectUrl = chrome.runtime.getURL(`pages/warning.html?url=${encodeURIComponent(details.url)}&source=${encodeURIComponent(threatSource)}&type=MALWARE`);
                chrome.tabs.update(details.tabId, { url: redirectUrl });

                chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
                chrome.action.setBadgeText({ text: '!' });

                // Log threat
                chrome.storage.local.get(['threatLog'], (res) => {
                    const log = res.threatLog || [];
                    log.push({ url: details.url, source: threatSource, timestamp: Date.now() });
                    chrome.storage.local.set({ threatLog: log });
                });
            }
        });
    });
} else {
    console.warn('[SecurityManager] webNavigation API not available.');
}

// Second listener was merged into the main listener above.

// --- SSL Config & Header Capture ---
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.type !== 'main_frame') return;

        const url = new URL(details.url);

        // Store response headers for the Network tab
        if (details.responseHeaders) {
            sessionStore.set({
                [`headers_${details.tabId}`]: {
                    url: details.url,
                    statusCode: details.statusCode,
                    headers: details.responseHeaders,
                    timestamp: Date.now()
                }
            });
        }

        if (url.protocol === 'http:') {
            // Insecure connection
            chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId: details.tabId }); // Yellow
            chrome.action.setBadgeText({ text: 'Insecure', tabId: details.tabId });

            chrome.storage.local.get(['insecureSites'], (res) => {
                const insecureSites = res.insecureSites || {};
                insecureSites[details.tabId] = url.hostname;
                chrome.storage.local.set({ insecureSites });
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

// --- Settings Changes (Trackers & WebRTC) ---
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.settings) {
        // Trackers
        const rulesetId = "ruleset_trackers";
        const enableTrackers = changes.settings.newValue.enableTrackerBlocker;

        if (enableTrackers !== undefined) {
            if (enableTrackers) {
                chrome.declarativeNetRequest.updateEnabledRulesets({ enableRulesetIds: [rulesetId] });
            } else {
                chrome.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: [rulesetId] });
            }
        }

        // WebRTC
        const enableWebRTC = changes.settings.newValue.enableWebRTCProtect;
        if (enableWebRTC !== undefined && chrome.privacy && chrome.privacy.network) {
            chrome.privacy.network.webRTCIPHandlingPolicy.set({
                value: enableWebRTC ? 'disable_non_proxied_udp' : 'default'
            });
        }

        // DNS-over-HTTPS
        const enableDoH = changes.settings.newValue.enableDoH;
        if (enableDoH !== undefined && chrome.privacy && chrome.privacy.network && chrome.privacy.network.dnsOverHttpsMode) {
            chrome.privacy.network.dnsOverHttpsMode.set({
                value: enableDoH ? 'automatic' : 'off'
            });
        }
    }
});

// --- Memory Cleanup on Tab Close ---
chrome.tabs.onRemoved.addListener((tabId) => {
    // Clean up local storage for insecureSites
    chrome.storage.local.get(['insecureSites'], (res) => {
        if (res.insecureSites && res.insecureSites[tabId]) {
            delete res.insecureSites[tabId];
            chrome.storage.local.set({ insecureSites: res.insecureSites });
        }
    });

    // Clean up session storage for headers and mixed content
    sessionStore.remove([`headers_${tabId}`, `mixed_${tabId}`]);
});
