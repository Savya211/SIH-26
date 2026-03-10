/**
 * content/gmail-scanner.js
 * Scans Gmail email bodies for phishing links and images.
 * Intercepts suspicious link clicks and shows an inline warning overlay.
 *
 * ZPhisher-aware: detects raw IPs, ngrok/serveo tunnels, fake login paths, HTTP links in email.
 *
 * Runs ONLY on https://mail.google.com/* (see manifest.json)
 */

(function () {
    'use strict';

    // ── State ────────────────────────────────────────────────────────────────
    let scannerEnabled = true;
    let scanResults = new Map();   // url → verdict object
    let observerActive = false;

    // ── Settings check ───────────────────────────────────────────────────────
    chrome.storage.local.get(['settings'], (res) => {
        if (res.settings && res.settings.enableGmailScanner === false) {
            scannerEnabled = false;
            return;
        }
        init();
    });

    chrome.storage.onChanged.addListener((changes) => {
        if (changes.settings) {
            const newEnabled = changes.settings.newValue?.enableGmailScanner !== false;
            if (newEnabled !== scannerEnabled) {
                scannerEnabled = newEnabled;
                if (scannerEnabled) init();
            }
        }
    });

    // ── Initialise ───────────────────────────────────────────────────────────
    function init() {
        if (observerActive) return;
        observerActive = true;
        console.log('[GmailScanner] Initialised on', window.location.href);

        // Gmail is a SPA — watch for email-panel DOM changes
        const observer = new MutationObserver(debounce(onDomChange, 600));
        observer.observe(document.body, { childList: true, subtree: true });

        // Also scan immediately in case an email is already open
        setTimeout(scanVisibleEmail, 1200);
    }

    // ── MutationObserver callback ────────────────────────────────────────────
    function onDomChange() {
        if (!scannerEnabled) return;
        scanVisibleEmail();
    }

    // ── Main scan function ───────────────────────────────────────────────────
    function scanVisibleEmail() {
        // Gmail renders the opened email inside role="main"
        const emailPanel = document.querySelector('[role="main"]');
        if (!emailPanel) return;

        // Find the actual email message body containers
        // Gmail uses div.a3s (message body) and gs (quoted text)
        const msgBodies = emailPanel.querySelectorAll('div.a3s, div[data-message-id]');
        if (!msgBodies.length) return;

        msgBodies.forEach(body => {
            // Skip if already processed
            if (body.dataset.tteScanned) return;
            body.dataset.tteScanned = '1';

            const links = extractLinks(body);
            const images = extractImages(body);

            if (links.length === 0 && images.length === 0) return;

            console.log(`[GmailScanner] Email loaded — scanning ${links.length} links, ${images.length} images`);

            // Send to backend for scanning
            fetch('http://localhost:3000/api/scan-email', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ links, images }),
                signal: AbortSignal.timeout(8000)
            })
                .then(r => r.json())
                .then(data => handleScanResults(data, body))
                .catch(err => {
                    // Backend unavailable — fall back to local quick scan
                    console.warn('[GmailScanner] Backend unavailable, using local scan:', err.message);
                    handleLocalFallback(links, images, body);
                });
        });
    }

    // ── Extract all hrefs from email body ────────────────────────────────────
    function extractLinks(container) {
        const anchors = container.querySelectorAll('a[href]');
        const urls = new Set();
        anchors.forEach(a => {
            try {
                const href = a.href;
                // Skip Gmail internal links and mailto
                if (href.startsWith('mailto:') || href.startsWith('javascript:')) return;
                if (href.includes('mail.google.com') && href.includes('#')) return;
                if (href.includes('google.com/url?q=')) {
                    // Unwrap Google redirect URLs
                    const inner = new URL(href).searchParams.get('q');
                    if (inner) urls.add(inner);
                    return;
                }
                urls.add(href);
            } catch { /* skip malformed */ }
        });
        return [...urls].slice(0, 50); // cap at 50
    }

    // ── Extract image src URLs from email body ────────────────────────────────
    function extractImages(container) {
        const imgs = container.querySelectorAll('img[src]');
        const urls = new Set();
        imgs.forEach(img => {
            try {
                const src = img.src;
                if (src.startsWith('data:')) return; // skip inline base64
                if (src.startsWith('chrome-extension://')) return;
                urls.add(src);
            } catch { /* skip */ }
        });
        return [...urls].slice(0, 30);
    }

    // ── Handle backend scan results ───────────────────────────────────────────
    function handleScanResults(data, emailBody) {
        if (!data || !Array.isArray(data.results)) return;

        data.results.forEach(result => {
            scanResults.set(result.url, result);
        });

        // Annotate flagged links in the email DOM
        const flagged = data.results.filter(r => r.verdict !== 'safe');
        if (flagged.length > 0) {
            console.log(`[GmailScanner] ⚠️ Found ${flagged.length} suspicious/dangerous URL(s)`);
            annotateLinks(emailBody, flagged);
            showEmailThreatBanner(flagged, emailBody);
        }

        // Wire click interception on ALL links in this email
        wireClickInterception(emailBody);
    }

    // ── Local fallback heuristics (no backend) ────────────────────────────────
    function handleLocalFallback(links, images, emailBody) {
        const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
        const TUNNEL = /\.(ngrok\.io|ngrok-free\.app|serveo\.net|loclx\.io|trycloudflare\.com)$/;
        const PHISH_PATH = /\/(gmail|google|facebook|fb|instagram|apple|microsoft|paypal|account|login|signin|verify|recover)(\/|$|-|\?)/i;

        const flagged = [];
        [...links, ...images].forEach(url => {
            const reasons = [];
            try {
                const u = new URL(url);
                if (u.protocol === 'http:') reasons.push('Insecure HTTP link in email');
                if (IPV4.test(u.hostname)) reasons.push(`Raw IP address host (${u.hostname}) — ZPhisher pattern`);
                if (TUNNEL.test(u.hostname)) reasons.push(`Tunnel URL detected (${u.hostname})`);
                if (PHISH_PATH.test(u.pathname)) reasons.push('Fake login page path detected');
                if (u.port && !['80', '443'].includes(u.port)) reasons.push(`Non-standard port ${u.port}`);
            } catch { reasons.push('Malformed URL'); }

            if (reasons.length) {
                const result = {
                    url,
                    verdict: reasons.length >= 2 ? 'dangerous' : 'suspicious',
                    score: reasons.length >= 2 ? 15 : 45,
                    reasons,
                    source: 'local-fallback'
                };
                scanResults.set(url, result);
                flagged.push(result);
            }
        });

        if (flagged.length) {
            annotateLinks(emailBody, flagged);
            showEmailThreatBanner(flagged, emailBody);
        }
        wireClickInterception(emailBody);
    }

    // ── Annotate suspicious links inline ─────────────────────────────────────
    function annotateLinks(emailBody, flagged) {
        const flaggedUrls = new Map(flagged.map(f => [f.url, f]));

        emailBody.querySelectorAll('a[href]').forEach(a => {
            let href = a.href;
            // Unwrap Google redirect
            if (href.includes('google.com/url?q=')) {
                try { href = new URL(href).searchParams.get('q') || href; } catch { }
            }

            if (flaggedUrls.has(href)) {
                const result = flaggedUrls.get(href);
                const isDangerous = result.verdict === 'dangerous';

                a.style.outline = `2px solid ${isDangerous ? '#ef4444' : '#f59e0b'}`;
                a.style.borderRadius = '3px';
                a.style.padding = '1px 3px';
                a.title = `⚠️ TheThirdEye: ${result.reasons[0] || 'Suspicious link'}`;

                // Add a small warning badge after the link
                if (!a.dataset.tteBadge) {
                    a.dataset.tteBadge = '1';
                    const badge = document.createElement('span');
                    badge.textContent = isDangerous ? ' ⛔' : ' ⚠️';
                    badge.title = result.reasons.join('\n');
                    badge.style.cssText = 'font-size:13px; cursor:help; user-select:none;';
                    a.insertAdjacentElement('afterend', badge);
                }
            }
        });
    }

    // ── Top-of-email threat banner ────────────────────────────────────────────
    function showEmailThreatBanner(flagged, emailBody) {
        if (emailBody.querySelector('.tte-email-banner')) return; // already shown

        const dangerous = flagged.filter(f => f.verdict === 'dangerous').length;
        const suspicious = flagged.filter(f => f.verdict === 'suspicious').length;

        const banner = document.createElement('div');
        banner.className = 'tte-email-banner';
        banner.style.cssText = `
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 16px;
            margin-bottom: 8px;
            border-radius: 8px;
            background: ${dangerous > 0 ? 'linear-gradient(135deg,#fee2e2,#fecaca)' : 'linear-gradient(135deg,#fef9c3,#fef08a)'};
            border-left: 4px solid ${dangerous > 0 ? '#ef4444' : '#f59e0b'};
            font-family: 'Google Sans', Roboto, sans-serif;
            font-size: 13px;
            color: #1f2937;
            position: relative;
            z-index: 9998;
        `;

        const icon = dangerous > 0 ? '⛔' : '⚠️';
        const title = dangerous > 0
            ? `Phishing Email Detected — ${dangerous} dangerous link${dangerous > 1 ? 's' : ''} found`
            : `Suspicious Email — ${suspicious} suspicious link${suspicious > 1 ? 's' : ''} found`;

        banner.innerHTML = `
            <span style="font-size:20px;">${icon}</span>
            <div style="flex:1">
                <strong style="display:block;margin-bottom:2px;">TheThirdEye: ${title}</strong>
                <span style="color:#6b7280;font-size:12px;">Links are highlighted. Click to see details before proceeding.</span>
            </div>
            <button id="tte-dismiss-banner" style="
                background:transparent;border:none;cursor:pointer;
                font-size:16px;color:#9ca3af;padding:4px 8px;border-radius:4px;
            " title="Dismiss">✕</button>
        `;

        banner.querySelector('#tte-dismiss-banner').addEventListener('click', () => {
            banner.remove();
        });

        emailBody.insertBefore(banner, emailBody.firstChild);
    }

    // ── Click interception ────────────────────────────────────────────────────
    function wireClickInterception(emailBody) {
        emailBody.addEventListener('click', onLinkClick, true); // capture phase
    }

    function onLinkClick(e) {
        if (!scannerEnabled) return;
        const a = e.target.closest('a[href]');
        if (!a) return;

        let href = a.href;
        // Unwrap Google redirect
        if (href.includes('google.com/url?q=')) {
            try { href = new URL(href).searchParams.get('q') || href; } catch { }
        }

        const result = scanResults.get(href);
        if (!result || result.verdict === 'safe') return;

        // Block the click and show overlay
        e.preventDefault();
        e.stopPropagation();
        showInterceptOverlay(href, result);
    }

    // ── Intercept overlay (full-page modal) ───────────────────────────────────
    function showInterceptOverlay(url, result) {
        // Remove existing overlay
        document.getElementById('tte-intercept-overlay')?.remove();

        const isDangerous = result.verdict === 'dangerous';
        let displayUrl = url;
        try {
            const u = new URL(url);
            displayUrl = u.hostname + (u.pathname !== '/' ? u.pathname : '');
            if (displayUrl.length > 60) displayUrl = displayUrl.slice(0, 57) + '…';
        } catch { }

        const overlay = document.createElement('div');
        overlay.id = 'tte-intercept-overlay';
        overlay.style.cssText = `
            position: fixed;
            inset: 0;
            z-index: 2147483647;
            background: rgba(0,0,0,0.75);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Google Sans', Roboto, sans-serif;
            backdrop-filter: blur(4px);
        `;

        overlay.innerHTML = `
            <div style="
                background: #fff;
                border-radius: 16px;
                padding: 36px 32px;
                max-width: 520px;
                width: 90%;
                box-shadow: 0 25px 60px rgba(0,0,0,0.4);
                text-align: center;
                animation: tte-pop 0.2s ease;
            ">
                <div style="font-size:56px;margin-bottom:12px;">${isDangerous ? '⛔' : '⚠️'}</div>
                <h2 style="
                    margin: 0 0 8px;
                    font-size: 22px;
                    color: ${isDangerous ? '#dc2626' : '#d97706'};
                    font-weight: 700;
                ">${isDangerous ? 'Phishing Link Detected!' : 'Suspicious Link'}</h2>
                <p style="margin:0 0 16px;color:#374151;font-size:14px;">
                    This link was flagged by <strong>TheThirdEye</strong> as
                    <strong>${isDangerous ? 'dangerous' : 'suspicious'}</strong>.
                </p>

                <div style="
                    background: #f3f4f6;
                    border-radius: 8px;
                    padding: 10px 14px;
                    margin-bottom: 16px;
                    text-align: left;
                    word-break: break-all;
                    font-size: 13px;
                    color: #6b7280;
                ">
                    <span style="font-weight:600;color:#111827;">Destination:</span><br>
                    <span style="color:#dc2626;">${displayUrl}</span>
                </div>

                <div style="
                    text-align: left;
                    background: ${isDangerous ? '#fee2e2' : '#fef9c3'};
                    border-radius: 8px;
                    padding: 10px 14px;
                    margin-bottom: 24px;
                    font-size: 13px;
                ">
                    <div style="font-weight:600;margin-bottom:4px;color:#111827;">Why flagged:</div>
                    ${result.reasons.map(r => `<div style="color:#374151;margin-bottom:2px;">• ${r}</div>`).join('')}
                    ${result.source ? `<div style="margin-top:6px;font-size:11px;color:#9ca3af;">Source: ${result.source}</div>` : ''}
                </div>

                <div style="display:flex;gap:12px;justify-content:center;">
                    <button id="tte-go-back" style="
                        padding: 12px 28px;
                        background: #2563eb;
                        color: #fff;
                        border: none;
                        border-radius: 8px;
                        font-size: 15px;
                        font-weight: 600;
                        cursor: pointer;
                        transition: background 0.2s;
                    ">← Go Back (Safe)</button>
                    <button id="tte-proceed" style="
                        padding: 12px 22px;
                        background: transparent;
                        color: #6b7280;
                        border: 2px solid #e5e7eb;
                        border-radius: 8px;
                        font-size: 14px;
                        cursor: pointer;
                        transition: all 0.2s;
                    ">Proceed Anyway ↗</button>
                </div>
                <p style="margin:16px 0 0;font-size:11px;color:#9ca3af;">
                    TheThirdEye Security Extension
                </p>
            </div>
            <style>
                @keyframes tte-pop {
                    from { transform: scale(0.9); opacity: 0; }
                    to   { transform: scale(1);   opacity: 1; }
                }
                #tte-go-back:hover { background: #1d4ed8 !important; }
                #tte-proceed:hover { border-color: #9ca3af !important; color: #374151 !important; }
            </style>
        `;

        document.body.appendChild(overlay);

        // Buttons
        overlay.querySelector('#tte-go-back').addEventListener('click', () => overlay.remove());
        overlay.querySelector('#tte-proceed').addEventListener('click', () => {
            overlay.remove();
            window.open(url, '_blank', 'noopener,noreferrer');
        });

        // Click outside to close (treat as go back)
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) overlay.remove();
        });

        // Notify background for logging
        chrome.runtime.sendMessage({
            type: 'GMAIL_PHISHING_DETECTED',
            url,
            verdict: result.verdict,
            reasons: result.reasons,
            timestamp: Date.now()
        });
    }

    // ── Utility: debounce ─────────────────────────────────────────────────────
    function debounce(fn, delay) {
        let t;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), delay);
        };
    }

})();
