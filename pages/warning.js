document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    const source = params.get('source');
    const type = params.get('type');

    document.getElementById('threat-url').textContent = url || 'Unknown URL';
    document.getElementById('threat-source').textContent = source || 'Unknown Detection Engine';

    if (type === 'HOMOGLYPH') {
        document.getElementById('warning-title').textContent = 'Suspicious Domain Detected';
        document.getElementById('warning-message').textContent = 'This site\'s URL looks like a popular site, but it is actually a different domain. This is often used in phishing attacks to steal your information.';
    }

    // Back to Safety — go back 2 steps (skip the dangerous URL in history) or close tab
    document.getElementById('btn-back').addEventListener('click', () => {
        if (window.history.length > 2) {
            window.history.go(-2);
        } else {
            // Close the tab if we can't go back far enough
            window.close();
        }
    });

    // Proceed Anyway — whitelist the URL for 24h, then navigate
    document.getElementById('btn-proceed').addEventListener('click', () => {
        if (!url) return;

        chrome.storage.local.get(['whitelist'], (res) => {
            const now = Date.now();
            let whitelist = res.whitelist || [];

            // Clean expired entries
            whitelist = whitelist.filter(w => typeof w === 'object' && w.expires > now);

            // Add the URL and its hostname variant to whitelist
            try {
                const parsed = new URL(url);
                const hostname = parsed.hostname.toLowerCase().replace('www.', '');

                // Remove existing entries for this URL/hostname
                whitelist = whitelist.filter(w => w.url !== url && w.hostname !== hostname);

                // Add both url and hostname so matching works regardless of trailing slashes etc.
                whitelist.push({
                    url: url,
                    hostname: hostname,
                    expires: now + 24 * 60 * 60 * 1000
                });
            } catch (e) {
                whitelist.push({ url: url, expires: now + 24 * 60 * 60 * 1000 });
            }

            chrome.storage.local.set({ whitelist }, () => {
                // Small delay to ensure storage is written before navigation triggers onBeforeNavigate
                setTimeout(() => {
                    window.location.href = url;
                }, 100);
            });
        });
    });
});
