/**
 * popup/components/reputation.js
 * Renders domain reputation card in the Overview tab
 */

document.addEventListener('DOMContentLoaded', () => {
    loadReputation();
    document.querySelector('[data-tab="overview"]').addEventListener('click', loadReputation);
});

async function loadReputation() {
    const card = document.getElementById('reputation-card');
    if (!card) return;

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        card.style.display = 'none';
        return;
    }

    let domain;
    try { domain = new URL(tab.url).hostname.replace('www.', ''); } catch (e) { card.style.display = 'none'; return; }

    const isHTTPS = tab.url.startsWith('https://');

    // Get header grade if available
    let headerGrade = null;
    try {
        headerGrade = await new Promise((resolve) => {
            chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: tab.id }, (hRes) => {
                if (hRes && hRes.data && hRes.data.headers && typeof gradeSecurityHeaders === 'function') {
                    resolve(gradeSecurityHeaders(hRes.data.headers).grade);
                } else {
                    resolve(null);
                }
            });
        });
    } catch (e) { /* ignore */ }

    // Get backend data (blocklist + WHOIS)
    chrome.runtime.sendMessage({ type: 'GET_DOMAIN_REPUTATION', domain }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
            card.style.display = 'none';
            return;
        }

        const signals = {
            domain,
            isHTTPS,
            inBlocklist: response.inBlocklist,
            headerGrade,
            backendData: response.backendData
        };

        if (typeof scoreDomainReputation !== 'function') {
            card.style.display = 'none';
            return;
        }

        const rep = scoreDomainReputation(signals);
        const verdictColors = { trusted: 'var(--success)', caution: 'var(--warning)', risky: 'var(--danger)' };
        const verdictColor = verdictColors[rep.verdict] || 'var(--text-muted)';

        let detailsHtml = '';
        rep.details.forEach(d => {
            const color = d.status === 'good' ? 'var(--success)' : d.status === 'warn' ? 'var(--warning)' : 'var(--danger)';
            const icon = d.status === 'good' ? '&#10003;' : d.status === 'warn' ? '&#9888;' : '&#10007;';
            detailsHtml += `<div style="display:flex;align-items:center;gap:6px;font-size:12px;padding:3px 0;">
                <span style="color:${color};">${icon}</span>
                <span>${d.label}</span>
                ${d.impact ? `<span style="color:${color};margin-left:auto;">${d.impact}</span>` : ''}
            </div>`;
        });

        card.style.display = 'block';
        document.getElementById('rep-domain').textContent = domain;
        document.getElementById('rep-score').textContent = rep.score;
        document.getElementById('rep-score').style.backgroundColor = verdictColor;
        document.getElementById('rep-verdict').textContent = rep.verdict.charAt(0).toUpperCase() + rep.verdict.slice(1);
        document.getElementById('rep-verdict').style.color = verdictColor;
        document.getElementById('rep-details').innerHTML = detailsHtml;
    });
}
