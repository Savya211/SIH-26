/**
 * popup/components/dashboard.js
 * Logic for calculating and displaying the overall security score and stats
 */

document.addEventListener('DOMContentLoaded', () => {
    // When popup opens, gather stats
    updateDashboard();

    // Listen for tab switch to overview to refresh
    document.querySelector('[data-tab="overview"]').addEventListener('click', updateDashboard);
});

function updateDashboard() {
    let score = 100;
    let breachesCount = 0;
    let threatsCount = 0;

    chrome.storage.local.get(['breaches', 'insecureSites', 'settings'], async (result) => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

        // 1. Password Breaches
        if (result.breaches) {
            breachesCount = result.breaches.length;
            score -= (breachesCount * 10); // -10 points per breached site
        }
        document.getElementById('stat-passwords').textContent = breachesCount;

        // 2. SSL Status
        const statusCard = document.querySelector('.status-card');
        const statusTitle = statusCard.querySelector('h2');
        const statusDesc = statusCard.querySelector('p');

        if (tab && tab.url && tab.url.startsWith('http://')) {
            score -= 20;
            statusCard.className = 'status-card yellow';
            statusTitle.textContent = 'Insecure Connection';
            statusDesc.textContent = 'This site is not using HTTPS. Data transferred may be intercepted.';
        } else if (tab && tab.url && tab.url.startsWith('https://')) {
            statusCard.className = 'status-card green';
            statusTitle.textContent = 'Connection Secure';
            statusDesc.textContent = 'Data to this site is encrypted.';
        } else {
            statusCard.className = 'status-card';
            statusCard.style.borderLeft = '4px solid var(--border)';
            statusTitle.textContent = 'System Page';
            statusDesc.textContent = 'Security checks not applicable here.';
        }

        // 3. Settings Deductions
        if (result.settings) {
            if (!result.settings.enablePasswordCheck) score -= 5;
            if (!result.settings.enablePhishingCheck) score -= 15;
            if (!result.settings.enableTrackerBlocker) score -= 10;
            if (!result.settings.enableWebRTCProtect) score -= 5;
        }

        // 4. Security Header Grade deduction (async — get result before finalizing)
        let headerGradeDeduction = 0;
        try {
            if (tab && tab.id) {
                headerGradeDeduction = await new Promise((resolve) => {
                    chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: tab.id }, (hRes) => {
                        if (hRes && hRes.data && hRes.data.headers && typeof gradeSecurityHeaders === 'function') {
                            const { grade } = gradeSecurityHeaders(hRes.data.headers);
                            if (grade === 'F') resolve(15);
                            else if (grade === 'D') resolve(10);
                            else if (grade === 'C') resolve(5);
                            else resolve(0);
                        } else {
                            resolve(0);
                        }
                    });
                });
            }
        } catch (e) { /* header grading unavailable, no deduction */ }

        score -= headerGradeDeduction;

        // 5. Mixed content deduction
        try {
            if (tab && tab.id) {
                const mixedDeduction = await new Promise((resolve) => {
                    chrome.runtime.sendMessage({ type: 'GET_MIXED_CONTENT', tabId: tab.id }, (mRes) => {
                        if (mRes && mRes.data && mRes.data.items && mRes.data.items.length > 0) {
                            const hasActive = mRes.data.items.some(i => i.type === 'script' || i.type === 'iframe');
                            resolve(hasActive ? 15 : 5);
                        } else {
                            resolve(0);
                        }
                    });
                });
                score -= mixedDeduction;
            }
        } catch (e) { /* mixed content check unavailable */ }

        // 6. Threat log count and Trackers (only count last 24h, cap deduction)
        chrome.storage.local.get(['threatLog'], async (res) => {
            const tLog = res.threatLog || [];
            const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
            const recentThreats = tLog.filter(t => t.timestamp > oneDayAgo);
            threatsCount = recentThreats.length;
            document.getElementById('stat-threats').textContent = tLog.length;

            score -= Math.min(threatsCount * 5, 20); // -5 per recent threat, max -20

            // 7. Trackers blocked
            try {
                if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.getMatchedRules) {
                    const rules = await chrome.declarativeNetRequest.getMatchedRules();
                    const trackerCount = rules.rulesMatchedInfo ? rules.rulesMatchedInfo.length : 0;
                    document.getElementById('stat-trackers').textContent = trackerCount;
                }
            } catch (e) { }

            // Finalize score bounding
            if (score < 0) score = 0;
        });
    });
}
