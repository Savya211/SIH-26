/**
 * popup/components/cookies.js
 * UI Logic for the Cookies tab in the popup
 */

document.addEventListener('DOMContentLoaded', () => {
    const cookiesList = document.getElementById('cookies-list');
    const clearAllBtn = document.getElementById('clear-cookies-btn');

    // Load cookies when tab is clicked
    document.querySelector('[data-tab="cookies"]').addEventListener('click', loadCookiesForCurrentTab);

    // Clear all cookies
    clearAllBtn.addEventListener('click', async () => {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            chrome.runtime.sendMessage({ type: 'CLEAR_COOKIES', url: tab.url }, (response) => {
                if (response.success) {
                    loadCookiesForCurrentTab();
                    clearAllBtn.textContent = 'Cleared!';
                    setTimeout(() => clearAllBtn.textContent = 'Clear All Current Site Cookies', 2000);
                }
            });
        }
    });

    async function loadCookiesForCurrentTab() {
        cookiesList.innerHTML = '<p class="empty-state">Loading cookies...</p>';

        try {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

            if (!tab || !tab.url || tab.url.startsWith('chrome://')) {
                cookiesList.innerHTML = '<p class="empty-state">Cookies cannot be read on this page.</p>';
                return;
            }

            chrome.runtime.sendMessage({ type: 'GET_COOKIES', url: tab.url }, (response) => {
                if (chrome.runtime.lastError) {
                    cookiesList.innerHTML = `<p class="empty-state" style="color:var(--danger)">Error: ${chrome.runtime.lastError.message}</p>`;
                    return;
                }
                if (!response) {
                    cookiesList.innerHTML = '<p class="empty-state">Error: No response from background script.</p>';
                    return;
                }
                if (response.error) {
                    cookiesList.innerHTML = `<p class="empty-state" style="color:var(--danger)">Error: ${response.error}</p>`;
                    return;
                }
                if (!response.cookies || response.cookies.length === 0) {
                    cookiesList.innerHTML = '<p class="empty-state">No cookies found for this site.</p>';
                    return;
                }

                cookiesList.innerHTML = ''; // Clear

                response.cookies.forEach(cookie => {
                    const el = document.createElement('div');
                    el.className = 'cookie-item';
                    el.style.cssText = 'display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 13px;';

                    const info = document.createElement('div');
                    info.innerHTML = `<strong>${cookie.name}</strong><br><span style="color: var(--text-muted); font-size: 11px;">Domain: ${cookie.domain} | SameSite: ${cookie.sameSite || 'None'}</span>`;

                    const delBtn = document.createElement('button');
                    delBtn.innerHTML = '✖';
                    delBtn.style.cssText = 'background: none; border: none; color: var(--danger); cursor: pointer; font-size: 14px;';

                    delBtn.onclick = () => {
                        chrome.runtime.sendMessage({
                            type: 'DELETE_COOKIE',
                            url: tab.url,
                            name: cookie.name
                        }, () => {
                            el.remove();
                            if (cookiesList.children.length === 0) {
                                cookiesList.innerHTML = '<p class="empty-state">No cookies found for this site.</p>';
                            }
                        });
                    };

                    el.appendChild(info);
                    el.appendChild(delBtn);
                    cookiesList.appendChild(el);
                });
            });

        } catch (e) {
            cookiesList.innerHTML = '<p class="empty-state">Error loading cookies.</p>';
            console.error(e);
        }
    }
});
