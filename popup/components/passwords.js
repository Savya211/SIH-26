/**
 * popup/components/passwords.js
 * Logic for the Passwords tab
 */

document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('[data-tab="passwords"]').addEventListener('click', loadPasswords);
});

function loadPasswords() {
    const list = document.getElementById('passwords-list');

    chrome.storage.local.get(['breaches'], (result) => {
        if (!result.breaches || result.breaches.length === 0) {
            list.innerHTML = '<p class="empty-state">No breached passwords detected yet. Keep browsing securely!</p>';
            return;
        }

        list.innerHTML = '';

        result.breaches.forEach((breach, index) => {
            const el = document.createElement('div');
            el.className = 'breach-item';
            el.style.cssText = 'padding: 10px; border-bottom: 1px solid var(--border);';

            const date = new Date(breach.timestamp).toLocaleDateString();

            el.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                    <strong style="color: var(--danger); font-size: 14px;">${breach.url}</strong>
                    <span style="font-size: 11px; color: var(--text-muted);">${date}</span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted);">
                    Found in <strong style="color: white;">${breach.count.toLocaleString()}</strong> data breaches.
                </div>
            `;
            list.appendChild(el);
        });

        // Add clear button
        const clearBtn = document.createElement('button');
        clearBtn.textContent = 'Clear Log';
        clearBtn.className = 'danger-btn mt-10';
        clearBtn.onclick = () => {
            chrome.storage.local.set({ breaches: [] }, loadPasswords);
            // Refresh overall score if dashboard is open
            if (typeof updateDashboard === 'function') updateDashboard();
        };
        list.appendChild(clearBtn);
    });
}
