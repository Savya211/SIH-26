/**
 * popup/components/threats.js
 * Logic for the Threats tab
 */

document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('[data-tab="threats"]').addEventListener('click', loadThreats);
});

function loadThreats() {
    const list = document.getElementById('threats-list');
    if (!list) return;

    chrome.storage.local.get(['threatLog'], (result) => {
        if (!result.threatLog || result.threatLog.length === 0) {
            list.innerHTML = '<p class="empty-state">No threats detected.</p>';
            return;
        }

        list.innerHTML = '';

        // Reverse array to show newest first
        const threats = [...result.threatLog].reverse();

        threats.forEach((threat) => {
            const el = document.createElement('div');
            el.className = 'threat-item';
            el.style.cssText = 'padding: 10px; border-bottom: 1px solid var(--border);';

            const date = new Date(threat.timestamp).toLocaleString();

            el.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                    <strong style="color: var(--danger); font-size: 13px; word-break: break-all; padding-right: 10px;">${threat.url}</strong>
                    <span style="font-size: 10px; color: var(--text-muted); white-space: nowrap;">${date}</span>
                </div>
                <div style="font-size: 12px; color: var(--text-muted);">
                    Blocked by: <strong style="color: var(--warning);">${threat.source || 'Security Manager'}</strong>
                </div>
            `;
            list.appendChild(el);
        });

        // Add clear button
        const clearBtn = document.createElement('button');
        clearBtn.textContent = 'Clear Log';
        clearBtn.className = 'danger-btn mt-10';
        clearBtn.onclick = () => {
            chrome.storage.local.set({ threatLog: [] }, loadThreats);
            // Refresh overall score if dashboard is open
            if (typeof updateDashboard === 'function') updateDashboard();
        };
        list.appendChild(clearBtn);
    });
}
