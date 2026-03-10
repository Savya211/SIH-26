/**
 * popup/components/network.js
 * UI Logic for the Network tab — displays response headers
 */

document.addEventListener('DOMContentLoaded', () => {
    document.querySelector('[data-tab="network"]').addEventListener('click', loadNetworkInfo);
});

async function loadNetworkInfo() {
    const headersList = document.getElementById('headers-list');
    const headerStatus = document.getElementById('header-status');
    headersList.innerHTML = '<p class="empty-state">Loading headers...</p>';
    headerStatus.innerHTML = '';

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        headersList.innerHTML = '<p class="empty-state">Headers not available for this page.</p>';
        return;
    }

    // Load mixed content
    loadMixedContent(tab.id);

    chrome.runtime.sendMessage({ type: 'GET_HEADERS', tabId: tab.id }, (response) => {
        if (chrome.runtime.lastError) {
            headersList.innerHTML = '<p class="empty-state">Error loading headers.</p>';
            return;
        }
        if (!response || !response.data || !response.data.headers) {
            headersList.innerHTML = '<p class="empty-state">No headers captured. Try reloading the page.</p>';
            return;
        }

        const { statusCode, headers, url } = response.data;

        // Status line
        const statusColor = statusCode < 300 ? 'var(--success)' : statusCode < 400 ? 'var(--primary)' : 'var(--danger)';
        headerStatus.innerHTML = `<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
            <span style="font-weight:600;color:${statusColor};font-size:14px;">HTTP ${statusCode}</span>
            <span style="color:var(--text-muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${url}</span>
        </div>`;

        // Security Header Grade
        const gradeContainer = document.getElementById('security-grade');
        if (typeof gradeSecurityHeaders === 'function') {
            const gradeResult = gradeSecurityHeaders(headers);
            const gradeColors = { A: 'var(--success)', B: 'var(--success)', C: 'var(--warning)', D: 'var(--warning)', F: 'var(--danger)' };
            const gradeColor = gradeColors[gradeResult.grade] || 'var(--text-muted)';

            let gradeHtml = `<div style="display:flex;align-items:center;gap:16px;margin-bottom:12px;">
                <div class="grade-badge" style="background:${gradeColor};">${gradeResult.grade}</div>
                <div>
                    <div style="font-weight:600;font-size:14px;">Security Header Score: ${gradeResult.percentage}%</div>
                    <div style="color:var(--text-muted);font-size:12px;">${gradeResult.results.filter(r => r.present).length}/${gradeResult.results.length} headers present</div>
                </div>
            </div>`;

            gradeResult.results.forEach(r => {
                const icon = r.present ? '<span style="color:var(--success);">&#10003;</span>' : '<span style="color:var(--danger);">&#10007;</span>';
                gradeHtml += `<div class="header-check">
                    ${icon}
                    <div>
                        <span style="font-weight:500;">${r.label}</span>${r.critical ? ' <span style="color:var(--warning);font-size:10px;">CRITICAL</span>' : ''}
                        ${r.rec ? `<div style="font-size:11px;color:var(--text-muted);margin-top:2px;">${r.rec}</div>` : ''}
                    </div>
                </div>`;
            });

            gradeContainer.innerHTML = gradeHtml;
        }

        // Render raw headers
        headersList.innerHTML = '';
        headers.forEach(h => {
            const row = document.createElement('div');
            row.className = 'header-row';
            row.innerHTML = `<span class="header-name">${escapeHtml(h.name)}</span><span class="header-value">${escapeHtml(h.value)}</span>`;
            headersList.appendChild(row);
        });
    });
}

function loadMixedContent(tabId) {
    const container = document.getElementById('mixed-content-list');
    if (!container) return;
    container.innerHTML = '<p class="empty-state">Checking...</p>';

    chrome.runtime.sendMessage({ type: 'GET_MIXED_CONTENT', tabId }, (response) => {
        if (!response || !response.data || !response.data.items || response.data.items.length === 0) {
            container.innerHTML = '<p class="empty-state" style="color:var(--success);">No mixed content detected.</p>';
            return;
        }

        container.innerHTML = '';
        response.data.items.forEach(item => {
            const typeColors = { script: 'var(--danger)', iframe: 'var(--danger)', stylesheet: 'var(--warning)', image: 'var(--text-muted)', media: 'var(--text-muted)', object: 'var(--warning)' };
            const row = document.createElement('div');
            row.className = 'header-row';
            const truncUrl = item.url.length > 60 ? item.url.substring(0, 60) + '...' : item.url;
            row.innerHTML = `<span class="header-name" style="color:${typeColors[item.type] || 'var(--text-muted)'};">${item.type} &lt;${item.tag}&gt;</span><span class="header-value">${escapeHtml(truncUrl)}</span>`;
            container.appendChild(row);
        });
    });
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
