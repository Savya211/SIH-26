/**
 * dashboard.js — TheThirdEye Fullscreen Dashboard
 * Reads REAL data from chrome.storage.local (extension storage).
 * Must be opened as a chrome-extension:// page to access chrome APIs.
 */

(function () {
    'use strict';

    // ═══════════════════════════════════════════
    //  Check if we're inside the extension context
    // ═══════════════════════════════════════════
    const isExtension = typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local;

    // ═══════════════════════════════════════════
    //  Initialization
    // ═══════════════════════════════════════════
    document.addEventListener('DOMContentLoaded', async () => {
        initSidebarNav();

        if (!isExtension) {
            showNotExtensionWarning();
            return;
        }

        await populateDashboard();

        // Live-update: listen for storage changes
        chrome.storage.onChanged.addListener((changes, area) => {
            if (area === 'local') {
                populateDashboard();
            }
        });
    });

    // ═══════════════════════════════════════════
    //  Not-in-extension warning
    // ═══════════════════════════════════════════
    function showNotExtensionWarning() {
        const content = document.getElementById('dashboard-content');
        content.innerHTML = `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:60vh;text-align:center;gap:16px;">
                <div style="font-size:64px;">🛡️</div>
                <h2 style="font-size:24px;font-weight:700;">Extension Context Required</h2>
                <p style="color:#64748b;max-width:480px;line-height:1.7;">
                    This dashboard needs to be opened from the TheThirdEye extension to access your security data.<br><br>
                    Open it by clicking the <strong>"Open Dashboard"</strong> button in the extension popup, or navigate to:<br>
                    <code style="background:#1e293b;padding:4px 10px;border-radius:6px;font-size:13px;margin-top:8px;display:inline-block;">chrome-extension://&lt;your-extension-id&gt;/dashboard/index.html</code>
                </p>
            </div>
        `;
    }

    // ═══════════════════════════════════════════
    //  Sidebar Navigation
    // ═══════════════════════════════════════════
    function initSidebarNav() {
        const navItems = document.querySelectorAll('.nav-item[data-section]');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                navItems.forEach(n => n.classList.remove('active'));
                item.classList.add('active');

                // Switch content sections
                const sectionId = item.getAttribute('data-section');
                const allSections = document.querySelectorAll('.content-section');
                allSections.forEach(sec => sec.style.display = 'none');

                // Map nav sections to DOM IDs
                let targetId = 'section-overview';
                if (sectionId === 'threats') targetId = 'section-threats';
                else if (sectionId === 'settings') targetId = 'section-settings';
                else if (sectionId === 'help') targetId = 'section-help';

                const targetSec = document.getElementById(targetId);
                if (targetSec) targetSec.style.display = 'block';
            });
        });
    }

    // ═══════════════════════════════════════════
    //  Populate Dashboard from chrome.storage
    // ═══════════════════════════════════════════
    async function populateDashboard() {
        const data = await getStorageData(['breaches', 'threatLog', 'settings', 'insecureSites']);

        const breaches = data.breaches || [];
        const threatLog = data.threatLog || [];
        const settings = data.settings || {};

        // ── Compute Stats ──
        const totalThreats = threatLog.length;
        const totalBreaches = breaches.length;

        // Categorize threats by source keyword
        const phishingThreats = threatLog.filter(t =>
            (t.source || '').toLowerCase().includes('phish') ||
            (t.source || '').toLowerCase().includes('safe browsing') ||
            (t.source || '').toLowerCase().includes('social')
        ).length;

        const malwareThreats = threatLog.filter(t =>
            (t.source || '').toLowerCase().includes('malware') ||
            (t.source || '').toLowerCase().includes('threat database') ||
            (t.source || '').toLowerCase().includes('threat list') ||
            (t.source || '').toLowerCase().includes('blocklist')
        ).length;

        const heuristicThreats = threatLog.filter(t =>
            (t.source || '').toLowerCase().includes('heuristic') ||
            (t.source || '').toLowerCase().includes('ai')
        ).length;

        const otherThreats = totalThreats - phishingThreats - malwareThreats - heuristicThreats;

        // Risk percentages (relative to total, capped at 100)
        const trackerRisk = totalThreats > 0 ? Math.min(100, Math.round((malwareThreats / Math.max(totalThreats, 1)) * 100)) : 0;
        const phishingRisk = totalThreats > 0 ? Math.min(100, Math.round((phishingThreats / Math.max(totalThreats, 1)) * 100)) : 0;
        const breachRisk = Math.min(100, totalBreaches * 10); // 10% per breach
        const cookieRisk = (!settings.enableTrackerBlocker) ? 50 : 10; // Higher if tracker blocker is off

        // ── Risk Score (0–1000) ──
        let riskScore = 200; // base
        riskScore += totalThreats * 30;          // each threat adds 30
        riskScore += totalBreaches * 50;         // each breach adds 50
        riskScore += phishingThreats * 40;       // phishing is worse
        if (!settings.enablePhishingCheck) riskScore += 100;
        if (!settings.enableTrackerBlocker) riskScore += 80;
        if (!settings.enableWebRTCProtect) riskScore += 40;
        if (!settings.enablePasswordCheck) riskScore += 60;
        riskScore = Math.min(1000, Math.max(0, riskScore));

        // ── Get tracker count from declarativeNetRequest ──
        let trackerCount = 0;
        try {
            if (chrome.declarativeNetRequest && chrome.declarativeNetRequest.getMatchedRules) {
                const rules = await chrome.declarativeNetRequest.getMatchedRules();
                trackerCount = rules.rulesMatchedInfo ? rules.rulesMatchedInfo.length : 0;
            }
        } catch (e) { /* not available */ }

        // ── Render everything ──
        animateStatCounters({
            totalThreats: totalThreats,
            trackerRisk: trackerRisk,
            phishingRisk: phishingRisk,
            breachRisk: breachRisk,
            cookieRisk: cookieRisk
        });

        animateGauge(riskScore);

        // Monthly threats from threatLog timestamps
        const monthlyData = computeMonthlyThreats(threatLog);
        drawLineChart(monthlyData.labels, monthlyData.counts);

        // Donut chart sources
        const donutSources = [
            { label: 'Phishing', value: Math.max(phishingThreats, 0), color: '#a855f7' },
            { label: 'Malware', value: Math.max(malwareThreats, 0), color: '#f43f5e' },
            { label: 'Heuristic', value: Math.max(heuristicThreats, 0), color: '#3b82f6' },
            { label: 'Other', value: Math.max(otherThreats, 0), color: '#06b6d4' }
        ].filter(s => s.value > 0);

        if (donutSources.length > 0) {
            drawDonutChart(donutSources);
        } else {
            drawEmptyDonut();
        }

        // Threat details table from threatLog
        renderThreatTable(threatLog);

        // Breaches table from breaches data
        renderBreachesTable(breaches);

        // Domain list from threatLog (unique domains)
        renderDomainList(threatLog, breaches);
    }

    // ═══════════════════════════════════════════
    //  chrome.storage helper (promisified)
    // ═══════════════════════════════════════════
    function getStorageData(keys) {
        return new Promise((resolve) => {
            chrome.storage.local.get(keys, (result) => {
                resolve(result);
            });
        });
    }

    // ═══════════════════════════════════════════
    //  Compute monthly threats from timestamps
    // ═══════════════════════════════════════════
    function computeMonthlyThreats(threatLog) {
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        const counts = new Array(12).fill(0);

        const now = new Date();
        const currentYear = now.getFullYear();

        threatLog.forEach(t => {
            const d = new Date(t.timestamp);
            if (d.getFullYear() === currentYear) {
                counts[d.getMonth()]++;
            }
        });

        return { labels: monthNames, counts };
    }

    // ═══════════════════════════════════════════
    //  Animated Stat Counters
    // ═══════════════════════════════════════════
    function animateStatCounters(stats) {
        const mapping = {
            'stat-total-threats': stats.totalThreats,
            'stat-tracker-risk': stats.trackerRisk,
            'stat-phishing-risk': stats.phishingRisk,
            'stat-breach-risk': stats.breachRisk,
            'stat-cookie-risk': stats.cookieRisk
        };

        Object.entries(mapping).forEach(([id, target]) => {
            const el = document.querySelector(`#${id} .risk-stat-value`);
            if (!el) return;
            animateNumber(el, 0, target, 1200);
        });
    }

    function animateNumber(el, start, end, duration) {
        const startTime = performance.now();
        function tick(now) {
            const elapsed = now - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.round(start + (end - start) * ease);
            if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
    }

    // ═══════════════════════════════════════════
    //  Risk Score Gauge
    // ═══════════════════════════════════════════
    function animateGauge(score) {
        const gaugeValue = document.getElementById('gauge-value');
        const gaugeSeverity = document.getElementById('gauge-severity');

        animateNumber(gaugeValue, 0, score, 1500);

        let severity = 'Low';
        if (score > 700) severity = 'High';
        else if (score > 400) severity = 'Medium';

        setTimeout(() => {
            gaugeSeverity.textContent = severity;
            if (severity === 'High') {
                gaugeSeverity.style.background = 'rgba(244,63,94,.15)';
                gaugeSeverity.style.color = '#f43f5e';
            } else if (severity === 'Medium') {
                gaugeSeverity.style.background = 'rgba(249,115,22,.15)';
                gaugeSeverity.style.color = '#f97316';
            } else {
                gaugeSeverity.style.background = 'rgba(16,185,129,.15)';
                gaugeSeverity.style.color = '#10b981';
            }
        }, 400);
    }

    // ═══════════════════════════════════════════
    //  Line Chart — Threat Summary
    // ═══════════════════════════════════════════
    function drawLineChart(labels, data) {
        const canvas = document.getElementById('threat-summary-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const container = canvas.parentElement;

        const dpr = window.devicePixelRatio || 1;
        const rect = container.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.scale(dpr, dpr);
        const W = rect.width;
        const H = rect.height;

        // Clear
        ctx.clearRect(0, 0, W, H);

        const padLeft = 48, padRight = 20, padTop = 24, padBottom = 36;
        const chartW = W - padLeft - padRight;
        const chartH = H - padTop - padBottom;
        const maxVal = Math.max(...data, 1) * 1.25;

        // Y-axis labels
        ctx.font = '11px Inter, sans-serif';
        ctx.fillStyle = '#475569';
        ctx.textAlign = 'right';
        const ySteps = 5;
        for (let i = 0; i <= ySteps; i++) {
            const val = Math.round((maxVal / ySteps) * i);
            const y = padTop + chartH - (chartH / ySteps) * i;
            ctx.fillText(val, padLeft - 10, y + 4);
            ctx.strokeStyle = 'rgba(255,255,255,.04)';
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(padLeft, y);
            ctx.lineTo(W - padRight, y);
            ctx.stroke();
        }

        // X-axis labels
        ctx.textAlign = 'center';
        ctx.fillStyle = '#475569';
        const step = chartW / (labels.length - 1);
        labels.forEach((label, i) => {
            const x = padLeft + step * i;
            ctx.fillText(label, x, H - 10);
        });

        // If all data is 0, show "No data" message
        if (data.every(v => v === 0)) {
            ctx.fillStyle = '#475569';
            ctx.font = '14px Inter, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('No threat data recorded this year', W / 2, H / 2);
            return;
        }

        // Data points
        const points = data.map((val, i) => ({
            x: padLeft + step * i,
            y: padTop + chartH - (val / maxVal) * chartH
        }));

        // Gradient fill
        const grad = ctx.createLinearGradient(0, padTop, 0, padTop + chartH);
        grad.addColorStop(0, 'rgba(139,92,246,.3)');
        grad.addColorStop(1, 'rgba(139,92,246,0)');

        ctx.beginPath();
        ctx.moveTo(points[0].x, padTop + chartH);
        drawSmoothCurve(ctx, points);
        ctx.lineTo(points[points.length - 1].x, padTop + chartH);
        ctx.closePath();
        ctx.fillStyle = grad;
        ctx.fill();

        // Line
        ctx.beginPath();
        drawSmoothCurve(ctx, points);
        ctx.strokeStyle = '#8b5cf6';
        ctx.lineWidth = 2.5;
        ctx.stroke();

        // Dots
        points.forEach((p) => {
            ctx.beginPath();
            ctx.arc(p.x, p.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = '#8b5cf6';
            ctx.fill();
            ctx.strokeStyle = '#111827';
            ctx.lineWidth = 2;
            ctx.stroke();
        });

        // Tooltip interaction
        const tooltip = document.getElementById('chart-tooltip');
        canvas.addEventListener('mousemove', (e) => {
            const bRect = canvas.getBoundingClientRect();
            const mx = e.clientX - bRect.left;
            let closest = null, minDist = Infinity;
            points.forEach((p, i) => {
                const d = Math.abs(mx - p.x);
                if (d < minDist) { minDist = d; closest = i; }
            });
            if (closest !== null && minDist < 30) {
                tooltip.style.display = 'flex';
                tooltip.style.left = (points[closest].x - 40) + 'px';
                tooltip.style.top = (points[closest].y - 70) + 'px';
                tooltip.querySelector('.tooltip-month').textContent = labels[closest] + ' ' + new Date().getFullYear();
                tooltip.querySelector('.tooltip-value').textContent = data[closest];
            } else {
                tooltip.style.display = 'none';
            }
        });
        canvas.addEventListener('mouseleave', () => {
            tooltip.style.display = 'none';
        });
    }

    function drawSmoothCurve(ctx, points) {
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 0; i < points.length - 1; i++) {
            const cpx = (points[i].x + points[i + 1].x) / 2;
            ctx.quadraticCurveTo(points[i].x, points[i].y, cpx, (points[i].y + points[i + 1].y) / 2);
        }
        const last = points[points.length - 1];
        ctx.lineTo(last.x, last.y);
    }

    // ═══════════════════════════════════════════
    //  Donut Chart — Threats by Source
    // ═══════════════════════════════════════════
    function drawDonutChart(sources) {
        const canvas = document.getElementById('donut-chart');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        canvas.width = 180 * dpr;
        canvas.height = 180 * dpr;
        ctx.scale(dpr, dpr);

        const cx = 90, cy = 90, radius = 78, thickness = 22;
        const total = sources.reduce((s, d) => s + d.value, 0);
        const gap = 0.03;
        let startAngle = -Math.PI / 2;

        sources.forEach((src) => {
            const sliceAngle = (src.value / total) * (Math.PI * 2 - gap * sources.length);
            const endAngle = startAngle + sliceAngle;

            ctx.beginPath();
            ctx.arc(cx, cy, radius, startAngle, endAngle);
            ctx.arc(cx, cy, radius - thickness, endAngle, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = src.color;
            ctx.fill();

            startAngle = endAngle + gap;
        });

        // Legend
        const legend = document.getElementById('donut-legend');
        legend.innerHTML = '';
        sources.forEach(src => {
            const item = document.createElement('div');
            item.className = 'legend-item';
            item.innerHTML = `<span class="legend-dot" style="background:${src.color}"></span><span>${src.label} (${src.value})</span>`;
            legend.appendChild(item);
        });

        // Total label
        const topSource = sources.reduce((a, b) => a.value > b.value ? a : b);
        document.getElementById('donut-total').textContent = total > 0
            ? Math.round((topSource.value / total) * 100) + '%'
            : '0%';
    }

    function drawEmptyDonut() {
        const canvas = document.getElementById('donut-chart');
        if (!canvas) return;

        // Hide canvas entirely and show a clean empty state
        canvas.style.display = 'none';

        document.getElementById('donut-total').textContent = '';
        const legend = document.getElementById('donut-legend');
        legend.innerHTML = `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;padding:28px 0;text-align:center;">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#1e293b" stroke-width="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                </svg>
                <span style="color:#475569;font-size:13px;font-weight:500;">No threats recorded yet</span>
                <span style="color:#334155;font-size:11px;">Threats will appear here as they are detected</span>
            </div>`;
    }

    // ═══════════════════════════════════════════
    //  Threat Details Table (from real threatLog)
    // ═══════════════════════════════════════════
    function renderThreatTable(threatLog) {
        const tbody = document.getElementById('threat-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (threatLog.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#475569;padding:32px;">No threats detected yet. Browse the web and threats will appear here.</td></tr>';
            return;
        }

        // Show newest first, max 20
        const sorted = [...threatLog].sort((a, b) => b.timestamp - a.timestamp).slice(0, 20);

        sorted.forEach(threat => {
            const date = new Date(threat.timestamp).toLocaleDateString();
            let domain = 'Unknown';
            try { domain = new URL(threat.url).hostname; } catch (e) { domain = threat.url; }

            // Determine threat type from source
            let type = 'Unknown';
            const src = (threat.source || '').toLowerCase();
            if (src.includes('phish') || src.includes('safe browsing')) type = 'Phishing';
            else if (src.includes('malware') || src.includes('threat') || src.includes('blocklist')) type = 'Malware';
            else if (src.includes('heuristic')) type = 'Suspicious';
            else if (src.includes('ai')) type = 'AI Flagged';
            else if (src.includes('homoglyph') || src.includes('security manager')) type = 'Homoglyph';
            else type = 'Blocked';

            // Severity based on source
            let severity = 'medium';
            if (src.includes('threat list') || src.includes('threat database') || src.includes('blocklist') || src.includes('malware')) severity = 'high';
            else if (src.includes('heuristic') || src.includes('ai')) severity = 'medium';
            else if (src.includes('safe browsing') || src.includes('phish')) severity = 'high';

            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${date}</td>
                <td style="font-weight:600;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${domain}">${domain}</td>
                <td>${type}</td>
                <td>${threat.source || 'Security Manager'}</td>
                <td><span class="severity-badge severity-${severity}">${severity}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ═══════════════════════════════════════════
    //  Breaches Table
    // ═══════════════════════════════════════════
    function renderBreachesTable(breaches) {
        const tbody = document.getElementById('breaches-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!breaches || breaches.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#475569;padding:32px;">No breaches detected. Your passwords appear safe.</td></tr>';
            return;
        }

        breaches.forEach(breach => {
            const date = new Date(breach.timestamp || Date.now()).toLocaleDateString();
            const domain = breach.domain || breach.url || 'Unknown';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${date}</td>
                <td style="font-weight:600;">${domain}</td>
                <td><span class="severity-badge severity-high">HaveIBeenPwned Match</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // ═══════════════════════════════════════════
    //  Threat by Domain List (from real data)
    // ═══════════════════════════════════════════
    function renderDomainList(threatLog, breaches) {
        const list = document.getElementById('domain-list');
        if (!list) return;
        list.innerHTML = '';

        // Collect unique domains from threats + breaches
        const domainMap = new Map();

        threatLog.forEach(t => {
            let domain = '';
            try { domain = new URL(t.url).hostname; } catch (e) { domain = t.url; }
            if (!domainMap.has(domain)) {
                domainMap.set(domain, { name: domain, type: 'threat', source: t.source });
            }
        });

        breaches.forEach(b => {
            let domain = '';
            try { domain = new URL(b.url).hostname; } catch (e) { domain = b.url; }
            if (!domainMap.has(domain)) {
                domainMap.set(domain, { name: domain, type: 'breach', count: b.count });
            }
        });

        if (domainMap.size === 0) {
            list.innerHTML = '<div style="color:#475569;font-size:13px;text-align:center;padding:24px;">No domains flagged yet</div>';
            return;
        }

        // Show up to 8
        const domains = [...domainMap.values()].slice(0, 8);

        const colors = ['#f43f5e', '#f97316', '#3b82f6', '#06b6d4', '#a855f7', '#10b981', '#eab308', '#ec4899'];
        const emojis = ['🔴', '🟠', '🔵', '🟢', '🟣', '🟡', '🔶', '🟤'];

        domains.forEach((d, i) => {
            const color = colors[i % colors.length];
            const emoji = emojis[i % emojis.length];
            const labelText = d.type === 'breach' ? 'Breached Domain' : 'Threat Domain';

            const item = document.createElement('div');
            item.className = 'domain-item';
            item.innerHTML = `
                <div class="domain-avatar" style="background: ${color}22; color: ${color};">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
                </div>
                <div class="domain-info">
                    <span class="domain-label">${labelText}</span>
                    <span class="domain-name" title="${d.name}">${d.name}</span>
                </div>
                <div class="domain-risk-icon" style="background: ${color}18;">
                    <span style="font-size:16px;">${emoji}</span>
                </div>
            `;
            list.appendChild(item);
        });
    }

    // ═══════════════════════════════════════════
    //  Window resize => redraw charts
    // ═══════════════════════════════════════════
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            if (isExtension) populateDashboard();
        }, 200);
    });

})();
