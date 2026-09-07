/**
 * app.js — AegisMail Analyst Dashboard Application
 * 
 * Core logic for the Email Forensic Intelligence Dashboard:
 *   - File upload with drag-and-drop
 *   - API communication with forensic engine
 *   - Dynamic rendering of all analysis panels
 *   - Animated risk score dial
 *   - Case history via localStorage
 */

// ═══════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════

const API_BASE = 'http://localhost:5001';
let currentAnalysis = null;


// ═══════════════════════════════════════════════
//  Initialization
// ═══════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initDropzone();
    initThemeToggle();
    checkEngineStatus();
    updateStatCards();
});


// ═══════════════════════════════════════════════
//  Theme Toggle
// ═══════════════════════════════════════════════

function initThemeToggle() {
    const root = document.documentElement;
    const toggle = document.getElementById('theme-toggle');
    const saved = localStorage.getItem('aegismail_theme');

    if (saved) {
        root.setAttribute('data-theme', saved);
    }

    if (toggle) {
        toggle.addEventListener('click', () => {
            const next = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            root.setAttribute('data-theme', next);
            localStorage.setItem('aegismail_theme', next);
        });
    }
}


// ═══════════════════════════════════════════════
//  Navigation
// ═══════════════════════════════════════════════

const panelTitles = {
    upload: { title: 'Upload & Analyze', subtitle: 'Drop an .eml file to begin forensic analysis' },
    results: { title: 'Analysis Report', subtitle: 'Comprehensive threat assessment results' },
    map: { title: 'GeoTrace Map', subtitle: 'Hop-by-hop email relay visualization' },
    headers: { title: 'Header Inspector', subtitle: 'RFC 822 header forensic breakdown' },
    cases: { title: 'Case History', subtitle: 'Previously analyzed email cases' },
    threatintel: { title: 'Threat Intelligence', subtitle: 'Recurring threat indicators across analyzed cases' },
    finalreport: { title: 'Final Report', subtitle: 'Complete investigation report for the current case' },
};

function initNavigation() {
    document.querySelectorAll('.nav-item[data-panel]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const panelId = item.getAttribute('data-panel');
            switchPanel(panelId);
        });
    });
}

function switchPanel(panelId) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navItem = document.querySelector(`.nav-item[data-panel="${panelId}"]`);
    if (navItem) navItem.classList.add('active');

    // Update panels
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    const panel = document.getElementById(`panel-${panelId}`);
    if (panel) panel.classList.add('active');

    // Update title
    const info = panelTitles[panelId] || {};
    document.getElementById('page-title').textContent = info.title || '';
    document.getElementById('page-subtitle').textContent = info.subtitle || '';

    // Initialize map when switching to map panel
    if (panelId === 'map') {
        setTimeout(() => {
            initMap();
            if (geoMap) geoMap.invalidateSize();
        }, 100);
    }

    // Load cases when switching to cases panel
    if (panelId === 'cases') {
        loadCases();
    }

    // Load threat intel when switching to threatintel panel
    if (panelId === 'threatintel') {
        loadThreatIntel();
    }

    // Render final report when switching to finalreport panel
    if (panelId === 'finalreport') {
        renderFinalReport();
    }
}


// ═══════════════════════════════════════════════
//  Engine Health Check
// ═══════════════════════════════════════════════

async function checkEngineStatus() {
    const pill = document.getElementById('engine-status');
    try {
        const resp = await fetch(`${API_BASE}/api/health`, { signal: AbortSignal.timeout(3000) });
        if (resp.ok) {
            pill.innerHTML = '<span class="status-dot"></span><span>Engine Online</span>';
            pill.style.background = 'rgba(34, 197, 94, 0.1)';
            pill.style.borderColor = 'rgba(34, 197, 94, 0.2)';
            pill.style.color = '#22c55e';
        } else {
            throw new Error('Not OK');
        }
    } catch {
        pill.innerHTML = '<span class="status-dot" style="background:#ef4444;"></span><span>Engine Offline</span>';
        pill.style.background = 'rgba(239, 68, 68, 0.1)';
        pill.style.borderColor = 'rgba(239, 68, 68, 0.2)';
        pill.style.color = '#ef4444';
    }
}


// ═══════════════════════════════════════════════
//  File Upload & Drag-Drop
// ═══════════════════════════════════════════════

function initDropzone() {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');

    // Click to browse
    dropzone.addEventListener('click', () => fileInput.click());

    // File selected via browse
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            analyzeFile(e.target.files[0]);
        }
    });

    // Drag events
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('drag-over');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('drag-over');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            analyzeFile(e.dataTransfer.files[0]);
        }
    });
}


// ═══════════════════════════════════════════════
//  Analysis Pipeline
// ═══════════════════════════════════════════════

async function analyzeFile(file) {
    showAnalyzingState();

    const formData = new FormData();
    formData.append('file', file);

    try {
        updateAnalyzingStage('Uploading .eml file...');
        const resp = await fetch(`${API_BASE}/api/analyze-eml`, {
            method: 'POST',
            body: formData,
        });

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Server error: ${resp.status}`);
        }

        const data = await resp.json();
        currentAnalysis = data;

        updateAnalyzingStage('Rendering results...');
        await new Promise(r => setTimeout(r, 300));

        renderResults(data);
        saveCaseToStats(data);
        hideAnalyzingState();
        switchPanel('results');

    } catch (err) {
        hideAnalyzingState();
        alert(`Analysis failed: ${err.message}\n\nMake sure the forensic engine is running:\n  cd forensic-engine && python main.py`);
    }
}


async function analyzeDemoEmail(filename) {
    showAnalyzingState();

    try {
        updateAnalyzingStage(`Loading ${filename}...`);
        const resp = await fetch(`${API_BASE}/api/analyze-demo/${filename}`, {
            method: 'POST',
        });

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Server error: ${resp.status}`);
        }

        const data = await resp.json();
        currentAnalysis = data;

        updateAnalyzingStage('Rendering results...');
        await new Promise(r => setTimeout(r, 300));

        renderResults(data);
        saveCaseToStats(data);
        hideAnalyzingState();
        switchPanel('results');

    } catch (err) {
        hideAnalyzingState();
        alert(`Demo analysis failed: ${err.message}\n\nMake sure the forensic engine is running:\n  cd forensic-engine && python main.py`);
    }
}


function showAnalyzingState() {
    document.querySelector('.dropzone-content').style.display = 'none';
    document.getElementById('dropzone-analyzing').style.display = 'flex';
    document.getElementById('dropzone-analyzing').style.flexDirection = 'column';
    document.getElementById('dropzone-analyzing').style.alignItems = 'center';
}

function hideAnalyzingState() {
    document.querySelector('.dropzone-content').style.display = 'block';
    document.getElementById('dropzone-analyzing').style.display = 'none';
}

function updateAnalyzingStage(text) {
    document.getElementById('analyzing-stage').textContent = text;
}


// ═══════════════════════════════════════════════
//  Render Results
// ═══════════════════════════════════════════════

function renderResults(data) {
    renderRiskDial(data.risk);
    renderSubScores(data.risk.sub_scores);
    renderEmailSummary(data);
    renderIndicators(data.risk.indicators);
    renderNLPAnalysis(data.nlp_analysis);
    renderURLAnalysis(data.url_analysis);
    renderAuthCards(data.authentication);
    renderHeadersTable(data.headers);

    // Map
    if (data.geolocation && data.geolocation.hop_path) {
        renderHopPath(data.geolocation.hop_path);
        renderHopList(data.geolocation.hop_path);
    }
}


// ─── Risk Dial ───

function renderRiskDial(risk) {
    const score = risk.threat_score;
    const verdict = risk.verdict;
    const color = risk.verdict_color;

    // Animate score number
    const scoreEl = document.getElementById('risk-score-value');
    animateNumber(scoreEl, 0, score, 1500);

    // Animate arc
    const arc = document.getElementById('risk-dial-arc');
    const circumference = 2 * Math.PI * 85; // ~534
    const offset = circumference - (score / 100) * circumference;

    // Set gradient based on verdict
    let gradId = 'dial-green';
    if (score >= 70) gradId = 'dial-red';
    else if (score >= 40) gradId = 'dial-orange';
    arc.setAttribute('stroke', `url(#${gradId})`);

    setTimeout(() => {
        arc.style.transition = 'stroke-dashoffset 1.5s cubic-bezier(0.4, 0, 0.2, 1)';
        arc.setAttribute('stroke-dashoffset', offset);
    }, 100);

    // Verdict badge
    const verdictEl = document.getElementById('risk-verdict');
    verdictEl.textContent = verdict;
    verdictEl.style.background = `${color}22`;
    verdictEl.style.color = color;

    // Meta
    document.getElementById('risk-confidence').textContent = `${Math.round(risk.confidence * 100)}%`;
    const pt = currentAnalysis ? currentAnalysis.processing_time_seconds : 0;
    document.getElementById('risk-time').textContent = `${(pt * 1000).toFixed(0)}ms`;
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


// ─── Sub Scores ───

function renderSubScores(subScores) {
    const container = document.getElementById('sub-scores-list');
    const items = [
        { label: 'Authentication', key: 'authentication', color: '#ef4444' },
        { label: 'NLP Content', key: 'nlp_content', color: '#a855f7' },
        { label: 'URL Heuristics', key: 'url_heuristics', color: '#f97316' },
        { label: 'Geographic', key: 'geographic', color: '#06b6d4' },
        { label: 'Attachments', key: 'attachments', color: '#3b82f6' },
    ];

    container.innerHTML = items.map(item => {
        const value = Math.round(subScores[item.key] || 0);
        return `
            <div class="sub-score-item">
                <span class="sub-score-label">${item.label}</span>
                <div class="sub-score-bar">
                    <div class="sub-score-fill" style="width: 0%; background: ${item.color};" data-target="${value}"></div>
                </div>
                <span class="sub-score-value">${value}</span>
            </div>
        `;
    }).join('');

    // Animate bars
    setTimeout(() => {
        container.querySelectorAll('.sub-score-fill').forEach(fill => {
            fill.style.width = `${fill.dataset.target}%`;
        });
    }, 200);
}


// ─── Email Summary ───

function renderEmailSummary(data) {
    const container = document.getElementById('summary-fields');
    const h = data.headers || {};
    const fields = [
        { label: 'From', value: h.sender?.full || 'N/A' },
        { label: 'To', value: h.to || 'N/A' },
        { label: 'Reply-To', value: h.reply_to?.full || '—' },
        { label: 'Subject', value: h.subject || 'N/A' },
        { label: 'Date', value: h.date?.raw || 'N/A' },
        { label: 'Hops', value: `${h.total_hops || 0} relay servers` },
        { label: 'Case ID', value: data.case_id || 'N/A' },
    ];

    container.innerHTML = fields.map(f => `
        <div class="summary-field">
            <span class="summary-field-label">${f.label}</span>
            <span class="summary-field-value">${escapeHtml(f.value)}</span>
        </div>
    `).join('');
}


// ─── Threat Indicators ───

function renderIndicators(indicators) {
    const container = document.getElementById('indicators-list');

    if (!indicators || indicators.length === 0) {
        container.innerHTML = '<p class="empty-state">No threat indicators detected — email appears safe</p>';
        return;
    }

    container.innerHTML = indicators.map(ind => `
        <div class="indicator-item severity-${ind.severity}">
            <span class="indicator-badge ${ind.severity}">${ind.severity}</span>
            <span class="indicator-category">${ind.category}</span>
            <span class="indicator-message">${escapeHtml(ind.message)}</span>
        </div>
    `).join('');
}


// ─── NLP Analysis ───

function renderNLPAnalysis(nlp) {
    if (!nlp) return;

    // Category scores
    const catContainer = document.getElementById('nlp-categories');
    const categories = [
        { label: 'Urgency', score: nlp.urgency_score, color: '#ef4444' },
        { label: 'Credential', score: nlp.credential_score, color: '#f97316' },
        { label: 'Financial', score: nlp.financial_score, color: '#a855f7' },
        { label: 'Impersonation', score: nlp.impersonation_score, color: '#3b82f6' },
        { label: 'Social Eng.', score: nlp.social_engineering_score, color: '#06b6d4' },
    ];

    catContainer.innerHTML = categories.map(cat => {
        const pct = Math.round((cat.score || 0) * 100);
        const color = pct >= 50 ? cat.color : 'var(--text-muted)';
        return `
            <div class="nlp-category">
                <span class="nlp-cat-score" style="color: ${color}">${pct}%</span>
                <span class="nlp-cat-label">${cat.label}</span>
            </div>
        `;
    }).join('');

    // Flagged keywords
    const kwContainer = document.getElementById('nlp-keywords');
    if (nlp.flagged_keywords && nlp.flagged_keywords.length > 0) {
        kwContainer.innerHTML = nlp.flagged_keywords.map(kw =>
            `<span class="nlp-keyword" title="${escapeHtml(kw.context || '')}">${escapeHtml(kw.keyword)}</span>`
        ).join('');
    } else {
        kwContainer.innerHTML = '<p class="empty-state" style="padding: 12px;">No suspicious keywords detected</p>';
    }
}


// ─── URL Analysis ───

function renderURLAnalysis(urlData) {
    const container = document.getElementById('urls-table-wrapper');

    if (!urlData || !urlData.analyzed_urls || urlData.analyzed_urls.length === 0) {
        container.innerHTML = '<p class="empty-state">No URLs found in email body</p>';
        return;
    }

    const rows = urlData.analyzed_urls.map(url => {
        const risk = url.risk_score || 0;
        let badgeClass = 'safe';
        let badgeText = 'Safe';
        if (risk >= 0.5) { badgeClass = 'danger'; badgeText = 'Dangerous'; }
        else if (risk >= 0.2) { badgeClass = 'warning'; badgeText = 'Suspicious'; }

        const findings = (url.findings || []).map(f => f.detail).join('; ');

        return `
            <tr>
                <td class="url-cell" title="${escapeHtml(url.url)}">${escapeHtml(url.url)}</td>
                <td><span class="url-risk-badge ${badgeClass}">${badgeText}</span></td>
                <td>${Math.round(risk * 100)}%</td>
                <td style="font-size:11px; color: var(--text-muted);">${escapeHtml(findings || 'None')}</td>
            </tr>
        `;
    }).join('');

    container.innerHTML = `
        <table class="urls-table">
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}


// ─── Auth Cards ───

function renderAuthCards(auth) {
    const container = document.getElementById('auth-cards');
    if (!auth) {
        container.innerHTML = '';
        return;
    }

    const protocols = [
        { name: 'SPF', data: auth.spf, icon: '🔐' },
        { name: 'DKIM', data: auth.dkim, icon: '✍️' },
        { name: 'DMARC', data: auth.dmarc, icon: '🛡️' },
    ];

    container.innerHTML = protocols.map(p => {
        const status = p.data?.status || 'unknown';
        const stateClass = p.data?.pass === true ? 'pass' : p.data?.pass === false ? 'fail' : 'unknown';
        const statusText = status.charAt(0).toUpperCase() + status.slice(1);

        return `
            <div class="auth-card ${stateClass}">
                <div class="auth-card-icon">${p.icon}</div>
                <div class="auth-card-title">${p.name}</div>
                <div class="auth-card-status">${statusText}</div>
                ${p.data?.detail ? `<p style="font-size:11px; color: var(--text-muted); margin-top: 8px;">${escapeHtml(p.data.detail)}</p>` : ''}
            </div>
        `;
    }).join('');
}


// ─── Headers Table ───

function renderHeadersTable(headers) {
    const container = document.getElementById('headers-table-wrapper');
    if (!headers || !headers.received_hops || headers.received_hops.length === 0) {
        container.innerHTML = '<p class="empty-state">No Received headers parsed</p>';
        return;
    }

    const rows = headers.received_hops.map(hop => `
        <tr>
            <td style="font-weight: 600; color: var(--accent-purple);">Hop ${hop.hop_index}</td>
            <td>${escapeHtml(hop.from_hostname || '—')}</td>
            <td><code>${hop.from_ip || '—'}</code></td>
            <td>${escapeHtml(hop.by_hostname || '—')}</td>
            <td>${hop.timestamp || '—'}</td>
        </tr>
    `).join('');

    container.innerHTML = `
        <table class="headers-table">
            <thead>
                <tr>
                    <th>Hop</th>
                    <th>From Host</th>
                    <th>IP</th>
                    <th>By Host</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}


// ─── Cases ───

async function loadCases() {
    const container = document.getElementById('cases-list');

    try {
        const resp = await fetch(`${API_BASE}/api/cases`);
        if (!resp.ok) throw new Error();
        const data = await resp.json();

        if (!data.cases || data.cases.length === 0) {
            container.innerHTML = '<p class="empty-state">No cases analyzed yet. Upload an email to get started.</p>';
            return;
        }

        container.innerHTML = data.cases.map(c => {
            const color = c.verdict === 'MALICIOUS' ? '#ef4444' : c.verdict === 'SUSPICIOUS' ? '#f97316' : '#22c55e';
            return `
                <div class="case-item" onclick="loadCase('${c.case_id}')">
                    <div class="case-verdict-dot" style="background: ${color};"></div>
                    <div class="case-info">
                        <div class="case-subject">${escapeHtml(c.subject || 'No Subject')}</div>
                        <div class="case-sender">${escapeHtml(c.sender || 'Unknown Sender')}</div>
                    </div>
                    <div class="case-meta">
                        <div class="case-score" style="color: ${color};">${c.threat_score}</div>
                        <div class="case-time">${c.filename || ''}</div>
                    </div>
                </div>
            `;
        }).join('');

    } catch {
        container.innerHTML = '<p class="empty-state">Unable to load cases. Is the engine running?</p>';
    }
}

async function loadCase(caseId) {
    try {
        const resp = await fetch(`${API_BASE}/api/cases/${caseId}`);
        if (!resp.ok) throw new Error();
        const data = await resp.json();
        currentAnalysis = data;
        renderResults(data);
        switchPanel('results');
    } catch {
        alert('Failed to load case');
    }
}


// ═══════════════════════════════════════════════
// Statistics Cards
// ═══════════════════════════════════════════════

function getStats() {
    try {
        return JSON.parse(
            localStorage.getItem('aegismail_stats') ||
            '{"emails":0,"threats":0,"cases":0,"highrisk":0}'
        );
    } catch {
        return {
            emails: 0,
            threats: 0,
            cases: 0,
            highrisk: 0
        };
    }
}

function updateStatCards() {
    const stats = getStats();

    document.getElementById('stat-emails').textContent = stats.emails;
    document.getElementById('stat-threats').textContent = stats.threats;
    document.getElementById('stat-cases').textContent = stats.cases;
    document.getElementById('stat-highrisk').textContent = stats.highrisk;
}

function saveCaseToStats(data) {
    const stats = getStats();

    stats.emails += 1;
    stats.cases += 1;

    const verdict = String(data?.risk?.verdict || '').toUpperCase();
    const score = Number(data?.risk?.threat_score || 0);

    if (verdict === 'MALICIOUS' || verdict === 'SUSPICIOUS') {
        stats.threats += 1;
    }

    if (score >= 70) {
        stats.highrisk += 1;
    }

    localStorage.setItem(
        'aegismail_stats',
        JSON.stringify(stats)
    );

    updateStatCards();
}

// ═══════════════════════════════════════════════
//  Threat Intelligence
// ═══════════════════════════════════════════════

async function loadThreatIntel() {
    const domainsEl = document.getElementById('threatintel-domains');
    const sendersEl = document.getElementById('threatintel-senders');
    const ipsEl = document.getElementById('threatintel-ips');
    const warningEl = document.getElementById('threatintel-warning');

    domainsEl.innerHTML = '<p class="empty-state">Loading case data…</p>';
    sendersEl.innerHTML = '';
    ipsEl.innerHTML = '';
    warningEl.style.display = 'none';

    try {
        // Step 1: Get case list
        const listResp = await fetch(`${API_BASE}/api/cases`);
        if (!listResp.ok) throw new Error('Cannot reach engine');
        const listData = await listResp.json();
        const caseSummaries = listData.cases || [];

        if (caseSummaries.length === 0) {
            domainsEl.innerHTML = '<p class="empty-state">No cases analyzed yet. Upload emails to build threat intelligence.</p>';
            sendersEl.innerHTML = '<p class="empty-state">No data</p>';
            ipsEl.innerHTML = '<p class="empty-state">No data</p>';
            return;
        }

        // Step 2: Fetch full case data for each case
        const casePromises = caseSummaries.map(c =>
            fetch(`${API_BASE}/api/cases/${c.case_id}`)
                .then(r => r.ok ? r.json() : null)
                .catch(() => null)
        );
        const fullCases = (await Promise.all(casePromises)).filter(Boolean);

        // Step 3: Aggregate indicators across cases
        const domainCounts = {};  // domain -> { count, cases Set }
        const senderCounts = {};  // email -> { count, cases Set }
        const ipCounts = {};      // ip -> { count, cases Set }

        const isPrivateIP = (ip) => {
            return /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip);
        };

        for (const c of fullCases) {
            const caseId = c.case_id || '';
            const headers = c.headers || {};
            const urlAnalysis = c.url_analysis || {};

            // Sender domain
            const senderDomain = headers.sender?.domain;
            if (senderDomain) {
                if (!domainCounts[senderDomain]) domainCounts[senderDomain] = { count: 0, cases: new Set() };
                domainCounts[senderDomain].count++;
                domainCounts[senderDomain].cases.add(caseId);
            }

            // Reply-to domain
            const replyDomain = headers.reply_to?.domain;
            if (replyDomain && replyDomain !== senderDomain) {
                if (!domainCounts[replyDomain]) domainCounts[replyDomain] = { count: 0, cases: new Set() };
                domainCounts[replyDomain].count++;
                domainCounts[replyDomain].cases.add(caseId);
            }

            // Return-path domain
            const returnDomain = headers.return_path?.domain;
            if (returnDomain && returnDomain !== senderDomain && returnDomain !== replyDomain) {
                if (!domainCounts[returnDomain]) domainCounts[returnDomain] = { count: 0, cases: new Set() };
                domainCounts[returnDomain].count++;
                domainCounts[returnDomain].cases.add(caseId);
            }

            // Domains from analyzed URLs
            const urls = urlAnalysis.analyzed_urls || [];
            for (const u of urls) {
                if (u.risk_score >= 0.2) {
                    try {
                        const urlDomain = new URL(u.url).hostname;
                        if (urlDomain && !isPrivateIP(urlDomain)) {
                            if (!domainCounts[urlDomain]) domainCounts[urlDomain] = { count: 0, cases: new Set() };
                            domainCounts[urlDomain].count++;
                            domainCounts[urlDomain].cases.add(caseId);
                        }
                    } catch { /* invalid URL */ }
                }
            }

            // Sender email
            const senderFull = headers.sender?.full;
            if (senderFull) {
                if (!senderCounts[senderFull]) senderCounts[senderFull] = { count: 0, cases: new Set() };
                senderCounts[senderFull].count++;
                senderCounts[senderFull].cases.add(caseId);
            }

            // Reply-to email
            const replyFull = headers.reply_to?.full;
            if (replyFull && replyFull !== senderFull) {
                if (!senderCounts[replyFull]) senderCounts[replyFull] = { count: 0, cases: new Set() };
                senderCounts[replyFull].count++;
                senderCounts[replyFull].cases.add(caseId);
            }

            // IPs from hops (skip private)
            const allIPs = headers.all_ips || [];
            for (const ip of allIPs) {
                if (!isPrivateIP(ip)) {
                    if (!ipCounts[ip]) ipCounts[ip] = { count: 0, cases: new Set() };
                    ipCounts[ip].count++;
                    ipCounts[ip].cases.add(caseId);
                }
            }
        }

        // Step 4: Check if any recurring indicators exist
        const hasRecurring = (obj) => Object.values(obj).some(v => v.cases.size >= 2);
        if (hasRecurring(domainCounts) || hasRecurring(senderCounts) || hasRecurring(ipCounts)) {
            warningEl.style.display = 'flex';
            warningEl.className = 'threatintel-warning';
            warningEl.innerHTML = `
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                Recurring Attack Detected — Threat indicators observed across multiple analyzed cases
            `;
        }

        // Step 5: Render tables
        domainsEl.innerHTML = renderThreatIntelTable(domainCounts, 'Domain');
        sendersEl.innerHTML = renderThreatIntelTable(senderCounts, 'Sender');
        ipsEl.innerHTML = renderThreatIntelTable(ipCounts, 'IP Address');

    } catch {
        domainsEl.innerHTML = '<p class="empty-state">Unable to load threat data. Is the engine running?</p>';
        sendersEl.innerHTML = '<p class="empty-state">Engine offline</p>';
        ipsEl.innerHTML = '<p class="empty-state">Engine offline</p>';
    }
}

function renderThreatIntelTable(countsObj, label) {
    const entries = Object.entries(countsObj)
        .map(([key, val]) => ({ indicator: key, count: val.count, uniqueCases: val.cases.size }))
        .sort((a, b) => b.uniqueCases - a.uniqueCases || b.count - a.count);

    if (entries.length === 0) {
        return `<p class="empty-state">No ${label.toLowerCase()} indicators found</p>`;
    }

    const rows = entries.map(e => {
        const badge = e.uniqueCases >= 2
            ? '<span class="ti-recurring-badge">Recurring</span>'
            : '';
        return `
            <tr>
                <td class="ti-indicator">${escapeHtml(e.indicator)}</td>
                <td class="ti-count">${e.count}</td>
                <td class="ti-count">${e.uniqueCases}</td>
                <td>${badge}</td>
            </tr>
        `;
    }).join('');

    return `
        <table class="threatintel-table">
            <thead>
                <tr>
                    <th>${label}</th>
                    <th style="text-align:center;">Appearances</th>
                    <th style="text-align:center;">Unique Cases</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>
    `;
}


// ═══════════════════════════════════════════════
//  Final Report
// ═══════════════════════════════════════════════

function renderFinalReport() {
    const container = document.getElementById('final-report-content');
    if (!currentAnalysis) {
        container.innerHTML = '<p class="empty-state">Analyze an email first, then generate the final investigation report.</p>';
        return;
    }

    const data = currentAnalysis;
    const h = data.headers || {};
    const risk = data.risk || {};
    const auth = data.authentication || {};
    const nlp = data.nlp_analysis || {};
    const urlData = data.url_analysis || {};
    const geo = data.geolocation || {};
    const now = new Date().toLocaleString();

    // Verdict color
    const score = risk.threat_score || 0;
    let verdictClass = 'fr-verdict-safe';
    if (score >= 70) verdictClass = 'fr-verdict-malicious';
    else if (score >= 40) verdictClass = 'fr-verdict-suspicious';

    let html = '';

    // ── Report Header ──
    html += `
        <div class="fr-header">
            <div class="fr-header-logo">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent-primary)" stroke-width="2" stroke-linecap="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <circle cx="12" cy="11" r="3"/>
                </svg>
                <div>
                    <div class="fr-header-title">AegisMail Investigation Report</div>
                    <div class="fr-header-subtitle">Email Forensic Intelligence Platform — SIH26106</div>
                </div>
            </div>
            <div class="fr-header-meta">
                <span>Generated: ${escapeHtml(now)}</span>
                <span>Case ID: <strong>${escapeHtml(data.case_id || 'N/A')}</strong></span>
            </div>
        </div>
    `;

    // ── 1. Case Overview ──
    html += `
        <div class="fr-section">
            <div class="fr-section-title">1. Case Overview</div>
            <div class="fr-overview-grid">
                <div class="fr-overview-item">
                    <span class="fr-overview-label">Case ID</span>
                    <span class="fr-overview-value fr-mono">${escapeHtml(data.case_id || 'N/A')}</span>
                </div>
                <div class="fr-overview-item">
                    <span class="fr-overview-label">Risk Score</span>
                    <span class="fr-overview-value"><span class="fr-score-badge ${verdictClass}">${score} / 100</span></span>
                </div>
                <div class="fr-overview-item">
                    <span class="fr-overview-label">Verdict</span>
                    <span class="fr-overview-value"><span class="fr-verdict-badge ${verdictClass}">${escapeHtml(risk.verdict || 'N/A')}</span></span>
                </div>
                <div class="fr-overview-item">
                    <span class="fr-overview-label">Confidence</span>
                    <span class="fr-overview-value">${risk.confidence ? Math.round(risk.confidence * 100) + '%' : 'N/A'}</span>
                </div>
                <div class="fr-overview-item">
                    <span class="fr-overview-label">Processing Time</span>
                    <span class="fr-overview-value">${data.processing_time_seconds ? (data.processing_time_seconds * 1000).toFixed(0) + 'ms' : 'N/A'}</span>
                </div>
            </div>
        </div>
    `;

    // ── 2. Sender / Recipient Details ──
    const senderFields = [
        { label: 'From', value: h.sender?.full || 'N/A' },
        { label: 'To', value: h.to || 'N/A' },
        { label: 'Reply-To', value: h.reply_to?.full || '—' },
        { label: 'Return-Path', value: h.return_path?.full || '—' },
        { label: 'Subject', value: h.subject || 'N/A' },
        { label: 'Date', value: h.date?.raw || 'N/A' },
        { label: 'Total Hops', value: `${h.total_hops || 0} relay servers` },
    ];

    html += `
        <div class="fr-section">
            <div class="fr-section-title">2. Sender / Recipient Details</div>
            <table class="fr-table">
                <tbody>
                    ${senderFields.map(f => `<tr><td class="fr-table-label">${f.label}</td><td>${escapeHtml(f.value)}</td></tr>`).join('')}
                </tbody>
            </table>
        </div>
    `;

    // ── 3. Authentication Results ──
    const authProtocols = [
        { name: 'SPF', data: auth.spf },
        { name: 'DKIM', data: auth.dkim },
        { name: 'DMARC', data: auth.dmarc },
    ];

    html += `
        <div class="fr-section">
            <div class="fr-section-title">3. SPF / DKIM / DMARC Authentication</div>
            <div class="fr-auth-grid">
                ${authProtocols.map(p => {
                    const status = p.data?.status || 'unknown';
                    const passed = p.data?.pass;
                    const stClass = passed === true ? 'fr-auth-pass' : passed === false ? 'fr-auth-fail' : 'fr-auth-unknown';
                    return `
                        <div class="fr-auth-card ${stClass}">
                            <div class="fr-auth-name">${p.name}</div>
                            <div class="fr-auth-status">${status.charAt(0).toUpperCase() + status.slice(1)}</div>
                            ${p.data?.detail ? `<div class="fr-auth-detail">${escapeHtml(p.data.detail)}</div>` : ''}
                        </div>
                    `;
                }).join('')}
            </div>
        </div>
    `;

    // ── 4. Header Analysis ──
    const hops = h.received_hops || [];
    html += `
        <div class="fr-section">
            <div class="fr-section-title">4. Header Analysis — Received Chain</div>
            ${hops.length > 0 ? `
                <table class="fr-table">
                    <thead><tr><th>Hop</th><th>From Host</th><th>IP</th><th>By Host</th><th>Timestamp</th></tr></thead>
                    <tbody>
                        ${hops.map(hop => `
                            <tr>
                                <td><strong>Hop ${hop.hop_index}</strong></td>
                                <td>${escapeHtml(hop.from_hostname || '—')}</td>
                                <td><code>${hop.from_ip || '—'}</code></td>
                                <td>${escapeHtml(hop.by_hostname || '—')}</td>
                                <td>${hop.timestamp || '—'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<p class="fr-empty">No received headers parsed</p>'}
        </div>
    `;

    // ── 5. URL & IOC Analysis ──
    const urls = urlData.analyzed_urls || [];
    html += `
        <div class="fr-section">
            <div class="fr-section-title">5. URLs & IOC Analysis</div>
            ${urls.length > 0 ? `
                <table class="fr-table">
                    <thead><tr><th>URL</th><th>Status</th><th>Risk</th><th>Findings</th></tr></thead>
                    <tbody>
                        ${urls.map(u => {
                            const r = u.risk_score || 0;
                            let badge = 'Safe', bClass = 'fr-verdict-safe';
                            if (r >= 0.5) { badge = 'Dangerous'; bClass = 'fr-verdict-malicious'; }
                            else if (r >= 0.2) { badge = 'Suspicious'; bClass = 'fr-verdict-suspicious'; }
                            const findings = (u.findings || []).map(f => f.detail).join('; ');
                            return `
                                <tr>
                                    <td class="fr-url-cell">${escapeHtml(u.url)}</td>
                                    <td><span class="fr-verdict-badge ${bClass}">${badge}</span></td>
                                    <td>${Math.round(r * 100)}%</td>
                                    <td>${escapeHtml(findings || 'None')}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            ` : '<p class="fr-empty">No URLs found in email body</p>'}
        </div>
    `;

    // ── 6. IP / GeoTrace Information ──
    const hopPath = geo.hop_path || [];
    html += `
        <div class="fr-section">
            <div class="fr-section-title">6. IP / GeoTrace Information</div>
            ${hopPath.length > 0 ? `
                <table class="fr-table">
                    <thead><tr><th>Hop</th><th>IP Address</th><th>Location</th><th>ISP / Org</th><th>Country</th></tr></thead>
                    <tbody>
                        ${hopPath.map((hop, i) => `
                            <tr>
                                <td><strong>${i + 1}</strong></td>
                                <td><code>${hop.ip || '—'}</code></td>
                                <td>${escapeHtml(hop.city || '')}${hop.city && hop.region ? ', ' : ''}${escapeHtml(hop.region || '')}</td>
                                <td>${escapeHtml(hop.org || hop.isp || '—')}</td>
                                <td>${escapeHtml(hop.country || '—')}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            ` : '<p class="fr-empty">No geolocation data available</p>'}
        </div>
    `;

    // ── 7. NLP Findings ──
    const nlpCategories = [
        { label: 'Urgency', score: nlp.urgency_score },
        { label: 'Credential Harvesting', score: nlp.credential_score },
        { label: 'Financial Manipulation', score: nlp.financial_score },
        { label: 'Impersonation', score: nlp.impersonation_score },
        { label: 'Social Engineering', score: nlp.social_engineering_score },
    ];
    const flaggedKw = nlp.flagged_keywords || [];

    html += `
        <div class="fr-section">
            <div class="fr-section-title">7. NLP Content Analysis</div>
            <table class="fr-table">
                <thead><tr><th>Category</th><th>Score</th><th>Assessment</th></tr></thead>
                <tbody>
                    ${nlpCategories.map(cat => {
                        const pct = Math.round((cat.score || 0) * 100);
                        let assessment = 'Low risk';
                        let aClass = 'fr-verdict-safe';
                        if (pct >= 50) { assessment = 'High risk'; aClass = 'fr-verdict-malicious'; }
                        else if (pct >= 25) { assessment = 'Moderate'; aClass = 'fr-verdict-suspicious'; }
                        return `<tr><td>${cat.label}</td><td>${pct}%</td><td><span class="fr-verdict-badge ${aClass}">${assessment}</span></td></tr>`;
                    }).join('')}
                </tbody>
            </table>
            ${flaggedKw.length > 0 ? `
                <div class="fr-subsection">
                    <div class="fr-subsection-title">Flagged Keywords</div>
                    <div class="fr-keyword-list">
                        ${flaggedKw.map(kw => `<span class="fr-keyword">${escapeHtml(kw.keyword)}</span>`).join('')}
                    </div>
                </div>
            ` : ''}
        </div>
    `;

    // ── 8. Timeline ──
    html += `
        <div class="fr-section">
            <div class="fr-section-title">8. Email Timeline</div>
            ${hops.length > 0 ? `
                <div class="fr-timeline">
                    ${hops.map(hop => `
                        <div class="fr-timeline-item">
                            <div class="fr-timeline-dot"></div>
                            <div class="fr-timeline-content">
                                <div class="fr-timeline-time">${hop.timestamp || 'Unknown time'}</div>
                                <div class="fr-timeline-desc">Hop ${hop.hop_index}: ${escapeHtml(hop.from_hostname || 'Origin')} → ${escapeHtml(hop.by_hostname || 'Destination')}</div>
                                ${hop.from_ip ? `<div class="fr-timeline-ip">IP: <code>${hop.from_ip}</code></div>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>
            ` : '<p class="fr-empty">No timeline data available</p>'}
        </div>
    `;

    // ── 9. Evidence Summary (Threat Indicators) ──
    const indicators = risk.indicators || [];
    html += `
        <div class="fr-section">
            <div class="fr-section-title">9. Evidence Summary — Threat Indicators</div>
            ${indicators.length > 0 ? `
                <table class="fr-table">
                    <thead><tr><th>Severity</th><th>Category</th><th>Description</th></tr></thead>
                    <tbody>
                        ${indicators.map(ind => {
                            let sevClass = 'fr-verdict-safe';
                            if (ind.severity === 'critical' || ind.severity === 'high') sevClass = 'fr-verdict-malicious';
                            else if (ind.severity === 'medium') sevClass = 'fr-verdict-suspicious';
                            return `
                                <tr>
                                    <td><span class="fr-verdict-badge ${sevClass}">${ind.severity}</span></td>
                                    <td>${escapeHtml(ind.category)}</td>
                                    <td>${escapeHtml(ind.message)}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            ` : '<p class="fr-empty">No threat indicators detected — email appears safe</p>'}
        </div>
    `;

    // ── 10. Recurring Threat Intelligence ──
    html += `
        <div class="fr-section">
            <div class="fr-section-title">10. Recurring Threat Intelligence</div>
            <div id="fr-threatintel-content"><p class="fr-empty">Loading cross-case intelligence…</p></div>
        </div>
    `;

    // ── Report Footer ──
    html += `
        <div class="fr-footer">
            <p>This report was generated by AegisMail Forensic Intelligence Platform (SIH26106).</p>
            <p>Report generated on ${escapeHtml(now)}. All data is based on automated analysis and should be reviewed by a qualified analyst.</p>
        </div>
    `;

    container.innerHTML = html;

    // Load threat intel asynchronously for section 10
    loadFinalReportThreatIntel();
}


async function loadFinalReportThreatIntel() {
    const container = document.getElementById('fr-threatintel-content');
    if (!container) return;

    try {
        const resp = await fetch(`${API_BASE}/api/cases`);
        if (!resp.ok) throw new Error();
        const listData = await resp.json();
        const caseSummaries = listData.cases || [];

        if (caseSummaries.length < 2) {
            container.innerHTML = '<p class="fr-empty">Analyze multiple emails to detect recurring threat patterns across cases.</p>';
            return;
        }

        const casePromises = caseSummaries.map(c =>
            fetch(`${API_BASE}/api/cases/${c.case_id}`)
                .then(r => r.ok ? r.json() : null)
                .catch(() => null)
        );
        const fullCases = (await Promise.all(casePromises)).filter(Boolean);

        const domainCounts = {};
        const senderCounts = {};
        const ipCounts = {};
        const isPrivateIP = (ip) => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip);

        for (const c of fullCases) {
            const caseId = c.case_id || '';
            const headers = c.headers || {};
            const urlAnalysis = c.url_analysis || {};

            const senderDomain = headers.sender?.domain;
            if (senderDomain) {
                if (!domainCounts[senderDomain]) domainCounts[senderDomain] = { count: 0, cases: new Set() };
                domainCounts[senderDomain].count++;
                domainCounts[senderDomain].cases.add(caseId);
            }

            const senderFull = headers.sender?.full;
            if (senderFull) {
                if (!senderCounts[senderFull]) senderCounts[senderFull] = { count: 0, cases: new Set() };
                senderCounts[senderFull].count++;
                senderCounts[senderFull].cases.add(caseId);
            }

            const allIPs = headers.all_ips || [];
            for (const ip of allIPs) {
                if (!isPrivateIP(ip)) {
                    if (!ipCounts[ip]) ipCounts[ip] = { count: 0, cases: new Set() };
                    ipCounts[ip].count++;
                    ipCounts[ip].cases.add(caseId);
                }
            }

            const urls = (urlAnalysis.analyzed_urls || []).filter(u => u.risk_score >= 0.2);
            for (const u of urls) {
                try {
                    const urlDomain = new URL(u.url).hostname;
                    if (urlDomain && !isPrivateIP(urlDomain)) {
                        if (!domainCounts[urlDomain]) domainCounts[urlDomain] = { count: 0, cases: new Set() };
                        domainCounts[urlDomain].count++;
                        domainCounts[urlDomain].cases.add(caseId);
                    }
                } catch { /* skip invalid */ }
            }
        }

        const renderTI = (obj, label) => {
            const entries = Object.entries(obj)
                .map(([key, val]) => ({ indicator: key, count: val.count, uniqueCases: val.cases.size }))
                .filter(e => e.uniqueCases >= 2)
                .sort((a, b) => b.uniqueCases - a.uniqueCases || b.count - a.count);
            if (entries.length === 0) return '';
            return `
                <div class="fr-subsection">
                    <div class="fr-subsection-title">Recurring ${label}</div>
                    <table class="fr-table">
                        <thead><tr><th>${label}</th><th>Appearances</th><th>Unique Cases</th></tr></thead>
                        <tbody>${entries.map(e => `<tr><td>${escapeHtml(e.indicator)}</td><td>${e.count}</td><td>${e.uniqueCases}</td></tr>`).join('')}</tbody>
                    </table>
                </div>
            `;
        };

        const tiHtml = renderTI(domainCounts, 'Domains') + renderTI(senderCounts, 'Senders') + renderTI(ipCounts, 'IP Addresses');
        container.innerHTML = tiHtml || '<p class="fr-empty">No recurring threat indicators detected across analyzed cases.</p>';

    } catch {
        container.innerHTML = '<p class="fr-empty">Unable to load cross-case threat data. Is the engine running?</p>';
    }
}


// ── Final Report Actions ──

function downloadReportPDF() {
    if (!currentAnalysis) {
        alert('No analysis data available. Analyze an email first.');
        return;
    }
    window.print();
}

async function copyReport() {
    if (!currentAnalysis) {
        alert('No analysis data available. Analyze an email first.');
        return;
    }
    const content = document.getElementById('final-report-content');
    const text = content.innerText;
    try {
        await navigator.clipboard.writeText(text);
        const btn = document.getElementById('fr-btn-copy');
        const original = btn.innerHTML;
        btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Copied!';
        btn.classList.add('fr-btn-success');
        setTimeout(() => {
            btn.innerHTML = original;
            btn.classList.remove('fr-btn-success');
        }, 2000);
    } catch {
        // Fallback: select and prompt copy
        const range = document.createRange();
        range.selectNodeContents(content);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        alert('Report text selected. Press Ctrl+C to copy.');
    }
}

function openSendReportModal() {
    if (!currentAnalysis) {
        alert('No analysis data available. Analyze an email first.');
        return;
    }
    const modal = document.getElementById('fr-send-modal');
    modal.style.display = 'flex';

    // Pre-fill subject
    const subjectInput = document.getElementById('fr-send-subject');
    if (!subjectInput.value) {
        const caseId = currentAnalysis.case_id || 'Unknown';
        const verdict = currentAnalysis.risk?.verdict || 'N/A';
        subjectInput.value = `AegisMail Investigation Report — Case ${caseId} [${verdict}]`;
    }
}

function closeSendReportModal() {
    document.getElementById('fr-send-modal').style.display = 'none';
}

function sendReport() {
    const to = document.getElementById('fr-send-to').value.trim();
    const subject = document.getElementById('fr-send-subject').value.trim();
    const message = document.getElementById('fr-send-message').value.trim();

    if (!to) {
        alert('Please enter a recipient email address.');
        return;
    }

    // Build plain-text report body
    const content = document.getElementById('final-report-content');
    let body = '';
    if (message) {
        body += message + '\n\n---\n\n';
    }
    body += content.innerText;

    // mailto: URI with encoded fields
    const mailto = `mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject || 'AegisMail Investigation Report')}&body=${encodeURIComponent(body)}`;

    // Open user's email client
    window.open(mailto, '_blank');
    closeSendReportModal();
}


// ═══════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
