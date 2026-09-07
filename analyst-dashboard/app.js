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
//  Utilities
// ═══════════════════════════════════════════════

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
