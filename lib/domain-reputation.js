/**
 * lib/domain-reputation.js
 * Computes a domain reputation score (0-100) from local + backend signals.
 */

const SUSPICIOUS_TLDS_REP = ['.xyz', '.top', '.buzz', '.club', '.gq', '.ml', '.tk', '.cf', '.ga', '.work', '.click', '.loan', '.download', '.bid', '.racing', '.win', '.stream'];

function scoreDomainReputation(signals) {
    // signals: { domain, isHTTPS, inBlocklist, headerGrade, backendData? }
    let score = 100;
    const details = [];

    // 1. HTTPS check
    if (!signals.isHTTPS) {
        score -= 15;
        details.push({ label: 'No HTTPS', impact: -15, status: 'bad' });
    } else {
        details.push({ label: 'HTTPS Enabled', impact: 0, status: 'good' });
    }

    // 2. TLD risk
    const domain = signals.domain.toLowerCase();
    let suspiciousTld = false;
    for (const tld of SUSPICIOUS_TLDS_REP) {
        if (domain.endsWith(tld)) {
            score -= 15;
            suspiciousTld = true;
            details.push({ label: `Suspicious TLD (${tld})`, impact: -15, status: 'bad' });
            break;
        }
    }
    if (!suspiciousTld) {
        details.push({ label: 'Standard TLD', impact: 0, status: 'good' });
    }

    // 3. Local blocklist
    if (signals.inBlocklist) {
        score -= 50;
        details.push({ label: 'In local threat blocklist', impact: -50, status: 'bad' });
    }

    // 4. Security header grade
    if (signals.headerGrade) {
        const g = signals.headerGrade;
        if (g === 'F') { score -= 15; details.push({ label: 'Security Headers: F', impact: -15, status: 'bad' }); }
        else if (g === 'D') { score -= 10; details.push({ label: 'Security Headers: D', impact: -10, status: 'bad' }); }
        else if (g === 'C') { score -= 5; details.push({ label: 'Security Headers: C', impact: -5, status: 'warn' }); }
        else { details.push({ label: `Security Headers: ${g}`, impact: 0, status: 'good' }); }
    }

    // 5. Backend data (WHOIS age, Tranco rank)
    if (signals.backendData) {
        const bd = signals.backendData;
        if (bd.domainAgeDays !== undefined && bd.domainAgeDays !== null) {
            if (bd.domainAgeDays < 30) { score -= 25; details.push({ label: 'Domain < 30 days old', impact: -25, status: 'bad' }); }
            else if (bd.domainAgeDays < 90) { score -= 15; details.push({ label: 'Domain < 90 days old', impact: -15, status: 'warn' }); }
            else if (bd.domainAgeDays < 365) { score -= 5; details.push({ label: 'Domain < 1 year old', impact: -5, status: 'warn' }); }
            else { details.push({ label: `Domain ${Math.floor(bd.domainAgeDays / 365)}+ years old`, impact: 0, status: 'good' }); }
        }
        if (bd.trancoRank !== undefined && bd.trancoRank !== null) {
            if (bd.trancoRank <= 10000) { details.push({ label: `Tranco Top 10K (#${bd.trancoRank})`, impact: 0, status: 'good' }); }
            else if (bd.trancoRank <= 100000) { score -= 5; details.push({ label: `Tranco Top 100K (#${bd.trancoRank})`, impact: -5, status: 'warn' }); }
        } else if (signals.backendData.trancoRank === null) {
            score -= 10;
            details.push({ label: 'Not in Tranco Top 1M', impact: -10, status: 'warn' });
        }
    }

    score = Math.max(0, Math.min(100, score));

    let verdict;
    if (score >= 80) verdict = 'trusted';
    else if (score >= 50) verdict = 'caution';
    else verdict = 'risky';

    return { score, verdict, details };
}
