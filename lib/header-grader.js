/**
 * lib/header-grader.js
 * Grades a site's security headers (A-F) based on presence and configuration.
 */

const SECURITY_HEADERS = [
    { name: 'content-security-policy', label: 'Content-Security-Policy', weight: 25, critical: true,
      rec: 'Implement a Content-Security-Policy to prevent XSS and injection attacks.' },
    { name: 'strict-transport-security', label: 'Strict-Transport-Security', weight: 20, critical: true,
      rec: 'Add HSTS with max-age >= 31536000 and includeSubDomains.' },
    { name: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 10, critical: false,
      rec: 'Add X-Content-Type-Options: nosniff to prevent MIME-type sniffing.' },
    { name: 'x-frame-options', label: 'X-Frame-Options', weight: 10, critical: false,
      rec: 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.' },
    { name: 'referrer-policy', label: 'Referrer-Policy', weight: 10, critical: false,
      rec: 'Set Referrer-Policy to no-referrer or strict-origin-when-cross-origin.' },
    { name: 'permissions-policy', label: 'Permissions-Policy', weight: 10, critical: false,
      rec: 'Use Permissions-Policy to restrict access to browser features.' },
    { name: 'x-xss-protection', label: 'X-XSS-Protection', weight: 5, critical: false,
      rec: 'Add X-XSS-Protection: 1; mode=block for legacy browser protection.' },
    { name: 'cross-origin-opener-policy', label: 'Cross-Origin-Opener-Policy', weight: 5, critical: false,
      rec: 'Set Cross-Origin-Opener-Policy to same-origin for isolation.' },
    { name: 'cross-origin-resource-policy', label: 'Cross-Origin-Resource-Policy', weight: 5, critical: false,
      rec: 'Set Cross-Origin-Resource-Policy to same-origin or same-site.' },
];

function gradeSecurityHeaders(headersArray) {
    const headerMap = {};
    headersArray.forEach(h => { headerMap[h.name.toLowerCase()] = h.value; });

    let totalWeight = 0;
    let earnedWeight = 0;
    const results = [];

    for (const check of SECURITY_HEADERS) {
        totalWeight += check.weight;
        const present = check.name in headerMap;
        if (present) earnedWeight += check.weight;
        results.push({
            label: check.label,
            present,
            value: present ? headerMap[check.name] : null,
            critical: check.critical,
            rec: present ? null : check.rec
        });
    }

    const percentage = Math.round((earnedWeight / totalWeight) * 100);
    let grade;
    if (percentage >= 90) grade = 'A';
    else if (percentage >= 75) grade = 'B';
    else if (percentage >= 60) grade = 'C';
    else if (percentage >= 40) grade = 'D';
    else grade = 'F';

    return { grade, percentage, results };
}
