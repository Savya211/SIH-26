"""
url_analyzer.py — URL Threat Heuristic Analyzer

Analyzes extracted URLs for phishing indicators:
- Raw IP address hosts
- Tunnel/phishing infrastructure (ngrok, serveo, etc.)
- Non-standard ports (BeEF, exploitation frameworks)
- Typosquatting detection via Levenshtein distance
- Dangerous redirect chains
- Credential harvesting path patterns
"""

import re
from urllib.parse import urlparse
from typing import Optional


# ═══════════════════════════════════════════════
#  Known Phishing Infrastructure
# ═══════════════════════════════════════════════

TUNNEL_DOMAINS = {
    'ngrok.io': 'ngrok',
    'ngrok-free.app': 'ngrok',
    'serveo.net': 'serveo',
    'loclx.io': 'loclx',
    'trycloudflare.com': 'cloudflare tunnel',
    'localxpose.io': 'localxpose',
    'bohr.io': 'bohr',
    'pagekite.me': 'pagekite',
    'localhost.run': 'localhost.run',
}

EXPLOITATION_PORTS = {3000, 4444, 8080, 8888, 1337, 9090, 5555, 6666, 7777, 31337}

# Top domains for typosquatting comparison
TOP_DOMAINS = [
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'paypal.com', 'netflix.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'onlinesbi.com', 'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
    'rbi.org.in', 'paytm.com', 'phonepe.com', 'googlepay.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'dropbox.com', 'icloud.com', 'outlook.com', 'yahoo.com', 'gmail.com',
]

# Suspicious TLDs commonly abused in phishing
SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz',
    '.club', '.work', '.icu', '.cam', '.click', '.link', '.monster',
    '.rest', '.quest', '.fit', '.live', '.stream',
}

# Phishing URL path patterns
PHISHING_PATH_PATTERNS = [
    re.compile(r'/(gmail|google|facebook|fb|instagram|twitter|paypal|apple|microsoft|amazon|netflix|bank|secure|account|login|signin|verify|update|confirm|validate|recovery|password|credential)(/|$|-|\?)', re.IGNORECASE),
    re.compile(r'/wp-(admin|login|content)/.*\.(php|html)', re.IGNORECASE),
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    prev_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    
    return prev_row[-1]


def check_typosquatting(hostname: str) -> dict:
    """
    Check if a hostname is a typosquat of a known legitimate domain.
    
    Returns:
        {"is_typosquat": bool, "target_domain": str, "distance": int}
    """
    if not hostname:
        return {"is_typosquat": False, "target_domain": None, "distance": None}
    
    hostname_lower = hostname.lower()
    
    # Don't flag if it IS a legitimate domain
    if hostname_lower in TOP_DOMAINS:
        return {"is_typosquat": False, "target_domain": None, "distance": None}
    
    best_match = None
    best_distance = float('inf')
    
    for legit in TOP_DOMAINS:
        dist = levenshtein_distance(hostname_lower, legit)
        # Flag if very close (1-2 edits) but not exact
        if 0 < dist <= 2 and dist < best_distance:
            best_distance = dist
            best_match = legit
    
    if best_match:
        return {
            "is_typosquat": True,
            "target_domain": best_match,
            "distance": best_distance
        }
    
    return {"is_typosquat": False, "target_domain": None, "distance": None}


def analyze_single_url(url: str) -> dict:
    """
    Analyze a single URL for threat indicators.
    
    Returns:
        {
            "url": str,
            "risk_score": float (0-1),
            "findings": [{"type": str, "severity": str, "detail": str}],
            "is_raw_ip": bool,
            "is_tunnel": bool,
            "has_suspicious_port": bool,
            "is_typosquat": bool,
            "has_suspicious_tld": bool,
            "has_phishing_path": bool
        }
    """
    result = {
        "url": url,
        "risk_score": 0.0,
        "findings": [],
        "is_raw_ip": False,
        "is_tunnel": False,
        "has_suspicious_port": False,
        "is_typosquat": False,
        "has_suspicious_tld": False,
        "has_phishing_path": False
    }
    
    try:
        parsed = urlparse(url)
    except Exception:
        result["risk_score"] = 0.5
        result["findings"].append({
            "type": "MALFORMED_URL",
            "severity": "medium",
            "detail": "URL could not be parsed"
        })
        return result
    
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or ""
    scheme = parsed.scheme or ""
    
    score = 0.0
    
    # 1. HTTP (no TLS)
    if scheme == 'http':
        score += 0.15
        result["findings"].append({
            "type": "NO_TLS",
            "severity": "medium",
            "detail": "URL uses insecure HTTP without encryption"
        })
    
    # 2. Raw IP address host
    if hostname and re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname):
        score += 0.30
        result["is_raw_ip"] = True
        result["findings"].append({
            "type": "RAW_IP_HOST",
            "severity": "high",
            "detail": f"Raw IP address used as hostname: {hostname}"
        })
    
    # 3. Tunnel domains
    for tunnel_domain, service in TUNNEL_DOMAINS.items():
        if hostname.endswith(tunnel_domain):
            score += 0.35
            result["is_tunnel"] = True
            result["findings"].append({
                "type": "TUNNEL_DOMAIN",
                "severity": "high",
                "detail": f"Tunnel infrastructure detected ({service}): {hostname}"
            })
            break
    
    # 4. Suspicious ports
    if port and port in EXPLOITATION_PORTS:
        score += 0.25
        result["has_suspicious_port"] = True
        result["findings"].append({
            "type": "EXPLOITATION_PORT",
            "severity": "high",
            "detail": f"Known exploitation/testing port detected: {port}"
        })
    elif port and port not in (80, 443):
        score += 0.10
        result["has_suspicious_port"] = True
        result["findings"].append({
            "type": "NON_STANDARD_PORT",
            "severity": "medium",
            "detail": f"Non-standard port: {port}"
        })
    
    # 5. BeEF hook detection
    if 'hook.js' in url:
        score += 0.50
        result["findings"].append({
            "type": "BEEF_HOOK",
            "severity": "critical",
            "detail": "BeEF Browser Exploitation Framework hook.js detected in URL"
        })
    
    # 6. Typosquatting
    typo = check_typosquatting(hostname)
    if typo["is_typosquat"]:
        score += 0.30
        result["is_typosquat"] = True
        result["findings"].append({
            "type": "TYPOSQUAT",
            "severity": "high",
            "detail": f"Domain '{hostname}' appears to be typosquatting '{typo['target_domain']}' (edit distance: {typo['distance']})"
        })
    
    # 7. Suspicious TLD
    tld_match = re.search(r'(\.\w+)$', hostname)
    if tld_match and tld_match.group(1) in SUSPICIOUS_TLDS:
        score += 0.15
        result["has_suspicious_tld"] = True
        result["findings"].append({
            "type": "SUSPICIOUS_TLD",
            "severity": "medium",
            "detail": f"Suspicious top-level domain: {tld_match.group(1)}"
        })
    
    # 8. Phishing path patterns
    for pattern in PHISHING_PATH_PATTERNS:
        if pattern.search(path):
            score += 0.20
            result["has_phishing_path"] = True
            result["findings"].append({
                "type": "PHISHING_PATH",
                "severity": "medium",
                "detail": f"URL path matches credential harvesting pattern: {path}"
            })
            break
    
    result["risk_score"] = round(min(1.0, score), 3)
    return result


def analyze_urls(urls: list) -> dict:
    """
    Analyze a list of URL objects (from body_parser.extract_urls_from_html).
    
    Returns:
        {
            "analyzed_urls": [...],
            "url_risk_score": float (0-1, max across all URLs),
            "total_urls": int,
            "dangerous_urls": int,
            "url_indicators": [str]
        }
    """
    analyzed = []
    max_score = 0.0
    indicators = []
    dangerous_count = 0
    
    for url_obj in urls:
        href = url_obj.get("href", "") if isinstance(url_obj, dict) else str(url_obj)
        analysis = analyze_single_url(href)
        
        # Add anchor mismatch from body parser
        if isinstance(url_obj, dict) and url_obj.get("anchor_mismatch"):
            analysis["risk_score"] = min(1.0, analysis["risk_score"] + 0.35)
            analysis["findings"].append({
                "type": "ANCHOR_MISMATCH",
                "severity": "critical",
                "detail": f"Display text shows '{url_obj.get('display_text', '')}' but href points to '{href}'"
            })
        
        if analysis["risk_score"] > max_score:
            max_score = analysis["risk_score"]
        
        if analysis["risk_score"] >= 0.5:
            dangerous_count += 1
        
        analyzed.append(analysis)
    
    # Build indicators
    if dangerous_count > 0:
        indicators.append(f"{dangerous_count} dangerous URL(s) detected")
    
    anchor_mismatches = sum(1 for u in urls if isinstance(u, dict) and u.get("anchor_mismatch"))
    if anchor_mismatches > 0:
        indicators.append(f"{anchor_mismatches} anchor text / href mismatch(es) found")
    
    tunnel_urls = sum(1 for a in analyzed if a.get("is_tunnel"))
    if tunnel_urls > 0:
        indicators.append(f"{tunnel_urls} URL(s) pointing to phishing tunnel infrastructure")
    
    return {
        "analyzed_urls": analyzed,
        "url_risk_score": round(max_score, 3),
        "total_urls": len(urls),
        "dangerous_urls": dangerous_count,
        "url_indicators": indicators
    }
