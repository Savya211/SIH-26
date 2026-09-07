"""
auth_validator.py — Email Authentication Protocol Validator

Validates SPF, DKIM, and DMARC authentication status by:
1. Parsing the Authentication-Results header (primary method)
2. Performing live DNS queries as a fallback (SPF TXT records, DMARC policy)

Produces a structured report with pass/fail/softfail status for each protocol
and an overall authentication risk score.
"""

import re
from typing import Optional


def parse_authentication_results(auth_header: str) -> dict:
    """
    Parse the Authentication-Results header to extract SPF, DKIM, and DMARC status.
    
    Example header:
        Authentication-Results: mx.google.com;
            spf=fail (domain does not designate IP as permitted);
            dkim=pass header.d=example.com;
            dmarc=fail action=none header.from=example.com
    
    Returns:
        {
            "spf": {"status": "fail", "detail": "...", "pass": False},
            "dkim": {"status": "pass", "detail": "...", "pass": True},
            "dmarc": {"status": "fail", "detail": "...", "pass": False},
            "raw": "original header text"
        }
    """
    result = {
        "spf": {"status": "unknown", "detail": "", "pass": None},
        "dkim": {"status": "unknown", "detail": "", "pass": None},
        "dmarc": {"status": "unknown", "detail": "", "pass": None},
        "raw": auth_header
    }
    
    if not auth_header:
        return result
    
    header_lower = auth_header.lower()
    
    # --- SPF ---
    spf_match = re.search(r'spf\s*=\s*(\w+)', header_lower)
    if spf_match:
        status = spf_match.group(1)
        result["spf"]["status"] = status
        result["spf"]["pass"] = status == "pass"
        
        # Extract detail in parentheses after spf=status
        spf_detail = re.search(r'spf\s*=\s*\w+\s*\(([^)]+)\)', header_lower)
        if spf_detail:
            result["spf"]["detail"] = spf_detail.group(1).strip()
    
    # --- DKIM ---
    dkim_match = re.search(r'dkim\s*=\s*(\w+)', header_lower)
    if dkim_match:
        status = dkim_match.group(1)
        result["dkim"]["status"] = status
        result["dkim"]["pass"] = status == "pass"
        
        # Extract signing domain
        dkim_domain = re.search(r'dkim\s*=\s*\w+.*?header\.d\s*=\s*([\w.-]+)', header_lower)
        if dkim_domain:
            result["dkim"]["detail"] = f"Signing domain: {dkim_domain.group(1)}"
    
    # --- DMARC ---
    dmarc_match = re.search(r'dmarc\s*=\s*(\w+)', header_lower)
    if dmarc_match:
        status = dmarc_match.group(1)
        result["dmarc"]["status"] = status
        result["dmarc"]["pass"] = status == "pass"
        
        # Extract policy action
        dmarc_action = re.search(r'dmarc\s*=\s*\w+.*?action\s*=\s*(\w+)', header_lower)
        if dmarc_action:
            result["dmarc"]["detail"] = f"Policy action: {dmarc_action.group(1)}"
        
        # Extract header.from domain
        dmarc_from = re.search(r'dmarc\s*=\s*\w+.*?header\.from\s*=\s*([\w.-]+)', header_lower)
        if dmarc_from:
            existing_detail = result["dmarc"]["detail"]
            result["dmarc"]["detail"] = f"{existing_detail}, From domain: {dmarc_from.group(1)}" if existing_detail else f"From domain: {dmarc_from.group(1)}"
    
    return result


def check_spf_dns(domain: str) -> dict:
    """
    Perform a live DNS query to check if the domain has SPF records.
    
    Falls back gracefully if dnspython is not available or DNS query fails.
    Returns: {"has_spf": bool, "record": str, "detail": str}
    """
    result = {"has_spf": None, "record": "", "detail": "DNS query not performed"}
    
    if not domain:
        return result
    
    try:
        import dns.resolver
        
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=spf1'):
                result["has_spf"] = True
                result["record"] = txt_record
                result["detail"] = f"SPF record found: {txt_record[:100]}"
                return result
        
        result["has_spf"] = False
        result["detail"] = f"No SPF TXT record found for domain {domain}"
        
    except ImportError:
        result["detail"] = "dnspython not installed — cannot perform live DNS checks"
    except Exception as e:
        result["detail"] = f"DNS query failed: {str(e)}"
    
    return result


def check_dmarc_dns(domain: str) -> dict:
    """
    Perform a live DNS query to check the domain's DMARC policy.
    Queries _dmarc.<domain> TXT record.
    
    Returns: {"has_dmarc": bool, "policy": str, "record": str, "detail": str}
    """
    result = {"has_dmarc": None, "policy": "", "record": "", "detail": "DNS query not performed"}
    
    if not domain:
        return result
    
    try:
        import dns.resolver
        
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_record = str(rdata).strip('"')
            if txt_record.startswith('v=DMARC1'):
                result["has_dmarc"] = True
                result["record"] = txt_record
                
                # Extract policy
                policy_match = re.search(r'p\s*=\s*(\w+)', txt_record)
                if policy_match:
                    result["policy"] = policy_match.group(1)
                
                result["detail"] = f"DMARC policy: {result['policy'] or 'found'}"
                return result
        
        result["has_dmarc"] = False
        result["detail"] = f"No DMARC record found for {dmarc_domain}"
        
    except ImportError:
        result["detail"] = "dnspython not installed — cannot perform live DNS checks"
    except Exception as e:
        result["detail"] = f"DNS query failed for _dmarc.{domain}: {str(e)}"
    
    return result


def validate_authentication(auth_header: str, sender_domain: Optional[str] = None) -> dict:
    """
    Full authentication validation pipeline.
    
    1. Parse Authentication-Results header
    2. Optionally perform live DNS lookups for SPF and DMARC
    3. Compute an overall authentication risk score (0.0 to 1.0)
    
    Returns:
        {
            "spf": {...},
            "dkim": {...},
            "dmarc": {...},
            "dns_spf": {...},       # Live DNS SPF check
            "dns_dmarc": {...},     # Live DNS DMARC check
            "auth_risk_score": float,  # 0.0 = all pass, 1.0 = all fail
            "auth_indicators": [...]   # Human-readable findings
        }
    """
    # Step 1: Parse header
    parsed = parse_authentication_results(auth_header)
    
    # Step 2: Live DNS checks (if domain provided)
    dns_spf = {"has_spf": None, "record": "", "detail": "No sender domain provided"}
    dns_dmarc = {"has_dmarc": None, "policy": "", "record": "", "detail": "No sender domain provided"}
    
    if sender_domain:
        dns_spf = check_spf_dns(sender_domain)
        dns_dmarc = check_dmarc_dns(sender_domain)
    
    # Step 3: Compute authentication risk score
    risk_score = 0.0
    indicators = []
    
    # SPF scoring
    if parsed["spf"]["status"] == "fail":
        risk_score += 0.35
        indicators.append("SPF verification FAILED — sender IP is not authorized to send for this domain")
    elif parsed["spf"]["status"] == "softfail":
        risk_score += 0.20
        indicators.append("SPF verification SOFTFAIL — sender IP may not be authorized")
    elif parsed["spf"]["status"] == "none":
        risk_score += 0.10
        indicators.append("No SPF record configured for sender domain")
    elif parsed["spf"]["status"] == "unknown":
        risk_score += 0.05
        indicators.append("SPF status could not be determined from headers")
    
    # DKIM scoring
    if parsed["dkim"]["status"] == "fail":
        risk_score += 0.30
        indicators.append("DKIM signature INVALID — email content may have been tampered with")
    elif parsed["dkim"]["status"] == "none":
        risk_score += 0.10
        indicators.append("No DKIM signature present on this email")
    elif parsed["dkim"]["status"] == "unknown":
        risk_score += 0.05
        indicators.append("DKIM status could not be determined from headers")
    
    # DMARC scoring
    if parsed["dmarc"]["status"] == "fail":
        risk_score += 0.35
        indicators.append("DMARC alignment FAILED — sender domain is likely spoofed")
    elif parsed["dmarc"]["status"] == "none":
        risk_score += 0.10
        indicators.append("No DMARC policy configured for sender domain")
    elif parsed["dmarc"]["status"] == "unknown":
        risk_score += 0.05
        indicators.append("DMARC status could not be determined from headers")
    
    # DNS-based additional flags
    if dns_spf.get("has_spf") is False:
        risk_score += 0.05
        indicators.append(f"DNS lookup: No SPF TXT record found for {sender_domain}")
    
    if dns_dmarc.get("has_dmarc") is False:
        risk_score += 0.05
        indicators.append(f"DNS lookup: No DMARC record found for _dmarc.{sender_domain}")
    
    # Clamp to [0, 1]
    risk_score = min(1.0, risk_score)
    
    return {
        "spf": parsed["spf"],
        "dkim": parsed["dkim"],
        "dmarc": parsed["dmarc"],
        "dns_spf": dns_spf,
        "dns_dmarc": dns_dmarc,
        "auth_risk_score": round(risk_score, 3),
        "auth_indicators": indicators
    }
