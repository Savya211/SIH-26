"""
nlp_engine.py — NLP Threat Classification Engine

Phase 1: Keyword-based heuristic classifier for detecting:
- Urgency & pressure tactics
- Credential harvesting attempts
- Financial fraud / payment redirection
- Executive impersonation (whaling)
- AI-generated social engineering cues

Produces per-category scores (0.0–1.0) and flags specific trigger words.
"""

import re
from typing import Optional


# ═══════════════════════════════════════════════
#  Threat Category Patterns
# ═══════════════════════════════════════════════

URGENCY_PATTERNS = [
    (r'\burgent(ly)?\b', 'urgent'),
    (r'\bimmediate(ly)?\b', 'immediate'),
    (r'\baction required\b', 'action required'),
    (r'\bsuspend(ed)?\b', 'suspended'),
    (r'\bdeactivat(ed|e|ion)\b', 'deactivated'),
    (r'\bterminated?\b', 'terminated'),
    (r'\bexpir(ed?|ing|es)\b', 'expiring'),
    (r'\bwithin\s+\d+\s*hours?\b', 'time pressure'),
    (r'\blast\s+(chance|warning|notice)\b', 'last warning'),
    (r'\bfailure\s+to\s+(respond|comply|verify)\b', 'failure to comply'),
    (r'\bunauthorized\s+(access|transaction|activity)\b', 'unauthorized activity'),
    (r'\bsecurity\s+(alert|breach|warning|incident)\b', 'security alert'),
    (r'\baccount\s+(will\s+be|has\s+been)\s+(closed|locked|suspended|blocked|disabled)\b', 'account threat'),
    (r'\bdo\s+not\s+ignore\b', 'do not ignore'),
    (r'\brequires?\s+immediate\b', 'requires immediate'),
    (r'\bfinal\s+notice\b', 'final notice'),
    (r'\bescalat(ed?|ion)\b', 'escalation'),
]

CREDENTIAL_HARVEST_PATTERNS = [
    (r'\bverify\s+your\s+(account|identity|email|password)\b', 'verify account'),
    (r'\breset\s+(your\s+)?password\b', 'reset password'),
    (r'\bconfirm\s+your\s+(identity|account|details|information)\b', 'confirm identity'),
    (r'\bupdate\s+your\s+(payment|billing|account|profile)\b', 'update account'),
    (r'\blog\s*in\s+(here|now|to\s+verify)\b', 'login prompt'),
    (r'\bclick\s+(here|below|the\s+link)\s+to\b', 'click bait'),
    (r'\benter\s+your\s+(password|credentials|pin|ssn|social\s+security)\b', 'enter credentials'),
    (r'\bsign\s*-?\s*in\s+(to\s+verify|required|now)\b', 'sign-in prompt'),
    (r'\buser\s*name\s+and\s+password\b', 'username and password'),
    (r'\b(one-time|otp|verification)\s+(code|pin|password)\b', 'OTP/code request'),
    (r'\bvalidate\s+your\b', 'validate request'),
    (r'\brestore\s+(your\s+)?(account|access)\b', 'restore access'),
]

FINANCIAL_FRAUD_PATTERNS = [
    (r'\bwire\s+transfer\b', 'wire transfer'),
    (r'\b(bank|account)\s+number\b', 'bank account'),
    (r'\bgift\s+card\b', 'gift card'),
    (r'\bpayment\s+(redirect|diversion|update)\b', 'payment redirection'),
    (r'\binvoice\s+(attached|enclosed|due|overdue|pending)\b', 'invoice scam'),
    (r'\bpurchase\s+order\b', 'purchase order'),
    (r'\bremitt?ance\b', 'remittance'),
    (r'\bfunds?\s+transfer\b', 'fund transfer'),
    (r'\b(new|updated|changed)\s+bank(ing)?\s+(details|account|information)\b', 'changed bank details'),
    (r'\bpayroll\s+(update|verification|change)\b', 'payroll fraud'),
    (r'\btax\s+(refund|return|rebate)\b', 'tax scam'),
    (r'\blottery|prize\s+winner\b', 'lottery scam'),
    (r'\binheritance\b', 'inheritance scam'),
    (r'\bcrypto(currency)?\s+(invest|opportunity|profit)\b', 'crypto scam'),
]

IMPERSONATION_PATTERNS = [
    (r'\b(chief\s+)?(executive|financial|operating)\s+officer\b', 'C-suite title'),
    (r'\bceo\b', 'CEO'),
    (r'\bcfo\b', 'CFO'),
    (r'\bdirector\s+(desk|general|of)\b', 'Director'),
    (r'\bmanaging\s+director\b', 'Managing Director'),
    (r'\bboard\s+of\s+directors?\b', 'Board of Directors'),
    (r'\binternal\s+(audit|compliance|investigation)\b', 'internal department'),
    (r'\bhuman\s+resources?\b', 'HR impersonation'),
    (r'\bit\s+(department|support|helpdesk|admin)\b', 'IT impersonation'),
    (r'\b(central|national|reserve)\s+bank\b', 'central bank'),
    (r'\bgovernment\s+(of|agency|department)\b', 'government impersonation'),
    (r'\blaw\s+enforcement\b', 'law enforcement'),
    (r'\bincome\s+tax\b', 'tax authority'),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (r'\bconfidential(ity)?\b', 'confidentiality'),
    (r'\bdo\s+not\s+(share|forward|disclose)\b', 'secrecy request'),
    (r'\bkeep\s+this\s+(between|private|confidential)\b', 'secrecy request'),
    (r'\btrust(ed)?\s+(source|contact|colleague)\b', 'trust building'),
    (r'\bas\s+(discussed|agreed|mentioned)\b', 'false familiarity'),
    (r'\bper\s+(our|your)\s+(conversation|discussion|request)\b', 'false familiarity'),
    (r'\bi\s+(need|require)\s+this\s+(done|completed|processed)\s+(today|asap|immediately)\b', 'authority pressure'),
    (r'\bdon\'?t\s+tell\s+anyone\b', 'secrecy request'),
]


def analyze_text_nlp(text: str, subject: str = "") -> dict:
    """
    Perform NLP analysis on email text to detect threat categories.
    
    Args:
        text: Plain text body of the email
        subject: Email subject line
    
    Returns:
        {
            "urgency_score": float (0-1),
            "credential_score": float (0-1),
            "financial_score": float (0-1),
            "impersonation_score": float (0-1),
            "social_engineering_score": float (0-1),
            "overall_nlp_score": float (0-1),
            "flagged_keywords": [{"keyword": str, "category": str, "context": str}],
            "threat_categories": [str],
            "nlp_indicators": [str]
        }
    """
    # Combine subject and body for analysis
    combined = f"{subject}\n{text}".lower()
    
    flagged_keywords = []
    
    def score_category(patterns, category_name):
        """Score a category based on pattern matches."""
        hits = 0
        for pattern, label in patterns:
            matches = re.findall(pattern, combined, re.IGNORECASE)
            if matches:
                hits += 1
                # Find context around match
                match_obj = re.search(pattern, combined, re.IGNORECASE)
                if match_obj:
                    start = max(0, match_obj.start() - 30)
                    end = min(len(combined), match_obj.end() + 30)
                    context = combined[start:end].strip()
                else:
                    context = ""
                
                flagged_keywords.append({
                    "keyword": label,
                    "category": category_name,
                    "context": f"...{context}..."
                })
        
        # Normalize: more matches = higher score, cap at 1.0
        # Using diminishing returns: each match adds less
        if hits == 0:
            return 0.0
        return min(1.0, hits * 0.2 + 0.1)  # 1 match = 0.3, 5+ matches = 1.0
    
    # Score each category
    urgency = score_category(URGENCY_PATTERNS, "Urgency & Pressure")
    credential = score_category(CREDENTIAL_HARVEST_PATTERNS, "Credential Harvesting")
    financial = score_category(FINANCIAL_FRAUD_PATTERNS, "Financial Fraud")
    impersonation = score_category(IMPERSONATION_PATTERNS, "Impersonation")
    social_eng = score_category(SOCIAL_ENGINEERING_PATTERNS, "Social Engineering")
    
    # Additional text-level heuristics
    
    # Check for excessive capitalization (SHOUTING)
    upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
    if upper_ratio > 0.3 and len(text) > 50:
        urgency = min(1.0, urgency + 0.15)
        flagged_keywords.append({
            "keyword": "excessive capitalization",
            "category": "Urgency & Pressure",
            "context": f"Upper case ratio: {upper_ratio:.0%}"
        })
    
    # Check for multiple exclamation marks
    exclamation_count = text.count('!')
    if exclamation_count > 3:
        urgency = min(1.0, urgency + 0.1)
        flagged_keywords.append({
            "keyword": "excessive exclamation marks",
            "category": "Urgency & Pressure",
            "context": f"Found {exclamation_count} exclamation marks"
        })
    
    # Overall NLP score: weighted combination
    overall = (
        urgency * 0.25 +
        credential * 0.30 +
        financial * 0.20 +
        impersonation * 0.15 +
        social_eng * 0.10
    )
    
    # Determine active threat categories
    threat_categories = []
    if urgency > 0.3:
        threat_categories.append("Urgency & Pressure Tactics")
    if credential > 0.3:
        threat_categories.append("Credential Harvesting Attempt")
    if financial > 0.3:
        threat_categories.append("Financial Fraud / Payment Redirection")
    if impersonation > 0.3:
        threat_categories.append("Identity Impersonation / Whaling")
    if social_eng > 0.3:
        threat_categories.append("Social Engineering Manipulation")
    
    # Build human-readable indicators
    indicators = []
    if urgency > 0.5:
        indicators.append(f"High urgency/pressure language detected (score: {urgency:.0%})")
    if credential > 0.5:
        indicators.append(f"Credential harvesting patterns detected (score: {credential:.0%})")
    if financial > 0.5:
        indicators.append(f"Financial fraud indicators detected (score: {financial:.0%})")
    if impersonation > 0.3:
        indicators.append(f"Impersonation cues detected (score: {impersonation:.0%})")
    if social_eng > 0.3:
        indicators.append(f"Social engineering tactics detected (score: {social_eng:.0%})")
    
    return {
        "urgency_score": round(urgency, 3),
        "credential_score": round(credential, 3),
        "financial_score": round(financial, 3),
        "impersonation_score": round(impersonation, 3),
        "social_engineering_score": round(social_eng, 3),
        "overall_nlp_score": round(overall, 3),
        "flagged_keywords": flagged_keywords,
        "threat_categories": threat_categories,
        "nlp_indicators": indicators
    }
