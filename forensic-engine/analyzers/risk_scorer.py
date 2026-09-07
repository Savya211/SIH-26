"""
risk_scorer.py — Composite Threat Risk Scoring Engine

Combines sub-scores from all analysis layers into a single
transparent, deterministic risk score (0–100) with an explainable
audit trail of contributing indicators.

Weights:
    Authentication: 30%
    NLP Content:    30%
    URL Heuristics: 20%
    Geographic:     10%
    Attachments:    10%
"""


def compute_composite_risk(
    auth_data: dict,
    nlp_data: dict,
    url_data: dict,
    geo_data: dict,
    body_data: dict,
    header_data: dict
) -> dict:
    """
    Compute the final composite risk score (0–100) from all analysis layers.
    
    Args:
        auth_data: Output from auth_validator.validate_authentication()
        nlp_data: Output from nlp_engine.analyze_text_nlp()
        url_data: Output from url_analyzer.analyze_urls()
        geo_data: Output from geo_tracer.trace_email_hops()
        body_data: Output from body_parser.parse_body()
        header_data: Output from header_parser.extract_all_headers()
    
    Returns:
        {
            "threat_score": int (0-100),
            "verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN",
            "verdict_color": str (hex color),
            "confidence": float (0-1),
            
            "sub_scores": {
                "authentication": float,
                "nlp_content": float,
                "url_heuristics": float,
                "geographic": float,
                "attachments": float
            },
            
            "indicators": [
                {"category": str, "severity": str, "message": str}
            ],
            
            "summary": str  (one-line human-readable summary)
        }
    """
    indicators = []
    
    # ═══════════════════════════════════════════
    #  Sub-Score 1: Authentication (30%)
    # ═══════════════════════════════════════════
    auth_score = auth_data.get("auth_risk_score", 0.0) * 100
    
    for indicator_msg in auth_data.get("auth_indicators", []):
        severity = "high" if "FAIL" in indicator_msg.upper() else "medium"
        indicators.append({
            "category": "Authentication",
            "severity": severity,
            "message": indicator_msg
        })
    
    # ═══════════════════════════════════════════
    #  Sub-Score 2: NLP Content Analysis (30%)
    # ═══════════════════════════════════════════
    nlp_score = nlp_data.get("overall_nlp_score", 0.0) * 100
    
    for indicator_msg in nlp_data.get("nlp_indicators", []):
        severity = "high" if "high" in indicator_msg.lower() else "medium"
        indicators.append({
            "category": "NLP Content",
            "severity": severity,
            "message": indicator_msg
        })
    
    # Add specific threat category indicators
    for cat in nlp_data.get("threat_categories", []):
        indicators.append({
            "category": "NLP Content",
            "severity": "high",
            "message": f"Threat category detected: {cat}"
        })
    
    # ═══════════════════════════════════════════
    #  Sub-Score 3: URL Heuristics (20%)
    # ═══════════════════════════════════════════
    url_score = url_data.get("url_risk_score", 0.0) * 100
    
    for indicator_msg in url_data.get("url_indicators", []):
        indicators.append({
            "category": "URL Analysis",
            "severity": "high",
            "message": indicator_msg
        })
    
    # Boost score if scripts are detected in body
    if body_data.get("has_scripts"):
        url_score = min(100, url_score + 40)
        for script in body_data.get("scripts", []):
            indicators.append({
                "category": "Active Content",
                "severity": "critical",
                "message": script.get("detail", "Embedded active content detected")
            })
    
    # Anchor mismatch is a critical phishing signal
    if body_data.get("has_anchor_mismatch"):
        url_score = min(100, url_score + 30)
        indicators.append({
            "category": "URL Analysis",
            "severity": "critical",
            "message": "Link display text does not match the actual destination URL"
        })
    
    # ═══════════════════════════════════════════
    #  Sub-Score 4: Geographic Anomaly (10%)
    # ═══════════════════════════════════════════
    geo_score = geo_data.get("geo_risk_score", 0.0) * 100
    
    for indicator_msg in geo_data.get("geo_indicators", []):
        severity = "high" if "tor" in indicator_msg.lower() or "vpn" in indicator_msg.lower() else "medium"
        indicators.append({
            "category": "Geographic",
            "severity": severity,
            "message": indicator_msg
        })
    
    for anomaly in geo_data.get("geo_anomalies", []):
        indicators.append({
            "category": "Geographic",
            "severity": "high",
            "message": anomaly
        })
    
    # ═══════════════════════════════════════════
    #  Sub-Score 5: Attachments (10%)
    # ═══════════════════════════════════════════
    attachment_score = 0.0
    dangerous_count = body_data.get("dangerous_attachment_count", 0)
    
    if dangerous_count > 0:
        attachment_score = min(100, dangerous_count * 50)
        for att in body_data.get("attachments", []):
            if att.get("is_dangerous"):
                detail = f"Dangerous attachment: {att['filename']}"
                if att.get("has_double_extension"):
                    detail += " (double extension detected — likely disguised executable)"
                indicators.append({
                    "category": "Attachments",
                    "severity": "critical",
                    "message": detail
                })
    
    # ═══════════════════════════════════════════
    #  Spoofing Indicators from Header Parser
    # ═══════════════════════════════════════════
    for spoof in header_data.get("spoofing_indicators", []):
        indicators.append({
            "category": "Identity Spoofing",
            "severity": spoof.get("severity", "high"),
            "message": spoof.get("detail", "Spoofing indicator detected")
        })
        # Boost auth score for spoofing
        auth_score = min(100, auth_score + 20)
    
    # ═══════════════════════════════════════════
    #  Weighted Composite Score
    # ═══════════════════════════════════════════
    composite = (
        auth_score * 0.30 +
        nlp_score * 0.30 +
        url_score * 0.20 +
        geo_score * 0.10 +
        attachment_score * 0.10
    )
    
    threat_score = round(min(100, max(0, composite)))
    
    # ═══════════════════════════════════════════
    #  Verdict & Confidence
    # ═══════════════════════════════════════════
    if threat_score >= 70:
        verdict = "MALICIOUS"
        verdict_color = "#ef4444"  # red
    elif threat_score >= 40:
        verdict = "SUSPICIOUS"
        verdict_color = "#f97316"  # orange
    else:
        verdict = "BENIGN"
        verdict_color = "#22c55e"  # green
    
    # Confidence: higher when more evidence sources agree
    evidence_sources = sum([
        1 if auth_score > 30 else 0,
        1 if nlp_score > 30 else 0,
        1 if url_score > 30 else 0,
        1 if geo_score > 30 else 0,
        1 if attachment_score > 30 else 0,
        1 if len(header_data.get("spoofing_indicators", [])) > 0 else 0,
    ])
    confidence = min(1.0, evidence_sources * 0.2 + 0.1)
    if threat_score < 20 and evidence_sources == 0:
        confidence = 0.9  # High confidence for clearly benign
    
    # ═══════════════════════════════════════════
    #  Human-Readable Summary
    # ═══════════════════════════════════════════
    critical_count = sum(1 for i in indicators if i["severity"] == "critical")
    high_count = sum(1 for i in indicators if i["severity"] == "high")
    
    if verdict == "MALICIOUS":
        summary = f"High-risk email detected with {critical_count + high_count} critical/high severity indicators. Immediate investigation recommended."
    elif verdict == "SUSPICIOUS":
        summary = f"Email shows {high_count} suspicious indicators. Manual review advised before interacting with contents."
    else:
        summary = "Email appears legitimate with no significant threat indicators detected."
    
    # Sort indicators by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    indicators.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return {
        "threat_score": threat_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "confidence": round(confidence, 2),
        
        "sub_scores": {
            "authentication": round(auth_score, 1),
            "nlp_content": round(nlp_score, 1),
            "url_heuristics": round(url_score, 1),
            "geographic": round(geo_score, 1),
            "attachments": round(attachment_score, 1)
        },
        
        "indicators": indicators,
        "summary": summary
    }
