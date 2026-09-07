"""
main.py — TheThirdEye Forensic Intelligence Engine

FastAPI application exposing email forensic analysis endpoints.
Runs on port 5001 alongside the existing ML microservice on port 5000.

Endpoints:
    POST /api/analyze-eml    — Full .eml file forensic analysis
    GET  /api/health         — Health check
    GET  /api/cases          — List previously analyzed cases
    GET  /api/demo-emails    — List available demo .eml files
"""

import os
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

# Local imports
from parsers.header_parser import parse_email_from_bytes, extract_all_headers
from parsers.auth_validator import validate_authentication
from parsers.body_parser import parse_body
from analyzers.nlp_engine import analyze_text_nlp
from analyzers.url_analyzer import analyze_urls
from analyzers.geo_tracer import trace_email_hops
from analyzers.risk_scorer import compute_composite_risk


# ═══════════════════════════════════════════════
#  App Configuration
# ═══════════════════════════════════════════════

app = FastAPI(
    title="TheThirdEye Forensic Engine",
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    version="1.0.0"
)

# CORS — allow dashboard to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Directory paths
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
CASES_DIR = DATA_DIR / "cases"
TEST_EMAILS_DIR = BASE_DIR / "test_emails"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
CASES_DIR.mkdir(exist_ok=True)
TEST_EMAILS_DIR.mkdir(exist_ok=True)


# ═══════════════════════════════════════════════
#  In-memory case store (persisted to disk)
# ═══════════════════════════════════════════════

def save_case(case_id: str, result: dict):
    """Save analysis result to disk for case history."""
    case_file = CASES_DIR / f"{case_id}.json"
    with open(case_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)


def load_cases() -> list:
    """Load all saved cases, sorted by timestamp (newest first)."""
    cases = []
    for case_file in CASES_DIR.glob("*.json"):
        try:
            with open(case_file, "r", encoding="utf-8") as f:
                case = json.load(f)
                cases.append({
                    "case_id": case.get("case_id", ""),
                    "filename": case.get("filename", ""),
                    "subject": case.get("headers", {}).get("subject", ""),
                    "sender": case.get("headers", {}).get("sender", {}).get("full", ""),
                    "threat_score": case.get("risk", {}).get("threat_score", 0),
                    "verdict": case.get("risk", {}).get("verdict", ""),
                    "timestamp": case.get("timestamp", ""),
                })
        except Exception:
            continue
    
    cases.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return cases


# ═══════════════════════════════════════════════
#  API Endpoints
# ═══════════════════════════════════════════════

@app.get("/")
async def root():
    """Root endpoint with API info."""
    return {
        "name": "TheThirdEye Forensic Intelligence Engine",
        "version": "1.0.0",
        "status": "online",
        "problem_statement": "SIH26106",
        "endpoints": {
            "POST /api/analyze-eml": "Upload and analyze a .eml file",
            "GET /api/health": "Health check",
            "GET /api/cases": "List analyzed cases",
            "GET /api/demo-emails": "List demo email files"
        }
    }


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    # Check for MaxMind database availability
    maxmind_available = (DATA_DIR / "GeoLite2-City.mmdb").exists()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "capabilities": {
            "header_parsing": True,
            "auth_validation": True,
            "nlp_classification": True,
            "url_analysis": True,
            "geolocation": True,
            "maxmind_db": maxmind_available,
            "geolocation_mode": "maxmind" if maxmind_available else "demo/ipinfo"
        }
    }


@app.post("/api/analyze-eml")
async def analyze_eml(file: UploadFile = File(...)):
    """
    Full forensic analysis of an uploaded .eml file.
    
    Returns a comprehensive JSON report including:
    - Parsed headers with spoofing detection
    - Authentication validation (SPF/DKIM/DMARC)
    - NLP threat classification
    - URL threat analysis
    - Hop-by-hop geolocation trace
    - Composite risk score (0–100) with verdict
    """
    start_time = time.time()
    
    # Validate file
    filename = file.filename or "unknown.eml"
    if not filename.lower().endswith(('.eml', '.txt', '.msg')):
        raise HTTPException(
            status_code=400,
            detail="Invalid file type. Please upload a .eml file."
        )
    
    # Read file contents
    try:
        raw_bytes = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")
    
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    
    # Generate case ID
    file_hash = hashlib.sha256(raw_bytes).hexdigest()[:12]
    case_id = f"CASE-{file_hash}-{int(time.time())}"
    
    # ── Stage 1: Parse Email ──
    try:
        msg = parse_email_from_bytes(raw_bytes)
    except Exception:
        # Try as string if bytes parsing fails
        try:
            raw_str = raw_bytes.decode('utf-8', errors='replace')
            from parsers.header_parser import parse_email_from_string
            msg = parse_email_from_string(raw_str)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse email: {str(e)}")
    
    # ── Stage 2: Extract Headers ──
    headers = extract_all_headers(msg)
    
    # ── Stage 3: Validate Authentication ──
    auth = validate_authentication(
        headers.get("authentication_results_raw", ""),
        headers.get("sender", {}).get("domain")
    )
    
    # ── Stage 4: Parse Body ──
    body = parse_body(msg)
    
    # ── Stage 5: NLP Analysis ──
    nlp = analyze_text_nlp(
        body.get("body", {}).get("plain_text", "") or body.get("body", {}).get("html", ""),
        headers.get("subject", "")
    )
    
    # ── Stage 6: URL Analysis ──
    urls = analyze_urls(body.get("urls", []))
    
    # ── Stage 7: Geographic Trace ──
    geo = trace_email_hops(
        headers.get("received_hops", []),
        headers.get("all_ips", [])
    )
    
    # ── Stage 8: Composite Risk Score ──
    risk = compute_composite_risk(auth, nlp, urls, geo, body, headers)
    
    processing_time = round(time.time() - start_time, 3)
    
    # ── Build Response ──
    result = {
        "case_id": case_id,
        "filename": filename,
        "file_hash_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "timestamp": datetime.now().isoformat(),
        "processing_time_seconds": processing_time,
        
        "headers": headers,
        "authentication": auth,
        "body_analysis": {
            "url_count": body.get("url_count", 0),
            "has_html": body.get("body", {}).get("has_html", False),
            "has_scripts": body.get("has_scripts", False),
            "has_anchor_mismatch": body.get("has_anchor_mismatch", False),
            "dangerous_attachments": body.get("dangerous_attachment_count", 0),
            "scripts": body.get("scripts", []),
            "attachments": body.get("attachments", []),
            "plain_text_preview": (body.get("body", {}).get("plain_text", ""))[:500],
        },
        "nlp_analysis": nlp,
        "url_analysis": urls,
        "geolocation": geo,
        "risk": risk
    }
    
    # Save case to disk
    try:
        save_case(case_id, result)
    except Exception:
        pass  # Don't fail the analysis if case save fails
    
    return result


@app.get("/api/cases")
async def list_cases():
    """List all previously analyzed cases."""
    cases = load_cases()
    return {"cases": cases, "total": len(cases)}


@app.get("/api/cases/{case_id}")
async def get_case(case_id: str):
    """Retrieve a specific case by ID."""
    case_file = CASES_DIR / f"{case_id}.json"
    if not case_file.exists():
        raise HTTPException(status_code=404, detail=f"Case {case_id} not found")
    
    with open(case_file, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/demo-emails")
async def list_demo_emails():
    """List available demo .eml files for testing."""
    emails = []
    for eml_file in TEST_EMAILS_DIR.glob("*.eml"):
        emails.append({
            "filename": eml_file.name,
            "size_bytes": eml_file.stat().st_size,
            "path": str(eml_file)
        })
    return {"demo_emails": emails}


@app.post("/api/analyze-demo/{filename}")
async def analyze_demo_email(filename: str):
    """Analyze a demo email file by filename."""
    eml_path = TEST_EMAILS_DIR / filename
    if not eml_path.exists():
        raise HTTPException(status_code=404, detail=f"Demo email '{filename}' not found")
    
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()
    
    # Create a mock UploadFile
    from io import BytesIO
    from starlette.datastructures import UploadFile as StarletteUploadFile
    
    mock_file = StarletteUploadFile(
        filename=filename,
        file=BytesIO(raw_bytes)
    )
    
    return await analyze_eml(mock_file)


# ═══════════════════════════════════════════════
#  Run the server
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("  TheThirdEye Forensic Intelligence Engine")
    print("  SIH26106: AI-Powered Email Threat Detection")
    print("=" * 60)
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=5001,
        reload=True,
        log_level="info"
    )
