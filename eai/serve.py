"""
TheThirdEye ML Prediction Microservice
Runs on http://localhost:5000

Endpoints:
  GET  /health        - Health check
  POST /predict-url   - Predict from URL + browser signals (used by Node.js backend)
  POST /predict       - Predict from raw feature dict (for testing)

Start with:
  python serve.py
"""

import os
import re
import json
import math
import joblib
import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(__file__)
MODELS_DIR  = os.path.join(BASE_DIR, "models")
LOOKUPS_DIR = os.path.join(BASE_DIR, "lookups")

# ── Load model artifacts at startup ──────────────────────────────────────────
print("Loading model artifacts...")

_model   = joblib.load(os.path.join(MODELS_DIR, "model.joblib"))
_scaler  = joblib.load(os.path.join(MODELS_DIR, "scaler.joblib"))

with open(os.path.join(MODELS_DIR, "feature_columns.json")) as f:
    _feature_cols: list[str] = json.load(f)

with open(os.path.join(MODELS_DIR, "training_medians.json")) as f:
    _medians: dict = json.load(f)

# Lookup tables (may not exist if preprocessing hasn't run yet)
_safe_domains: dict = {}
_unsafe_names: dict = {}

safe_path   = os.path.join(LOOKUPS_DIR, "safe_domains.json")
unsafe_path = os.path.join(LOOKUPS_DIR, "unsafe_names.json")

if os.path.exists(safe_path):
    with open(safe_path) as f:
        _safe_domains = json.load(f)

if os.path.exists(unsafe_path):
    with open(unsafe_path) as f:
        _unsafe_names = json.load(f)

with open(os.path.join(MODELS_DIR, "model_meta.json")) as f:
    _meta = json.load(f)

print(f"  Model: {_meta['model_type']}  |  Accuracy: {_meta['accuracy']}")
print(f"  Safe domains lookup: {len(_safe_domains)} entries")
print(f"  Unsafe names lookup: {len(_unsafe_names)} entries")
print("Ready.")

# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(title="TheThirdEye ML Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── URL feature extraction helpers ───────────────────────────────────────────

SUSPICIOUS_TLDS = {
    "xyz", "top", "buzz", "club", "gq", "ml", "tk", "cf", "ga",
    "work", "click", "loan", "download", "bid", "racing", "win", "stream",
    "online", "site", "website", "space", "fun",
}

TLD_LEGIT_PROB = {
    "com": 0.52, "org": 0.48, "net": 0.40, "edu": 0.85, "gov": 0.95,
    "io": 0.55, "co": 0.45, "uk": 0.50, "de": 0.50, "fr": 0.50,
    "jp": 0.55, "au": 0.55, "ca": 0.55, "in": 0.45, "us": 0.55,
}

BANK_KEYWORDS   = ["bank", "banking", "login", "signin", "account", "secure", "verify"]
PAY_KEYWORDS    = ["payment", "pay", "checkout", "billing", "credit", "card"]
CRYPTO_KEYWORDS = ["crypto", "bitcoin", "wallet", "btc", "eth", "nft", "coin"]


def _extract_domain(url: str) -> str:
    url = url.strip()
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0].split(":")[0]
    url = re.sub(r"^www\.", "", url)
    return url.lower()


def _is_ip(domain: str) -> int:
    return 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) else 0


def _get_tld(domain: str) -> str:
    parts = domain.split(".")
    return parts[-1] if len(parts) >= 2 else ""


def _url_features(url: str) -> dict:
    """Extract URL-based features that map directly to PhiUSIIL columns."""
    domain = _extract_domain(url)
    tld    = _get_tld(domain)
    parts  = domain.split(".")

    url_lower = url.lower()
    letters   = sum(1 for c in url if c.isalpha())
    digits    = sum(1 for c in url if c.isdigit())
    specials  = sum(1 for c in url if not c.isalnum() and c not in "/:.-_?=&#%")
    length    = len(url)

    return {
        "URLLength":            length,
        "DomainLength":         len(domain),
        "IsDomainIP":           _is_ip(domain),
        "TLDLength":            len(tld),
        "NoOfSubDomain":        max(0, len(parts) - 2),
        "IsHTTPS":              1 if url.lower().startswith("https://") else 0,
        "TLDLegitimateProb":    TLD_LEGIT_PROB.get(tld, 0.1 if tld in SUSPICIOUS_TLDS else 0.35),
        "URLCharProb":          round(letters / max(length, 1), 4),
        "NoOfLettersInURL":     letters,
        "LetterRatioInURL":     round(letters / max(length, 1), 4),
        "NoOfDegitsInURL":      digits,
        "DegitRatioInURL":      round(digits / max(length, 1), 4),
        "NoOfEqualsInURL":      url.count("="),
        "NoOfQMarkInURL":       url.count("?"),
        "NoOfAmpersandInURL":   url.count("&"),
        "NoOfOtherSpecialCharsInURL": specials,
        "SpacialCharRatioInURL": round(specials / max(length, 1), 4),
        "CharContinuationRate": _char_continuation(url),
        "HasObfuscation":       1 if "%2" in url or "%3" in url or "0x" in url_lower else 0,
        "NoOfObfuscatedChar":   url_lower.count("%"),
        "ObfuscationRatio":     round(url_lower.count("%") / max(length, 1), 4),
        "URLSimilarityIndex":   _url_similarity_index(domain),
        "Bank":                 int(any(k in url_lower for k in BANK_KEYWORDS)),
        "Pay":                  int(any(k in url_lower for k in PAY_KEYWORDS)),
        "Crypto":               int(any(k in url_lower for k in CRYPTO_KEYWORDS)),
    }


def _char_continuation(url: str) -> float:
    """Ratio of longest run of same char to total length."""
    if not url:
        return 0.0
    max_run = 1
    cur_run = 1
    for i in range(1, len(url)):
        if url[i] == url[i - 1]:
            cur_run += 1
            max_run = max(max_run, cur_run)
        else:
            cur_run = 1
    return round(max_run / len(url), 4)


_KNOWN_SAFE = {
    "google", "youtube", "facebook", "twitter", "instagram", "linkedin",
    "microsoft", "apple", "amazon", "netflix", "github", "wikipedia",
    "reddit", "stackoverflow", "mozilla", "cloudflare",
}


def _url_similarity_index(domain: str) -> float:
    """Rough similarity: 100 if exact known domain, lower if typosquat."""
    base = domain.split(".")[0] if "." in domain else domain
    if base in _KNOWN_SAFE:
        return 100.0
    # Check for near-matches (simple heuristic)
    for safe in _KNOWN_SAFE:
        if safe in base and base != safe:
            return 40.0  # looks like typosquat
    return 50.0


def _signals_to_features(url: str, signals: dict) -> np.ndarray:
    """
    Build a feature vector from URL + browser signals.
    1. Extract URL-based features directly
    2. Map browser signals to PhiUSIIL columns
    3. Fill remaining features with training medians
    """
    # Start with training medians as defaults
    features = dict(_medians)

    # Override with URL-derived features
    url_feats = _url_features(url)
    features.update(url_feats)

    # Map browser signals (names match what page-analyzer.js sends)
    s = signals or {}

    features["IsHTTPS"]         = 1 if s.get("isHTTPS", False) else 0
    features["HasPasswordField"] = 1 if int(s.get("passwordFields", 0)) > 0 else 0
    features["NoOfiFrame"]       = int(s.get("hiddenIframes", 0))
    features["NoOfJS"]           = int(s.get("externalScripts", 0))
    features["NoOfURLRedirect"]  = int(s.get("redirectCount", 0))
    features["Pay"]              = max(features["Pay"],
                                       1 if int(s.get("creditCardFields", 0)) > 0 else 0)
    features["HasSubmitButton"]  = 1 if int(s.get("totalForms", 0)) > 0 else 0
    features["NoOfPopup"]        = int(s.get("popupCount", 0))
    features["HasHiddenFields"]  = 1 if int(s.get("hiddenFields", 0)) > 0 else 0
    features["HasExternalFormSubmit"] = 1 if int(s.get("externalForms", 0)) > 0 else 0

    # Build ordered numpy array
    vec = np.array([features.get(col, 0.0) for col in _feature_cols], dtype=np.float32)
    return vec


def _score_to_verdict(score: float) -> str:
    if score < 30:
        return "dangerous"
    if score < 60:
        return "suspicious"
    return "safe"


# ── Request/Response schemas ──────────────────────────────────────────────────

class PredictURLRequest(BaseModel):
    url: str
    signals: Optional[Dict[str, Any]] = {}


class PredictFeaturesRequest(BaseModel):
    features: Dict[str, float]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model": _meta["model_type"],
        "accuracy": _meta["accuracy"],
        "safe_domains": len(_safe_domains),
    }


@app.post("/predict-url")
def predict_url(req: PredictURLRequest):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    domain = _extract_domain(url)

    # Fast bypass: known safe domain
    if domain in _safe_domains:
        entry = _safe_domains[domain]
        return {
            "score": 95,
            "verdict": "safe",
            "probability": 0.05,
            "source": "ml-lookup",
            "reasons": [f"Known safe site: {entry['name']} ({entry['category']})"],
            "category": "safe",
        }

    # Build feature vector and predict
    vec = _signals_to_features(url, req.signals)
    vec_scaled = _scaler.transform(vec.reshape(1, -1))

    proba = _model.predict_proba(vec_scaled)[0]
    # label=1 is safe, label=0 is phishing (as per PhiUSIIL dataset)
    phishing_prob = proba[0]
    safe_prob     = proba[1]

    score   = round((1 - phishing_prob) * 100)
    verdict = _score_to_verdict(score)

    reasons = []
    if req.signals:
        s = req.signals
        if int(s.get("passwordFields", 0)) > 0 and not s.get("isHTTPS", True):
            reasons.append("Password field on non-HTTPS page")
        if int(s.get("hiddenIframes", 0)) > 2:
            reasons.append(f"{s['hiddenIframes']} hidden iframes detected")
        if int(s.get("redirectCount", 0)) > 3:
            reasons.append(f"Excessive redirects ({s['redirectCount']})")
        if int(s.get("creditCardFields", 0)) > 0:
            reasons.append("Credit card field detected")
    if not req.signals.get("isHTTPS", True):
        reasons.append("No HTTPS")
    if _is_ip(domain):
        reasons.append("IP address used as domain")
    tld = _get_tld(domain)
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious TLD: .{tld}")

    if not reasons and verdict == "safe":
        reasons.append("No significant threat indicators detected")

    return {
        "score": score,
        "verdict": verdict,
        "probability": round(float(phishing_prob), 4),
        "source": "ml-model",
        "reasons": reasons,
        "category": "phishing" if verdict == "dangerous" else ("suspicious" if verdict == "suspicious" else "safe"),
    }


@app.post("/predict")
def predict_raw(req: PredictFeaturesRequest):
    """Predict from a raw feature dict (for testing/debugging)."""
    features = {col: req.features.get(col, _medians.get(col, 0.0)) for col in _feature_cols}
    vec = np.array([features[col] for col in _feature_cols], dtype=np.float32)
    vec_scaled = _scaler.transform(vec.reshape(1, -1))

    proba = _model.predict_proba(vec_scaled)[0]
    phishing_prob = proba[0]
    score   = round((1 - phishing_prob) * 100)
    verdict = _score_to_verdict(score)

    return {
        "score": score,
        "verdict": verdict,
        "probability": round(float(phishing_prob), 4),
        "source": "ml-model",
    }


if __name__ == "__main__":
    uvicorn.run("serve:app", host="0.0.0.0", port=5000, reload=False)
