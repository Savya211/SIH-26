# CyberShield — AI-Powered Email Forensic & Web Threat Intelligence Platform

> **Smart India Hackathon (SIH 2026)** | Problem Statement: **AI-Powered Email Forensic Intelligence, GeoLocation Tracing & Web Threat Defense**

![Chrome Extension](https://img.shields.io/badge/Platform-Chrome%20Extension-blue)
![Node.js](https://img.shields.io/badge/Backend-Node.js%20Express-green)
![FastAPI](https://img.shields.io/badge/Forensics%20%2F%20ML-Python%20FastAPI-green)
![Leaflet](https://img.shields.io/badge/Dashboard-Leaflet.js%20GeoTrace-orange)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🌟 Overview

**CyberShield** is an enterprise-grade cybersecurity platform combining a browser extension, a multi-layer threat-detection backend, and an analyst investigation dashboard:

1. 🧩 **Browser Extension (Manifest V3)** — Real-time phishing URL detection, Gmail inline threat scanning, homoglyph lookalike domain detection, password breach monitoring, tracker blocking, and mixed-content warnings.
2. ⚙️ **Node.js Backend (`backend/`)** — Orchestrates a 4-layer defense pipeline for URL/page analysis and exposes REST endpoints the extension calls.
3. 🧠 **ML Microservice (`eai/`)** — FastAPI service serving a phishing-URL classifier trained on the PhiUSIIL dataset (235K URLs).
4. 🕵️ **Email Forensic Engine (`forensic-engine/`)** — FastAPI service that parses raw `.eml` files, validates SPF/DKIM/DMARC, runs NLP urgency analysis, and traces the server hop chain by IP geolocation.
5. 🗺️ **Analyst Investigation Dashboard (`analyst-dashboard/`)** — Dark-mode SOC UI with an animated GeoTrace world map, threat-score dial, sub-score breakdown, and raw header inspector.
6. 🌐 **Landing Page (`website/`)** — Public-facing marketing/info site for the project.

---

## 🏗️ Architecture

```text
Browser Extension  ──▶  Node.js Backend (:3000)
                              │
                              ├── Layer 1: Community Threat Lists (URLhaus / OpenPhish)
                              ├── Layer 2: Heuristic Scoring Engine (scorer.js)
                              ├── Layer 3: ML Model Microservice — eai/ (:5000)
                              └── Layer 4: OpenRouter LLM Analysis (fallback / deep reasoning)

Uploaded .eml file ──▶  Forensic Engine — forensic-engine/ (:5001)  ──▶  Analyst Dashboard (:8080)
```

---

## ✨ Features

### 🧩 Chrome Browser Extension (Manifest V3)
- **Gmail Scanner** — scans links and sender credentials inline inside Gmail.
- **Homoglyph Attack Detector** — flags internationalized domain name (IDN) spoofing (e.g. `gооgle.com`).
- **Password Breach Shield** — SHA-1 k-Anonymity checks against the HIBP database, done locally.
- **Tracker Blocker** — `declarativeNetRequest` rules block trackers with zero runtime overhead.
- **Google Search Safety Annotator** — threat badges next to search result links.
- **Mixed-Content Detector** — flags insecure resources loaded on HTTPS pages.

### ⚙️ Node.js Backend (`backend/`)
- REST routes: `analyze`, `reputation`, `check-urls`, `scan-email`, `send-report`.
- Coordinates threat lists, heuristics, the ML microservice, and an LLM fallback into one verdict.

### 🧠 ML Phishing Classifier (`eai/`)
- Trained on the **PhiUSIIL dataset** (235K URLs, 52 features) using Logistic Regression / Random Forest.
- Serves predictions via FastAPI (`/predict-url`, `/predict`, `/health`).

### 📧 Email Forensic Intelligence Engine (`forensic-engine/`)
- RFC 822 header parsing (`Received:` chain, `Reply-To` anomalies, sender/domain alignment).
- Live SPF/DMARC DNS validation (`p=reject`, `p=quarantine`, `p=none`).
- Body & URL NLP analysis — urgency keywords, financial lures, double-extension attachments (`.pdf.exe`), suspicious tunnel domains (`ngrok`, `serveo`, `loclx`).
- GeoTrace relay mapping across every server hop.
- Composite 0–100 threat score with verdicts (`CRITICAL PHISHING`, `HIGH RISK`, `SUSPICIOUS`, `SAFE`).

### 📊 Analyst Investigation Dashboard (`analyst-dashboard/`)
- Interactive GeoTrace map (dark CartoDB basemap, animated polylines).
- Real-time animated SVG risk-score dial with verdict badge.
- Sub-score breakdown: Authentication, Urgency/Manipulation, Link/Domain Safety, Header Integrity.
- Raw header inspector with syntax highlighting.
- One-click demo payloads: *Spoofed Bank Alert*, *Executive Phishing*, *Clean Newsletter*.

---

## 📁 Project Structure

```text
CyberShield/
├── manifest.json               # Chrome Extension manifest (V3)
├── background/                 # Extension background service worker
├── content/                    # Extension content scripts (Gmail, homoglyph, password, mixed-content)
├── popup/                      # Extension popup UI (multi-tab)
├── pages/                      # Extension warning/interstitial page
├── lib/                        # Shared extension libs (crypto, constants, header-grader, domain-reputation)
├── rules/                      # Declarative tracker-blocking rules
├── assets/                     # Icons & media
│
├── backend/                    # Node.js/Express orchestration API (:3000)
│   ├── server.js
│   ├── routes/                 #   analyze, reputation, check-urls, scan-email, send-report
│   └── services/                #   threat-lists, scorer, ml-model, openrouter
│
├── eai/                        # Python FastAPI ML microservice (:5000)
│   ├── serve.py / train.py / evaluate.py
│   ├── models/                 #   trained model artifacts
│   └── lookups/                #   safe/unsafe domain lookups
│
├── forensic-engine/            # Python FastAPI email forensic engine (:5001)
│   ├── main.py
│   ├── parsers/                #   header, body, auth, hop parsers
│   ├── analyzers/              #   NLP urgency engine & risk scorer
│   ├── create_test_emails.py   #   generates demo .eml payloads
│   └── test_emails/            #   sample .eml files
│
├── analyst-dashboard/          # SOC analyst dashboard UI (:8080)
├── dataset/                    # PhiUSIIL phishing URL dataset + safe/unsafe site lists
├── website/                    # Public landing page
├── tests/                      # Jest test suite (extension libs)
└── PROJECT_DOCUMENTATION.md    # Full project write-up
```

---

## 🚀 Quick Start

### Prerequisites
- Node.js 18+
- Python 3.10+
- Google Chrome, Microsoft Edge, or Brave Browser

### 1. Node.js Backend (`:3000`)
```bash
cd backend
npm install
npm start
```

### 2. ML Microservice (`:5000`)
```bash
cd eai
pip install -r requirements.txt
python train.py      # first run only — trains and saves model artifacts
python serve.py
```

### 3. Email Forensic Engine (`:5001`)
```bash
cd forensic-engine
pip install -r requirements.txt
python main.py
```
> Interactive API docs at `http://localhost:5001/docs`.

### 4. Analyst Dashboard (`:8080`)
```bash
cd analyst-dashboard
python -m http.server 8080
```
> Open `http://localhost:8080`.

### 5. Load the Chrome Extension
1. Go to `chrome://extensions/`.
2. Enable **Developer Mode**.
3. Click **Load unpacked** and select the project root (`CyberShield/`).

---

## 🧪 Testing

**Extension unit tests (Jest):**
```bash
npm install
npm test
```

**Demo email payloads for the Forensic Engine:**
```bash
cd forensic-engine
python create_test_emails.py
```
Generates `spoofed_bank.eml`, `beef_attack.eml`, and `benign_corporate.eml` — upload these to the Analyst Dashboard or use the built-in demo cards for instant forensic analysis.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
