# CyberShield — AI-Powered Email Forensic Intelligence, GeoLocation Tracing & Web Threat Defense System

> **Smart India Hackathon (SIH 2026)** | **Problem Statement**: AI-Powered Email Forensic Intelligence, GeoLocation Tracing & Web Threat Defense

![Platform](https://img.shields.io/badge/Platform-Chrome%20Extension%20%7C%20Web%20Dashboard-blue?style=for-the-badge&logo=googlechrome)
![Backend](https://img.shields.io/badge/Backend-Node.js%20Express%20%7C%20Python%20FastAPI-green?style=for-the-badge&logo=python)
![ML Model](https://img.shields.io/badge/ML%20Engine-Random%20Forest%20%28PhiUSIIL%20235K%29-purple?style=for-the-badge&logo=scikitlearn)
![GeoTrace](https://img.shields.io/badge/GIS%20Mapping-Leaflet.js%20%7C%20CartoDB-orange?style=for-the-badge&logo=leaflet)
![Manifest](https://img.shields.io/badge/Manifest-V3-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

---

## 🌟 Executive Summary

**CyberShield** is an enterprise-grade cyber defense and email forensic intelligence ecosystem developed for the **Smart India Hackathon (SIH 2026)**. It addresses two critical security challenges faced by modern organizations and citizens:

1. **Email Phishing & Business Email Compromise (BEC)**: Deep forensic investigation of `.eml` files through automated RFC 822 header parsing, live DNS-level authentication checks (SPF/DKIM/DMARC), NLP psychological urgency classification, ESP tracking domain resolution, hop-by-hop server geolocation tracing, and a transparent composite risk scoring algorithm.
2. **Real-time Web Threats & Privacy Protection**: Active browser defense via a Chrome Manifest V3 extension featuring inline Gmail thread scanning, Cyrillic/Greek homoglyph IDN spoof detection, zero-overhead tracker blocking, password breach checks via SHA-1 k-anonymity, search safety annotations, and HTTP security header grading.

---

## 🏗️ System Architecture & Data Flow

```text
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               USER / SOC ANALYST                                 │
└───────────────────────────────┬──────────────────────────────────┬───────────────┘
                                │                                  │
         ┌──────────────────────┴────────┐                ┌────────┴──────────────────────┐
         ▼                               │                ▼                               │
 ┌───────────────┐                       │        ┌────────────────┐                      │
 │ Chrome        │ Injects Gmail Badges, │        │ SOC Analyst    │ Interactively        │
 │ Extension     │ Scans Links & Pages,  │        │ Investigation  │ Uploads .eml Files,  │
 │ (Manifest V3) │ Blocks Trackers       │        │ Dashboard      │ Views GeoTrace Map   │
 └───────┬───────┘                       │        └───────┬────────┘                      │
         │                               │                │                               │
         │ JSON Threat Signals           │                │ POST /api/analyze (.eml)      │
         ▼                               │                ▼                               │
 ┌───────────────┐                       │        ┌────────────────┐                      │
 │ Node.js       │ Orchestrates Layer    │        │ Python FastAPI │ Multi-stage Parsing, │
 │ Backend API   │ 1-4 Detection Pipeline│        │ Forensic Engine│ GeoIP Hop Mapping,    │
 │ (:3000)       │                       │        │ (:5001)        │ Risk Engine           │
 └───────┬───────┘                       │        └───────┬────────┘                      │
         │                               │                │                               │
 ┌───────┴───────┬───────────────┐       │        ┌───────┴───────┬───────────────┐       │
 ▼               ▼               ▼       │        ▼               ▼               ▼       │
┌─────────┐ ┌───────────┐ ┌───────────┐  │  ┌───────────┐   ┌───────────┐   ┌───────────┐ │
│Layer 1: │ │Layer 2:   │ │Layer 3:   │  │  │RFC 822    │   │DNS Auth   │   │GeoIP &    │ │
│Threat   │ │Heuristics │ │FastAPI ML │  │  │Header     │   │Validator  │   │MaxMind    │ │
│Feeds    │ │Engine     │ │(:5000)    │  │  │Parser     │   │(SPF/DMARC)│   │Engine     │ │
└─────────┘ └───────────┘ └───────────┘  │  └───────────┘   └───────────┘   └───────────┘ │
                                         └────────────────────────────────────────────────┘
```

---

## 🧩 Core Ecosystem Components

CyberShield consists of 6 integrated sub-systems working in unison:

### 1. 📧 Email Forensic Intelligence Engine (`forensic-engine/` - FastAPI `:5001`)
* **Multi-Stage RFC 822 Header Parser**: Parses complex `Received:` relay chains, sender identities (`From`, `Return-Path`, `Reply-To`), authentication tags, and timestamp alignment.
* **Live DNS Authentication Validator**: Performs live TXT queries for **SPF** records and **DMARC** policy enforcement (`p=reject`, `p=quarantine`, `p=none`).
* **Guaranteed Authentication Immunity Rule**: If an email passes SPF, DKIM, and DMARC with aligned domain credentials, its risk score is strictly capped at **15 (BENIGN / SAFE)** to guarantee zero false positives on authentic corporate alerts and newsletters.
* **ESP Tracking Domain Whitelist**: Automatically recognizes legitimate Email Service Providers (e.g. `sendgrid.net`, `mailgun.net`, `mailchimp.com`, `amazonses.com`) and resolves wrapped URLs to true destinations without falsely flagging ESP infrastructure.
* **NLP Psychological & BEC Threat Classifier**: Scans body text and subject lines for high-pressure urgency cues ("Account Suspended", "Action Required within 24 Hours"), credential harvesting traps, and wire transfer lures.
* **Hop-by-Hop GeoTrace Module**: Extracts intermediate relay IP addresses, queries IP geolocation APIs (City, Country, Latitude, Longitude, ISP, ASN), and constructs spatial hop routes.
* **Forensic Case Management API**: Automatically generates SHA-256 case IDs (`CASE-xxxx`), saves detailed JSON forensic reports in `data/cases/`, and provides full REST endpoints including history deletion (`DELETE /api/cases`).

### 2. 📊 SOC Analyst Investigation Dashboard (`analyst-dashboard/` - `:8080`)
* **Interactive Dark CartoDB GIS Map**: Powered by Leaflet.js, visualizing sender relay nodes, geographic paths, and server hop points with animated polylines and pulse indicators.
* **SVG Threat Score Gauge**: Displays overall threat score ($0 - 100$) with real-time color transitions:
  * 🔴 **CRITICAL PHISHING** ($80 - 100$)
  * 🟠 **HIGH RISK** ($60 - 79$)
  * 🟡 **SUSPICIOUS** ($30 - 59$)
  * 🟢 **SAFE / BENIGN** ($0 - 29$)
* **Sub-Score Breakdown Panels**: Highlights distinct sub-scores for *Authentication*, *Urgency/NLP*, *URL Safety*, and *Header Integrity*.
* **Raw Header Inspector**: Includes line-by-line syntax highlighting for deep header examination.
* **Case History & Deletion Controls**: Single-click case removal or bulk history purging synced directly with the backend API.
* **Built-in Demo Payloads**: One-click execution cards for *Spoofed Bank Alert*, *Executive BEC Request*, and *Clean Corporate Newsletter*.

### 3. 🧩 Chrome Browser Extension (`manifest.json` — Manifest V3)
* **Inline Gmail Threat Scanner**: Injects safety badges directly into Gmail email headers and scans links before user interaction.
* **Homoglyph IDN Spoof Detector**: Flags Cyrillic/Greek character substitution attacks (e.g. `gооgle.com` using `U+043E` Cyrillic 'о').
* **Password Breach Shield**: Checks typed passwords against Have I Been Pwned (HIBP) database using SHA-1 **k-Anonymity** (only the first 5 hash characters leave the browser).
* **Declarative Tracker Blocker**: Uses Manifest V3 `declarativeNetRequest` rules to block tracking pixels and telemetry scripts with zero CPU overhead.
* **Google Search Annotator**: Injects risk indicators alongside Google search results.
* **Security Headers Grader**: Analyzes site HTTP response headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`) and awards grades from **A+ to F**.

### 4. ⚙️ Node.js Orchestration Backend (`backend/` - Express `:3000`)
* Exposes unified REST endpoints (`/api/analyze`, `/api/reputation`, `/api/check-urls`, `/api/scan-email`).
* Combines multi-layer feeds into a single consensus verdict.

### 5. 🧠 Machine Learning Classifier Microservice (`eai/` - FastAPI `:5000`)
* Trained on the **PhiUSIIL Phishing URL Dataset** (235,000 URLs, 52 lexical/structural features).
* Employs Random Forest and Logistic Regression models achieving **97.8% Accuracy** and **0.991 ROC-AUC**.

### 6. 🌐 Public Project Portal (`website/`)
* Product overview, feature highlights, interactive demo links, and documentation links.

---

## 🔬 Threat Scoring & Forensic Algorithm

The composite threat score $S_{threat} \in [0, 100]$ is calculated as follows:

$$S_{threat} = \min\left(100, \sum_{i=1}^{4} w_i \cdot S_i + \delta_{penalty}\right)$$

### Sub-Score Matrix
| Sub-Score Component | Weight ($w_i$) | Key Evaluation Criteria |
| :--- | :---: | :--- |
| **Authentication Deficit ($S_1$)** | $0.35$ | SPF failure, DMARC policy violations, domain alignment mismatch between `From`, `Reply-To`, and `Return-Path`. |
| **Psychological Urgency ($S_2$)** | $0.25$ | NLP term frequencies targeting urgency, account suspension threats, wire transfers, and credential verification. |
| **Link & Infrastructure Risk ($S_3$)** | $0.25$ | Direct IP links, reverse proxy tunnels (`ngrok`, `serveo`), suspicious TLDs, double-extension attachments (`.pdf.exe`). |
| **Header Integrity ($S_4$)** | $0.15$ | Missing RFC Message-ID, timestamp misalignment, excessive relay hops ($> 8$). |

### Special Rules & Constraints
* **Guaranteed Authentication Immunity**: If $\text{SPF} = \text{PASS}$, $\text{DKIM} = \text{PASS}$, and $\text{DMARC} = \text{PASS}$ with domain alignment, $S_{threat} \le 15$.
* **Dual-Authentication Failure Penalty**: If both SPF and DMARC fail, a flat penalty $\delta_{penalty} = +20$ is added.

---

## 📑 REST API Catalog

### 📧 Email Forensic Engine (`http://localhost:5001`)

| Method | Endpoint | Description | Payload / Query |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze` | Analyze uploaded `.eml` binary file | `multipart/form-data` (`file`) |
| `POST` | `/api/analyze-demo/{name}` | Analyze preset demo payload | `spoofed_bank.eml`, `ceo_wire_transfer.eml`, `clean_newsletter.eml` |
| `GET` | `/api/cases` | Retrieve list of all forensic cases | None |
| `GET` | `/api/cases/{case_id}` | Retrieve full case details | `case_id` string |
| `DELETE`| `/api/cases/{case_id}` | Delete specific case record | `case_id` string |
| `DELETE`| `/api/cases` | Purge all stored case histories | None |
| `GET` | `/health` | Check service health & metrics | None |

### ⚙️ Node.js Backend (`http://localhost:3000`)

| Method | Endpoint | Description | Payload |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/analyze` | 4-layer URL threat evaluation | `{ "url": "http://example.com" }` |
| `POST` | `/api/check-urls` | Bulk URL batch verification | `{ "urls": ["http://site1.com", "http://site2.com"] }` |
| `GET` | `/api/reputation` | Query domain reputation score | `?domain=example.com` |

---

## 📁 Repository Directory Structure

```text
CyberShield/
├── manifest.json               # Chrome Extension Manifest V3 configuration
├── PROJECT_DOCUMENTATION.md    # Master technical specification document
├── generate_pdf.py             # PDF documentation builder script
├── README.md                   # Project landing documentation
│
├── forensic-engine/            # Python FastAPI Forensic Intelligence Engine (:5001)
│   ├── main.py                 # FastAPI server entrypoint & API routes
│   ├── requirements.txt        # Python dependency manifest
│   ├── create_test_emails.py   # Demo .eml generator utility
│   ├── parsers/                # Email parsing suite
│   │   ├── header_parser.py    # RFC 822 header & hop parser
│   │   ├── body_parser.py      # HTML, link, ESP whitelist & attachment parser
│   │   └── auth_validator.py   # Live SPF/DMARC DNS validator
│   ├── analyzers/              # Analysis & scoring engines
│   │   ├── nlp_engine.py       # Psychological urgency & BEC analyzer
│   │   ├── url_analyzer.py     # Link safety & tunnel domain classifier
│   │   ├── geo_tracer.py       # Hop-by-hop IP geolocation engine
│   │   └── risk_scorer.py      # Composite scoring matrix & immunity rules
│   └── data/cases/             # Stored JSON forensic case reports
│
├── analyst-dashboard/          # SOC Analyst Investigation Dashboard UI (:8080)
│   ├── index.html              # Main HTML5 dashboard interface
│   ├── style.css               # Dark cyberpunk design system
│   ├── app.js                  # Dashboard controller & history integration
│   └── map.js                  # Leaflet.js CartoDB map renderer
│
├── background/                 # Chrome Extension Service Worker
│   └── service-worker.js       # Extension threat orchestrator
│
├── content/                    # Extension Content Scripts
│   ├── gmail-scanner.js        # Gmail inline scanner
│   ├── homoglyph-detector.js   # IDN lookalike domain detector
│   ├── password-monitor.js     # HIBP k-anonymity breach shield
│   ├── search-scanner.js       # Google search result annotator
│   └── mixed-content-detector.js # Insecure HTTP content scanner
│
├── popup/                      # Extension Multi-Tab Interface
│   ├── popup.html / popup.css / popup.js
│
├── backend/                    # Node.js Express Orchestration Backend (:3000)
│   ├── server.js / routes/ / services/
│
├── eai/                        # ML Model Microservice (:5000)
│   ├── train.py / serve.py / evaluate.py / models/
│
└── website/                    # Public Product Landing Site
```

---

## 🚀 Installation & Setup Guide

### System Prerequisites
* **Node.js**: v18.0.0 or higher
* **Python**: v3.10.0 or higher
* **Browser**: Google Chrome, Microsoft Edge, or Brave

### Step 1: Launch the Email Forensic Engine
```powershell
cd forensic-engine
pip install -r requirements.txt
python main.py
```
> Forensic Engine active at `http://localhost:5001`. API Documentation at `http://localhost:5001/docs`.

### Step 2: Launch the Analyst Dashboard
```powershell
cd analyst-dashboard
python -m http.server 8080
```
> Open **[http://localhost:8080](http://localhost:8080)** in your browser.

### Step 3: Launch the Node.js Backend & ML Microservice (Optional for full extension support)
```powershell
# Node.js Backend
cd backend
npm install
npm start

# ML Microservice
cd eai
pip install -r requirements.txt
python serve.py
```

### Step 4: Load the Chrome Extension
1. Open Chrome/Edge and navigate to `chrome://extensions/`.
2. Toggle **Developer Mode** on in the top right corner.
3. Click **Load Unpacked** and select the root project directory (`CyberShield/`).

---

## 🧪 Testing & Verification

1. **Test Demo Payloads**: On the Analyst Dashboard (`http://localhost:8080`), click any demo card (*Spoofed Bank Alert*, *Executive Wire Transfer*, *Clean Newsletter*) for instant forensic analysis.
2. **Upload Custom `.eml`**: Drag and drop any `.eml` file onto the dashboard upload box to run real-time DNS auth, GeoTrace hop mapping, and NLP analysis.
3. **Extension Gmail Scan**: Open Gmail in Chrome with the extension active to view inline security badges on incoming messages.

---

## 📜 PDF Documentation Deliverable

An executive-grade printable PDF document containing complete technical specifications, architecture diagrams, API references, and deployment guides is available in the repository root:
📄 **[CyberShield_Project_Specification.pdf](file:///c:/Users/DELL/OneDrive/Desktop/SIH'26/TheThirdEye/CyberShield_Project_Specification.pdf)**

---

## ⚖️ License & Acknowledgments

This project is released under the **MIT License**. Built with pride for **Smart India Hackathon (SIH 2026)**.

