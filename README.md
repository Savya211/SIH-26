# AegisMail / TheThirdEye — AI-Powered Email Forensic & Web Threat Intelligence Platform

> **Smart India Hackathon (SIH 2026)** | Problem Statement / Open Innovation Project: **AI-Powered Email Forensic Intelligence, GeoLocation Tracing & Web Threat Defense**

![Chrome Extension](https://img.shields.io/badge/Platform-Chrome%20Extension-blue)
![FastAPI](https://img.shields.io/badge/Backend-Python%20FastAPI-green)
![Leaflet](https://img.shields.io/badge/Dashboard-Leaflet.js%20GeoTrace-orange)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 🌟 Overview

**AegisMail / TheThirdEye** is an enterprise-grade cybersecurity platform that combines:
1. 🛡️ **Browser Extension (Manifest V3)** — Real-time phishing URL detection, Gmail inline threat scanning, homoglyph lookalike domain detection, password breach monitoring, and tracker blocking.
2. 🕵️‍♂️ **Email Forensic Engine (FastAPI)** — Multi-stage RFC 822 email header parser, SPF/DKIM/DMARC authentication validator, NLP-driven body urgency analysis, credential harvesting detection, and hop-by-hop IP geolocation tracer.
3. 🗺️ **Analyst Investigation Dashboard (Leaflet.js)** — Dark-mode SOC analyst UI with animated GeoTrace world map, real-time threat score dials, sub-score breakdown, NLP threat indicators, and raw header inspector.

---

## ✨ Features

### 📧 Email Forensic Intelligence Engine (`forensic-engine/`)
- **RFC 822 Header Parsing**: Extracts `Received:` chain headers, `Reply-To` anomalies, and sender domain alignment.
- **Email Authentication Validation**: Performs live DNS lookups for SPF records and DMARC policies (`p=reject`, `p=quarantine`, `p=none`).
- **Body & URL NLP Analysis**: Scans email content for urgency keywords, financial lure phrases, double extension attachments (`.pdf.exe`), and suspicious tunnel domains (`ngrok`, `serveo`, `loclx`).
- **GeoTrace Relay Mapping**: Traces every server hop across the globe using IP geolocation services to pinpoint origin IPs.
- **Risk Scoring Matrix**: Calculates a composite 0-100 Threat Score and outputs verdicts (`CRITICAL PHISHING`, `HIGH RISK`, `SUSPICIOUS`, `SAFE`).

### 📊 Analyst Investigation Dashboard (`analyst-dashboard/`)
- **Interactive GeoTrace Map**: Dark CartoDB basemap with animated polylines showing the physical journey of an email from origin server to target inbox.
- **Real-Time Risk Dial**: Animated CSS SVG gauge showing threat score and verdict badge.
- **Deep-Dive Sub-Scores**: Displays separate ratings for Authentication, Urgency/Psychological Manipulation, Link/Domain Safety, and Header Integrity.
- **Raw Header Inspector**: Code view with syntax highlighting to inspect original email headers.
- **One-Click Demo Payloads**: Quick buttons to test `Spoofed Bank Alert`, `Executive Phishing`, and `Clean Newsletter`.

### 🧩 Chrome Browser Extension (`manifest.json` — Manifest V3)
- **Gmail Scanner**: Scans links and sender credentials directly inside the Gmail browser interface.
- **Homoglyph Attack Detector**: Identifies internationalized domain name (IDN) spoofing (e.g. `gооgle.com`).
- **Password Breach Shield**: SHA-1 k-Anonymity breach checking against HIBP database.
- **Tracker Blocker**: DeclarativeNetRequest rules blocking dynamic web trackers with zero runtime overhead.
- **Google Search Safety Annotator**: Displays threat badges next to search result links.

---

## 🏗️ Project Structure

```text
TheThirdEye/
├── manifest.json              # Chrome Extension manifest (V3)
├── analyst-dashboard/         # SOC Analyst Dashboard
│   ├── index.html             #   Main Dashboard UI
│   ├── style.css              #   Cyberpunk dark design system
│   ├── app.js                 #   Dashboard state & API integration
│   └── map.js                 #   Leaflet GeoTrace map module
├── forensic-engine/           # Python FastAPI Forensic Engine
│   ├── main.py                #   FastAPI REST API server (:5001)
│   ├── create_test_emails.py  #   Generates demo .eml payloads
│   ├── requirements.txt       #   Python dependencies
│   ├── parsers/               #   Header, body, auth & hop parsers
│   └── analyzers/              #   NLP urgency engine & risk scorer
├── background/                # Extension background service worker
├── content/                   # Extension content scripts
│   ├── gmail-scanner.js       #   Gmail DOM scanner
│   ├── page-analyzer.js       #   Webpage 23+ signal extractor
│   ├── homoglyph-detector.js  #   Lookalike domain detector
│   └── password-monitor.js    #   HIBP password breach monitor
├── popup/                     # Extension popup interface (7 tabs)
├── rules/                     # Declarative tracker blocking rules
├── assets/                    # Platform icons & media
└── website/                   # Landing page
```

---

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.10+
- Google Chrome, Microsoft Edge, or Brave Browser

### 1. Run the Forensic Engine (Backend)

```powershell
cd forensic-engine
pip install -r requirements.txt
python main.py
```
> The API server will start at `http://localhost:5001`. View interactive API docs at `http://localhost:5001/docs`.

### 2. Run the Analyst Dashboard (Frontend)

```powershell
cd analyst-dashboard
python -m http.server 8080
```
> Open your browser and navigate to **[http://localhost:8080](http://localhost:8080)**.

### 3. Load the Chrome Browser Extension

1. Open Chrome/Edge and go to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle).
3. Click **Load unpacked** and select the root directory `TheThirdEye`.

---

## 🧪 Testing Demo Email Payloads

You can generate sample `.eml` test files using:

```powershell
cd forensic-engine
python create_test_emails.py
```

Generated payloads:
- `spoofed_bank.eml` — Critical phishing email impersonating Chase Bank with SPF/DMARC failure and high urgency.
- `ceo_wire_transfer.eml` — High-risk BEC (Business Email Compromise) wire transfer request.
- `clean_newsletter.eml` — Legitimate newsletter from GitHub with valid authentication.

Upload these `.eml` files directly into the Analyst Dashboard or click the demo cards to view instant forensic analysis.

---

## 📜 License

Distributed under the [MIT License](LICENSE).
