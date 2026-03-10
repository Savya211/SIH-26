# TheThirdEye

A privacy-focused Chrome Extension that protects users from online threats using a **4-layer defense pipeline** — community threat lists, heuristic analysis, machine learning, and LLM fallback — all while keeping your data local.

![Chrome Extension](https://img.shields.io/badge/Platform-Chrome%20Extension-blue)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Password Breach Detection** — Uses Have I Been Pwned (HIBP) via k-Anonymity. Passwords are SHA-1 hashed locally; only the first 5 characters of the hash are ever sent.
- **4-Layer Phishing Detection** — Community threat feeds (URLhaus + OpenPhish) → heuristic scoring → ML model (RandomForest trained on 235K URLs) → LLM fallback for zero-day threats.
- **Tracker Blocking** — Blocks known tracking networks using Manifest V3 declarativeNetRequest API with zero performance overhead.
- **Cookie Management** — View and bulk-delete cookies for any site from the popup.
- **Security Headers Grading** — Grades site security headers from A to F.
- **Gmail Phishing Scanner** — Scans email links for threats directly in Gmail.
- **Homoglyph Detection** — Catches lookalike domains (e.g., `goog1e.com`).
- **Search Result Annotations** — Adds safety indicators to Google search results.
- **WebRTC Leak Prevention** — Forces UDP traffic through proxies to prevent IP leaks.
- **Real-time Dashboard** — Dark-mode popup with 7 tabs (Overview, Passwords, Threats, Trackers, Cookies, Network, Settings) plus a fullscreen analytics view.

## Architecture

```
Browser Navigation
    │
    ▼
Content Scripts ──► Service Worker ──► Backend (Express :3000)
(extract signals)   (orchestrate)       │
                                        ├─ Layer 1: Threat Lists (URLhaus + OpenPhish)
                                        ├─ Layer 2: Heuristic Scoring (rules engine)
                                        ├─ Layer 3: ML Model (FastAPI :5000)
                                        └─ Layer 4: LLM Fallback (OpenRouter)
                                        │
                                        ▼
                                    Verdict + Score + Reasons
                                        │
                                        ▼
                                Warning Page / Badge Update
```

## Project Structure

```
TheThirdEye/
├── manifest.json              # Chrome Extension manifest (V3)
├── background/                # Service worker
├── content/                   # Content scripts
│   ├── page-analyzer.js       #   DOM signal extraction (23+ signals)
│   ├── password-monitor.js    #   HIBP breach checking
│   ├── homoglyph-detector.js  #   Lookalike domain detection
│   ├── search-scanner.js      #   Google search annotations
│   ├── mixed-content-detector.js
│   └── gmail-scanner.js       #   Gmail link scanning
├── popup/                     # Extension popup UI (7 tabs)
│   ├── popup.html
│   └── components/            #   Tab components
├── dashboard/                 # Fullscreen analytics dashboard
├── pages/                     # Warning/block pages
├── lib/                       # Shared utilities
├── rules/                     # Tracker blocking rules
├── assets/                    # Icons
├── backend/                   # Node.js Express backend
│   ├── server.js              #   Entry point (:3000)
│   ├── routes/                #   API endpoints
│   └── services/              #   Threat lists, scorer, ML bridge, LLM
├── eai/                       # Python ML microservice
│   ├── train.py               #   Model training (PhiUSIIL dataset)
│   ├── serve.py               #   FastAPI server (:5000)
│   ├── evaluate.py            #   Metrics & evaluation
│   └── requirements.txt
├── tests/                     # Jest test suite
├── dataset/                   # Training data (gitignored)
└── website/                   # Marketing/landing page
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Extension | Vanilla JavaScript, Chrome Manifest V3 |
| Backend | Node.js, Express |
| ML Service | Python, FastAPI, scikit-learn (RandomForest / LogisticRegression) |
| LLM Fallback | OpenRouter API |
| Testing | Jest |

## Getting Started

### Prerequisites

- Google Chrome
- Node.js 18+
- Python 3.10+ (for ML service)

### 1. Install the Extension

1. Open `chrome://extensions`
2. Enable **Developer Mode**
3. Click **Load Unpacked** and select this directory

### 2. Start the Backend

```bash
cd backend
npm install
cp .env.example .env   # Add your OpenRouter API key
npm start               # Runs on :3000
```

### 3. Start the ML Service (Optional)

```bash
cd eai
pip install -r requirements.txt
python train.py         # Train the model (first time only)
python serve.py         # Runs on :5000
```

### API Keys

| Key | Where | Required |
|-----|-------|----------|
| OpenRouter API Key | `backend/.env` | Optional (Layer 4 fallback) |
| Google Safe Browsing | Extension Settings tab | Optional |
| PhishTank | Extension Settings tab | Optional |

The extension works without API keys but with reduced coverage for dynamic lookups.

## ML Model

- **Dataset**: PhiUSIIL — 235,000 phishing and legitimate URLs with 52 extracted features
- **Features**: URL length, domain reputation, TLD legitimacy, HTML structure, form presence, iframe count, etc.
- **Models**: RandomForest and LogisticRegression (best is auto-selected during training)
- **Accuracy**: >90% on test set

To evaluate:
```bash
cd eai
python evaluate.py      # Prints accuracy, ROC-AUC, confusion matrix
```

## Testing

```bash
npm test
```

Tests cover SHA-1 hashing, homoglyph detection, phishing heuristics, and tracker rules.

## License

[MIT](LICENSE)
