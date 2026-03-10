/**
 * server.js - TheThirdEye Backend Server
 * Provides AI-powered page analysis for the browser extension.
 *
 * 4-Layer Defense:
 *   1. Community Threat Lists (URLhaus + OpenPhish) — instant lookup
 *   2. Heuristic Scoring Engine       — fast local rules
 *   3. ML Model (Python FastAPI :5000) — trained on 235K phishing URLs  [NEW]
 *   4. OpenRouter LLM Analysis        — deep AI reasoning (fallback)
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { loadThreatLists, getThreatListSize } from './services/threat-lists.js';
import { checkMLHealth } from './services/ml-model.js';
import analyzeRoute from './routes/analyze.js';
import reputationRoute from './routes/reputation.js';
import checkUrlsRoute from './routes/check-urls.js';
import scanEmailRoute from './routes/scan-email.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '1mb' }));

// Request logging
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// Routes
analyzeRoute(app);
reputationRoute(app);
checkUrlsRoute(app);
scanEmailRoute(app);

// Root info
app.get('/', (req, res) => {
    res.json({
        name: 'TheThirdEye Backend',
        version: '1.1.0',
        status: 'online',
        threatListSize: getThreatListSize(),
        endpoints: {
            'POST /api/analyze': 'Analyze a page for threats',
            'POST /api/check-urls': 'Batch URL safety check',
            'GET /api/status': 'Server status and stats'
        }
    });
});

// Start server
async function start() {
    console.log('🛡️  TheThirdEye Backend Server');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

    // Load community threat lists on startup
    console.log('[Startup] Loading community threat lists...');
    await loadThreatLists();

    // Refresh threat lists every hour
    setInterval(loadThreatLists, 60 * 60 * 1000);

    // Check ML microservice availability
    console.log('[Startup] Checking ML model service (http://localhost:5000)...');
    const mlHealth = await checkMLHealth();
    if (mlHealth) {
        console.log(`[Startup] ✅ ML model online — type: ${mlHealth.model}, accuracy: ${mlHealth.accuracy}`);
        console.log(`[Startup]    Safe domains lookup: ${mlHealth.safe_domains} entries`);
    } else {
        console.warn('[Startup] ⚠️  ML model service not running. Layer 3 will be skipped.');
        console.warn('[Startup]    Start it with: cd eai && python serve.py');
    }

    app.listen(PORT, () => {
        console.log(`[Startup] Server running on http://localhost:${PORT}`);
        console.log(`[Startup] OpenRouter API key: ${process.env.OPENROUTER_API_KEY ? '✅ Configured' : '❌ Not set (AI fallback disabled)'}`);
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    });
}

start();
