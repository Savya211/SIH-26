/**
 * routes/analyze.js
 * POST /api/analyze — Receives page signals from the extension and returns threat analysis
 *
 * 4-Layer Defense Pipeline:
 *   Layer 1: Community Threat Lists  — instant lookup
 *   Layer 2: Heuristic Scoring       — fast local rules
 *   Layer 3: ML Model (Python :5000) — trained on 235K phishing URLs
 *   Layer 4: OpenRouter LLM          — fallback if ML unavailable
 */

import { heuristicScore } from '../services/scorer.js';
import { analyzePageWithAI } from '../services/openrouter.js';
import { isInThreatList, getThreatListSize } from '../services/threat-lists.js';
import { analyzeWithML } from '../services/ml-model.js';

export default function analyzeRoute(app) {
    app.post('/api/analyze', async (req, res) => {
        const signals = req.body;

        if (!signals || !signals.url) {
            return res.status(400).json({ error: 'Missing URL in request body' });
        }

        console.log(`[Analyze] Checking: ${signals.url}`);

        try {
            // ── Layer 1: Community Threat List (instant) ─────────────────────
            if (isInThreatList(signals.url)) {
                console.log(`[Analyze] BLOCKED by community threat list: ${signals.url}`);
                return res.json({
                    score: 0,
                    verdict: 'dangerous',
                    reasons: ['URL found in community malware/phishing threat database (URLhaus/OpenPhish)'],
                    category: 'malware',
                    source: 'threat-list',
                    blocked: true
                });
            }

            // ── Layer 2: Heuristic Analysis (fast, local) ────────────────────
            const heuristic = heuristicScore(signals);
            console.log(`[Analyze] Heuristic score: ${heuristic.score} (${heuristic.verdict})`);

            // Hard block on dangerous heuristic — no need to go further
            if (heuristic.verdict === 'dangerous') {
                return res.json({
                    ...heuristic,
                    category: 'suspicious',
                    source: 'heuristic',
                    blocked: true
                });
            }

            // ── Layer 3: ML Model (trained on PhiUSIIL — 235K URLs) ──────────
            // Called when heuristic is suspicious OR we want a second opinion on safe
            let mlResult = null;
            if (heuristic.verdict === 'suspicious') {
                console.log('[Analyze] Calling ML model (Layer 3)...');
                mlResult = await analyzeWithML(signals);
                if (mlResult) {
                    console.log(`[Analyze] ML result: score=${mlResult.score} verdict=${mlResult.verdict}`);
                } else {
                    console.warn('[Analyze] ML model unavailable, falling back to OpenRouter (Layer 4)');
                }
            }

            // ── Layer 4: OpenRouter LLM (fallback when ML is unavailable) ────
            // Only used if heuristic flagged suspicious AND ML didn't respond
            let aiResult = null;
            if (heuristic.verdict === 'suspicious' && !mlResult) {
                aiResult = await analyzePageWithAI(signals);
            }

            // ── Merge results ─────────────────────────────────────────────────
            const deepResult = mlResult || aiResult;
            if (deepResult) {
                const source = mlResult ? 'ml+heuristic' : 'ai+heuristic';
                console.log(`[Analyze] Deep result (${source}): score=${deepResult.score}`);

                // Use the more conservative (lower) score
                const finalScore = Math.min(heuristic.score, deepResult.score);
                const finalVerdict = finalScore < 30 ? 'dangerous' : finalScore < 60 ? 'suspicious' : 'safe';
                const allReasons = [...new Set([...heuristic.reasons, ...(deepResult.reasons || [])])];

                return res.json({
                    score: finalScore,
                    verdict: finalVerdict,
                    reasons: allReasons,
                    category: deepResult.category || 'unknown',
                    source,
                    blocked: finalVerdict === 'dangerous'
                });
            }

            // Heuristic-only result (safe pages or ML/AI both unavailable)
            return res.json({
                ...heuristic,
                category: 'unknown',
                source: 'heuristic',
                blocked: false
            });

        } catch (e) {
            console.error('[Analyze] Error:', e);
            return res.status(500).json({ error: 'Analysis failed', details: e.message });
        }
    });

    // Health check + stats
    app.get('/api/status', (req, res) => {
        res.json({
            status: 'running',
            threatListSize: getThreatListSize?.() || 0,
            version: '1.1.0',
            layers: {
                1: 'Community Threat Lists',
                2: 'Heuristic Scoring',
                3: 'ML Model (Python :5000)',
                4: 'OpenRouter LLM (fallback)'
            }
        });
    });
}
