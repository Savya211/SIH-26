/**
 * services/openrouter.js
 * OpenRouter API integration for LLM-based page analysis
 */

import dotenv from 'dotenv';
dotenv.config();

const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

export async function analyzePageWithAI(pageSignals) {
    if (!OPENROUTER_API_KEY || OPENROUTER_API_KEY === 'your_openrouter_api_key_here') {
        console.warn('[OpenRouter] API key not configured. Using heuristic-only analysis.');
        return null;
    }

    const prompt = buildAnalysisPrompt(pageSignals);

    try {
        const response = await fetch(OPENROUTER_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
                'Content-Type': 'application/json',
                'HTTP-Referer': 'https://thethirdeye-extension.local',
                'X-Title': 'TheThirdEye Security Extension'
            },
            body: JSON.stringify({
                model: 'google/gemini-2.0-flash-001',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a cybersecurity analyst AI. You analyze webpage signals and determine if a page is safe, suspicious, or dangerous. You MUST respond with valid JSON only, no markdown, no explanation outside the JSON.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                max_tokens: 300,
                temperature: 0.1
            })
        });

        if (!response.ok) {
            const errText = await response.text();
            console.error('[OpenRouter] API error:', response.status, errText);
            return null;
        }

        const data = await response.json();
        const content = data.choices?.[0]?.message?.content;

        if (!content) return null;

        // Parse the JSON response from the LLM
        const cleaned = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
        return JSON.parse(cleaned);

    } catch (e) {
        console.error('[OpenRouter] Analysis error:', e.message);
        return null;
    }
}

function buildAnalysisPrompt(signals) {
    const keywords = Array.isArray(signals.suspiciousKeywords) ? signals.suspiciousKeywords.join(', ') : 'none';

    return `Analyze this webpage for security threats. Consider phishing, malware distribution, scams, and fraud.

URL: ${signals.url}
Page Title: "${signals.title || 'Unknown'}"
Domain Age: ${signals.domainAge || 'Unknown'}

PAGE STRUCTURE:
- Password fields: ${signals.passwordFields || 0}
- Credit card fields: ${signals.creditCardFields || 0}
- Total forms: ${signals.totalForms || 0}
- Hidden iframes: ${signals.hiddenIframes || 0}
- External scripts: ${signals.externalScripts || 0} (from ${signals.uniqueScriptDomains || 0} unique domains)
- Auto-download attempts: ${signals.autoDownloads || 0}

CONTENT SIGNALS:
- Suspicious keywords found: [${keywords}]
- Page text snippet: "${signals.textSnippet || 'N/A'}"

SECURITY:
- SSL: ${signals.isHTTPS ? 'HTTPS' : 'HTTP (insecure)'}
- Known domain: ${signals.isKnownDomain ? 'Yes' : 'No'}
- Redirects detected: ${signals.redirectCount || 0}

Respond with ONLY this JSON format:
{"score": <0-100 where 0=dangerous 100=safe>, "verdict": "<safe|suspicious|dangerous>", "reasons": ["reason1", "reason2"], "category": "<phishing|malware|scam|fraud|safe>"}`;
}
