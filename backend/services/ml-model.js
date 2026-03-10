/**
 * services/ml-model.js
 * HTTP client for the TheThirdEye ML prediction microservice (Python FastAPI on :5000)
 *
 * Returns null on any failure so the caller can gracefully fall back to OpenRouter.
 */

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || 'http://localhost:5000';
const TIMEOUT_MS = 5000;

/**
 * Call the ML microservice to get a phishing probability score.
 *
 * @param {object} signals - Page signals from the browser extension
 *   Expected keys: url, isHTTPS, passwordFields, hiddenIframes, externalScripts,
 *                  redirectCount, creditCardFields, totalForms, popupCount,
 *                  hiddenFields, externalForms
 * @returns {object|null} { score, verdict, probability, source, reasons, category } or null
 */
export async function analyzeWithML(signals) {
    if (!signals || !signals.url) return null;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
        const response = await fetch(`${ML_SERVICE_URL}/predict-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: signals.url,
                signals: {
                    isHTTPS: signals.isHTTPS ?? false,
                    passwordFields: signals.passwordFields ?? 0,
                    hiddenIframes: signals.hiddenIframes ?? 0,
                    externalScripts: signals.externalScripts ?? 0,
                    redirectCount: signals.redirectCount ?? 0,
                    creditCardFields: signals.creditCardFields ?? 0,
                    totalForms: signals.totalForms ?? 0,
                    popupCount: signals.popupCount ?? 0,
                    hiddenFields: signals.hiddenFields ?? 0,
                    externalForms: signals.externalForms ?? 0,
                }
            }),
            signal: controller.signal
        });

        clearTimeout(timer);

        if (!response.ok) {
            console.warn(`[ML] Service returned ${response.status}`);
            return null;
        }

        return await response.json();

    } catch (err) {
        clearTimeout(timer);
        if (err.name === 'AbortError') {
            console.warn('[ML] Request timed out after 5s');
        } else {
            console.warn('[ML] Service unavailable:', err.message);
        }
        return null;
    }
}

/**
 * Ping /health to check if the ML service is running.
 * @returns {object|null} health payload or null
 */
export async function checkMLHealth() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2000);

    try {
        const response = await fetch(`${ML_SERVICE_URL}/health`, {
            signal: controller.signal
        });
        clearTimeout(timer);
        if (!response.ok) return null;
        return await response.json();
    } catch {
        clearTimeout(timer);
        return null;
    }
}
