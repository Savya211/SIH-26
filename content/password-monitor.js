/**
 * content/password-monitor.js
 * Detects password submissions and checks via HIBP using K-anonymity.
 * No passwords ever leave the browser!
 */

// We listen on the document for form submissions (capture phase)
document.addEventListener('submit', async (e) => {
    // Determine if settings allow checking
    chrome.storage.local.get(['settings'], async (result) => {
        if (result.settings && result.settings.enablePasswordCheck === false) {
            return; // Feature disabled
        }

        // Check if the form contains password inputs
        const target = e.target;
        if (!target || !target.querySelectorAll) return;

        const passwordInputs = target.querySelectorAll('input[type="password"]');
        if (passwordInputs.length === 0) return;

        for (const input of passwordInputs) {
            const password = input.value;
            if (password && password.length >= 4) {
                // Prevent duplicate checks for same pass in multiple fields
                await processPassword(password);
            }
        }
    });
}, true);


async function processPassword(password) {
    try {
        // 1. Hash locally using crypto.js
        const hash = await hashSHA1(password);

        // 2. K-Anonymity: Split into prefix and suffix
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);

        // 3. Send prefix to background script (to avoid page CSP blocking)
        chrome.runtime.sendMessage({
            type: 'CHECK_HIBP',
            prefix: prefix
        }, (response) => {
            if (response && response.success) {
                const lines = response.data.split('\n');
                let breachedCount = 0;

                // 4. Compare full suffix locally
                for (const line of lines) {
                    const [lineSuffix, count] = line.split(':');
                    if (lineSuffix && lineSuffix.trim() === suffix) {
                        breachedCount = parseInt(count.trim(), 10);
                        break;
                    }
                }

                if (breachedCount > 0) {
                    // 5. Notify if breached securely
                    chrome.runtime.sendMessage({
                        type: 'BREACH_DETECTED',
                        url: window.location.hostname,
                        count: breachedCount
                    });
                }
            }
        });
    } catch (e) {
        console.error('[Security Manager] Password Hash error:', e);
    }
}
