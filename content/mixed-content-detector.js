/**
 * content/mixed-content-detector.js
 * Detects HTTP resources loaded on HTTPS pages (mixed content).
 */

(function () {
    if (window.location.protocol !== 'https:') return;

    function detectMixedContent() {
        const mixed = [];

        const selectors = [
            { sel: 'img[src^="http://"]', type: 'image', attr: 'src' },
            { sel: 'script[src^="http://"]', type: 'script', attr: 'src' },
            { sel: 'link[rel="stylesheet"][href^="http://"]', type: 'stylesheet', attr: 'href' },
            { sel: 'iframe[src^="http://"]', type: 'iframe', attr: 'src' },
            { sel: 'video[src^="http://"]', type: 'media', attr: 'src' },
            { sel: 'audio[src^="http://"]', type: 'media', attr: 'src' },
            { sel: 'source[src^="http://"]', type: 'media', attr: 'src' },
            { sel: 'object[data^="http://"]', type: 'object', attr: 'data' },
            { sel: 'embed[src^="http://"]', type: 'object', attr: 'src' },
        ];

        selectors.forEach(({ sel, type, attr }) => {
            document.querySelectorAll(sel).forEach(el => {
                mixed.push({ type, url: el[attr] || el.getAttribute(attr), tag: el.tagName.toLowerCase() });
            });
        });

        if (mixed.length > 0) {
            chrome.runtime.sendMessage({
                type: 'MIXED_CONTENT_REPORT',
                data: { url: window.location.href, items: mixed, count: mixed.length }
            });
        }
    }

    if (document.readyState === 'complete') {
        setTimeout(detectMixedContent, 2000);
    } else {
        window.addEventListener('load', () => setTimeout(detectMixedContent, 2000));
    }
})();
