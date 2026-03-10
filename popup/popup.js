/**
 * popup.js - Handles UI interactions in the extension popup
 */

document.addEventListener('DOMContentLoaded', () => {
    // Tab switching logic
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            // Add active class to clicked
            btn.classList.add('active');
            const targetId = btn.getAttribute('data-tab');
            document.getElementById(targetId).classList.add('active');
        });
    });

    // Load Settings
    loadSettings();

    // Save Settings
    document.getElementById('save-settings-btn').addEventListener('click', saveSettings);

    // Open fullscreen dashboard in a new tab (as extension page)
    document.getElementById('open-dashboard-btn').addEventListener('click', () => {
        chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/index.html') });
    });

    // Panic button — redirect to superlogout.com to log out of all sites
    document.getElementById('panic-btn').addEventListener('click', () => {
        chrome.tabs.create({ url: 'https://superlogout.com' });
    });
});

function loadSettings() {
    chrome.storage.local.get(['settings'], (result) => {
        if (result.settings) {
            document.getElementById('setting-password').checked = result.settings.enablePasswordCheck;
            document.getElementById('setting-phishing').checked = result.settings.enablePhishingCheck;
            document.getElementById('setting-tracker').checked = result.settings.enableTrackerBlocker;
            document.getElementById('setting-webrtc').checked = result.settings.enableWebRTCProtect;
            document.getElementById('setting-doh').checked = result.settings.enableDoH || false;
            document.getElementById('setting-search-annotations').checked = result.settings.enableSearchAnnotations !== false;
            document.getElementById('setting-gmail-scanner').checked = result.settings.enableGmailScanner !== false;

            if (result.settings.safeBrowsingApiKey) {
                document.getElementById('safebrowsing-key').value = result.settings.safeBrowsingApiKey;
            }
            if (result.settings.phishtankApiKey) {
                document.getElementById('phishtank-key').value = result.settings.phishtankApiKey;
            }
        }
    });
}

function saveSettings() {
    const newSettings = {
        enablePasswordCheck: document.getElementById('setting-password').checked,
        enablePhishingCheck: document.getElementById('setting-phishing').checked,
        enableTrackerBlocker: document.getElementById('setting-tracker').checked,
        enableWebRTCProtect: document.getElementById('setting-webrtc').checked,
        enableDoH: document.getElementById('setting-doh').checked,
        enableSearchAnnotations: document.getElementById('setting-search-annotations').checked,
        enableGmailScanner: document.getElementById('setting-gmail-scanner').checked,
        safeBrowsingApiKey: document.getElementById('safebrowsing-key').value,
        phishtankApiKey: document.getElementById('phishtank-key').value
    };

    chrome.storage.local.get(['settings'], (result) => {
        const merged = { ...result.settings, ...newSettings };
        chrome.storage.local.set({ settings: merged }, () => {
            const btn = document.getElementById('save-settings-btn');
            btn.textContent = 'Saved!';
            btn.classList.add('success');
            setTimeout(() => {
                btn.textContent = 'Save Settings';
                btn.classList.remove('success');
            }, 2000);
        });
    });
}
