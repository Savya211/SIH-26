/**
 * lib/crypto.js
 * Provides local SHA-1 hashing using Web Crypto API.
 * Injected into content scripts (so no background/extension APIs are required).
 */

async function hashSHA1(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);

    // Perform hashing locally
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);

    // Convert buffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}
