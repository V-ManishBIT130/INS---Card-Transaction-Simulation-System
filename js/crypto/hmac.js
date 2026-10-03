/**
 * ============================================================
 * HMAC-SHA256 — Message Authentication Code
 * ============================================================
 * 
 * HMAC (Hash-based Message Authentication Code) provides BOTH:
 * 1. Data Integrity — detects if the message was modified
 * 2. Authentication — verifies the message came from a trusted sender
 * 
 * HMAC vs plain SHA-256:
 * - SHA-256 only provides integrity (anyone can compute a hash)
 * - HMAC requires a SECRET KEY, so only parties with the key can
 *   generate or verify the MAC
 * 
 * How HMAC works:
 * 1. Take a secret key and the message
 * 2. Apply two rounds of SHA-256 hashing with the key
 * 3. Output: HMAC = SHA-256(key ⊕ opad || SHA-256(key ⊕ ipad || message))
 * 
 * In payment systems:
 * - The merchant and gateway share an HMAC key
 * - The merchant computes HMAC over the entire transaction bundle
 * - The gateway recomputes HMAC and compares — if they match,
 *   the message is authentic and untampered
 * 
 * Standard: RFC 2104
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.HMAC = {

        /**
         * Generate a fresh HMAC-SHA256 key.
         * This key must be shared between the merchant and gateway
         * (pre-shared secret established during merchant registration).
         * 
         * @returns {Promise<Object>} { key: CryptoKey, keyHex: string }
         */
        async generateKey() {
            const key = await crypto.subtle.generateKey(
                {
                    name: 'HMAC',
                    hash: 'SHA-256'     // Use SHA-256 as the underlying hash
                },
                true,                   // Extractable
                ['sign', 'verify']      // Operations
            );

            // Export for display
            const exported = await crypto.subtle.exportKey('raw', key);
            const keyHex = Array.from(new Uint8Array(exported)).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');

            return {
                key: key,
                keyHex: keyHex,
                keyLength: keyHex.length / 2 * 8,  // Bits
                algorithm: 'HMAC-SHA256'
            };
        },

        /**
         * Generate an HMAC for a message.
         * The output MAC is a 256-bit (32-byte) authentication code.
         * 
         * @param {CryptoKey} key - The shared HMAC key
         * @param {string} message - The message to authenticate
         * @returns {Promise<Object>} { macBuffer, macHex }
         */
        async sign(key, message) {
            const data = new TextEncoder().encode(message);

            const macBuffer = await crypto.subtle.sign(
                'HMAC',
                key,
                data
            );

            const macArray = new Uint8Array(macBuffer);
            const macHex = Array.from(macArray).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');

            return {
                macBuffer: macBuffer,
                macHex: macHex,
                macLength: macArray.length,
                algorithm: 'HMAC-SHA256'
            };
        },

        /**
         * Verify an HMAC against a message.
         * Returns true if the HMAC is valid (message is authentic and untampered).
         * 
         * @param {CryptoKey} key - The shared HMAC key
         * @param {string} message - The message to verify
         * @param {ArrayBuffer} macBuffer - The HMAC to verify against
         * @returns {Promise<boolean>} True if verification passes
         */
        async verify(key, message, macBuffer) {
            const data = new TextEncoder().encode(message);

            return await crypto.subtle.verify(
                'HMAC',
                key,
                macBuffer,
                data
            );
        },

        /**
         * Export an HMAC key as a hex string.
         * @param {CryptoKey} key - The HMAC key
         * @returns {Promise<string>} Hex string
         */
        async exportKey(key) {
            const exported = await crypto.subtle.exportKey('raw', key);
            return Array.from(new Uint8Array(exported)).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
        }
    };

})();
