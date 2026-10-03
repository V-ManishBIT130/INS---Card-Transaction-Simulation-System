/**
 * ============================================================
 * AES-256-CBC — Symmetric Encryption
 * ============================================================
 * 
 * AES (Advanced Encryption Standard) is the industry-standard
 * symmetric encryption algorithm. "Symmetric" means the same key
 * is used for both encryption and decryption.
 * 
 * Configuration:
 * - Algorithm: AES-CBC (Cipher Block Chaining)
 * - Key size: 256 bits (32 bytes) — maximum AES security
 * - IV size: 128 bits (16 bytes) — unique per encryption
 * - Block size: 128 bits (16 bytes)
 * 
 * Why AES-CBC?
 * - CBC mode chains blocks together, so identical plaintext blocks
 *   produce different ciphertext (unlike ECB mode)
 * - The IV (Initialization Vector) ensures that encrypting the same
 *   message twice produces different ciphertext
 * - Industry standard for payment data encryption
 * 
 * In payment systems:
 * - Transaction payload (card token, amount, merchant) is encrypted with AES
 * - The AES key is a one-time "session key" generated fresh per transaction
 * - The session key itself is then encrypted with RSA (hybrid encryption)
 * 
 * Standard: FIPS 197 (published by NIST)
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.AES = {

        /**
         * Generate a fresh AES-256 key.
         * Each transaction should use a unique session key.
         * 
         * @returns {Promise<Object>} { key: CryptoKey, keyHex: string, keyBase64: string }
         */
        async generateKey() {
            // Generate a 256-bit AES key using Web Crypto API
            const key = await crypto.subtle.generateKey(
                {
                    name: 'AES-CBC',
                    length: 256     // Key size in bits
                },
                true,               // Extractable — so we can display it
                ['encrypt', 'decrypt']  // Allowed operations
            );

            // Export the key for display purposes
            const exported = await crypto.subtle.exportKey('raw', key);
            const keyBytes = new Uint8Array(exported);
            const keyHex = Array.from(keyBytes).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
            const keyBase64 = btoa(String.fromCharCode(...keyBytes));

            return {
                key: key,           // CryptoKey object (used in encrypt/decrypt)
                keyHex: keyHex,     // Hex representation (64 chars = 256 bits)
                keyBase64: keyBase64, // Base64 representation
                keyLength: 256,     // Bits
                algorithm: 'AES-CBC'
            };
        },

        /**
         * Encrypt plaintext with AES-256-CBC.
         * 
         * Steps:
         * 1. Generate a random 128-bit IV (Initialization Vector)
         * 2. Encode the plaintext as UTF-8 bytes
         * 3. Encrypt using AES-CBC with the key and IV
         * 4. Return ciphertext in multiple formats for display
         * 
         * @param {CryptoKey} key - The AES-256 key
         * @param {string} plaintext - The data to encrypt
         * @returns {Promise<Object>} { cipherBuffer, cipherHex, cipherBase64, iv, ivHex }
         */
        async encrypt(key, plaintext) {
            // Step 1: Generate random IV — MUST be unique per encryption
            // IV prevents identical plaintexts from producing identical ciphertexts
            const iv = crypto.getRandomValues(new Uint8Array(16)); // 128-bit IV

            // Step 2: Encode plaintext as bytes
            const data = new TextEncoder().encode(plaintext);

            // Step 3: Encrypt
            const cipherBuffer = await crypto.subtle.encrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                data
            );

            // Step 4: Convert to display formats
            const cipherArray = new Uint8Array(cipherBuffer);
            const cipherHex = Array.from(cipherArray).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
            const cipherBase64 = btoa(String.fromCharCode(...cipherArray));
            const ivHex = Array.from(iv).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');

            return {
                cipherBuffer: cipherBuffer,     // Raw ArrayBuffer (for decryption)
                cipherHex: cipherHex,           // Hex string (for display)
                cipherBase64: cipherBase64,     // Base64 string (for display)
                iv: iv,                         // Raw IV bytes (for decryption)
                ivHex: ivHex,                   // IV as hex (for display)
                plaintextLength: data.length,   // Original data size
                cipherLength: cipherArray.length, // Encrypted data size
                algorithm: 'AES-256-CBC'
            };
        },

        /**
         * Decrypt ciphertext with AES-256-CBC.
         * 
         * Steps:
         * 1. Decrypt the ciphertext using the same key and IV used for encryption
         * 2. Decode the resulting bytes back to a UTF-8 string
         * 
         * If the wrong key or IV is used, decryption will FAIL with an error.
         * This is how AES protects data — only the correct key can decrypt.
         * 
         * @param {CryptoKey} key - The AES-256 key
         * @param {ArrayBuffer} cipherBuffer - The encrypted data
         * @param {Uint8Array} iv - The initialization vector used during encryption
         * @returns {Promise<string>} The decrypted plaintext
         */
        async decrypt(key, cipherBuffer, iv) {
            const plainBuffer = await crypto.subtle.decrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                cipherBuffer
            );

            return new TextDecoder().decode(plainBuffer);
        },

        /**
         * Export an AES key as a hex string.
         * @param {CryptoKey} key - The key to export
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
