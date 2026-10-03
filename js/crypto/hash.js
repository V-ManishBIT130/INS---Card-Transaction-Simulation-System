/**
 * ============================================================
 * SHA-256 HASHING — Data Integrity Verification
 * ============================================================
 * 
 * SHA-256 (Secure Hash Algorithm 256-bit) produces a fixed-size
 * 256-bit (32-byte) hash value from any input data.
 * 
 * Key properties:
 * - Deterministic: Same input always produces the same hash
 * - Avalanche effect: A tiny change in input completely changes the hash
 * - One-way: Cannot reverse-engineer the original data from the hash
 * - Collision-resistant: Extremely unlikely for two different inputs to produce the same hash
 * 
 * In payment systems, hashing is used to:
 * - Verify that transaction data has not been tampered with
 * - Create digital fingerprints of transaction payloads
 * - Serve as input to digital signatures
 * 
 * Standard: FIPS 180-4 (published by NIST)
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.Hash = {

        /**
         * Compute SHA-256 hash of a string message.
         * Returns the hash as a lowercase hexadecimal string.
         * 
         * @param {string} message - The message to hash
         * @returns {Promise<string>} 64-character hex string (256 bits)
         */
        async sha256(message) {
            const data = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        },

        /**
         * Compute SHA-256 hash and return as Uint8Array.
         * Used when the raw bytes are needed (e.g., for signing).
         * 
         * @param {string} message - The message to hash
         * @returns {Promise<Uint8Array>} 32-byte hash
         */
        async sha256Raw(message) {
            const data = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            return new Uint8Array(hashBuffer);
        },

        /**
         * Compute SHA-256 hash of an ArrayBuffer.
         * Used for hashing binary data like encrypted payloads.
         * 
         * @param {ArrayBuffer} buffer - The data to hash
         * @returns {Promise<string>} 64-character hex string
         */
        async sha256Buffer(buffer) {
            const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        },

        /**
         * Demonstrate the avalanche effect — show how a tiny change
         * in the input completely changes the hash output.
         * 
         * @param {string} original - Original message
         * @param {string} modified - Slightly modified message
         * @returns {Promise<Object>} { originalHash, modifiedHash, bitsChanged }
         */
        async demonstrateAvalanche(original, modified) {
            const hash1 = await this.sha256(original);
            const hash2 = await this.sha256(modified);

            // Count how many bits differ between the two hashes
            let bitsChanged = 0;
            for (let i = 0; i < hash1.length; i += 2) {
                const byte1 = parseInt(hash1.substr(i, 2), 16);
                const byte2 = parseInt(hash2.substr(i, 2), 16);
                const xor = byte1 ^ byte2;
                // Count set bits in XOR result
                let bits = xor;
                while (bits) {
                    bitsChanged += bits & 1;
                    bits >>= 1;
                }
            }

            return {
                originalMessage: original,
                modifiedMessage: modified,
                originalHash: hash1,
                modifiedHash: hash2,
                bitsChanged: bitsChanged,
                totalBits: 256,
                percentChanged: ((bitsChanged / 256) * 100).toFixed(1) + '%'
            };
        }
    };

})();
