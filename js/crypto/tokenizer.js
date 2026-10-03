/**
 * ============================================================
 * TOKENIZATION — Card Number Protection
 * ============================================================
 * 
 * Tokenization replaces sensitive card data (PAN — Primary Account
 * Number) with a non-sensitive substitute called a "token."
 * 
 * Key properties of tokens:
 * - Non-reversible: You cannot derive the original PAN from the token
 * - Format-preserving: Tokens can look like card numbers but aren't valid
 * - Scoped: A token is only valid within a specific merchant/context
 * 
 * In real systems, a Token Vault (secure server) stores the mapping
 * between tokens and real PANs. Here we simulate this with an in-memory map.
 * 
 * Used by: Apple Pay, Google Pay, Visa Token Service, Mastercard MDES
 * Standard: PCI DSS Tokenization Guidelines
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.Tokenizer = {

        /**
         * Token Vault — In-memory storage mapping tokens to masked PANs.
         * In production, this would be a Hardware Security Module (HSM) backed database.
         */
        _vault: new Map(),

        /**
         * Generate a unique token for a given PAN (Primary Account Number).
         * 
         * Process:
         * 1. Combine PAN with a timestamp and random salt
         * 2. Hash with SHA-256 to produce a unique, non-reversible token
         * 3. Format as "tok_" followed by 32 hex characters
         * 4. Store the mapping in the vault (masked PAN only)
         * 
         * @param {string} pan - The full card number (16 digits)
         * @returns {Promise<Object>} { token, masked, firstSix, lastFour, original }
         */
        async tokenize(pan) {
            const clean = pan.replace(/\D/g, '');

            // Create input for hashing: PAN + timestamp + random salt
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
            const input = clean + '|' + Date.now() + '|' + saltHex;

            // Hash to create a non-reversible token
            const data = new TextEncoder().encode(input);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));

            // Format token: tok_ + 32 hex characters
            const token = 'tok_' + hashArray.slice(0, 16).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');

            // Create masked version for display (first 4 + **** + last 4)
            const firstSix = clean.slice(0, 6);
            const lastFour = clean.slice(-4);
            const masked = clean.slice(0, 4) + ' **** **** ' + lastFour;

            // Store in vault (only masked data, never the full PAN)
            this._vault.set(token, {
                masked: masked,
                firstSix: firstSix,
                lastFour: lastFour,
                createdAt: new Date().toISOString(),
                salt: saltHex
            });

            return {
                token: token,
                masked: masked,
                firstSix: firstSix,
                lastFour: lastFour,
                original: clean,
                salt: saltHex
            };
        },

        /**
         * Look up a token in the vault.
         * Returns masked card info — never the full PAN.
         * 
         * @param {string} token - The token to look up
         * @returns {Object|null} Vault entry or null if not found
         */
        detokenize(token) {
            return this._vault.get(token) || null;
        },

        /**
         * Check if a token exists in the vault.
         * @param {string} token - The token to check
         * @returns {boolean}
         */
        isValid(token) {
            return this._vault.has(token);
        },

        /**
         * Get the number of tokens in the vault.
         * @returns {number}
         */
        getVaultSize() {
            return this._vault.size;
        },

        /**
         * Clear all tokens (for demo reset).
         */
        clearVault() {
            this._vault.clear();
        }
    };

})();
