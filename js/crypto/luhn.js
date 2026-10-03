/**
 * ============================================================
 * LUHN ALGORITHM — Card Number Validation
 * ============================================================
 * 
 * The Luhn algorithm (also known as "modulus 10" algorithm) is a
 * checksum formula used to validate credit/debit card numbers.
 * 
 * It detects accidental errors in card numbers — typos, transpositions,
 * and single-digit errors. It does NOT protect against intentional fraud.
 * 
 * Standard: ISO/IEC 7812-1
 * Used by: Visa, Mastercard, Amex, Discover, RuPay, and most card networks
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.Luhn = {

        /**
         * Validate a card number using the Luhn algorithm.
         * Returns the validation result along with detailed steps for visualization.
         * 
         * Algorithm Steps:
         * 1. Starting from the rightmost digit, double every second digit
         * 2. If the doubled value exceeds 9, subtract 9
         * 3. Sum all the digits
         * 4. If the total modulo 10 equals 0, the number is valid
         * 
         * @param {string} number - The card number (may contain spaces/dashes)
         * @returns {Object} { valid, sum, digits, steps[], checkDigit }
         */
        validate(number) {
            const digits = number.replace(/\D/g, '');

            if (digits.length < 13 || digits.length > 19) {
                return {
                    valid: false,
                    reason: 'Card number must be 13-19 digits',
                    sum: 0,
                    steps: [],
                    digits: digits
                };
            }

            let sum = 0;
            let isDouble = false;
            const steps = [];

            // Process from right to left
            for (let i = digits.length - 1; i >= 0; i--) {
                let digit = parseInt(digits[i], 10);
                const original = digit;

                if (isDouble) {
                    digit *= 2;
                    const subtracted = digit > 9;
                    if (subtracted) digit -= 9;

                    steps.unshift({
                        position: i,
                        original: original,
                        action: 'double',
                        doubled: original * 2,
                        subtracted: subtracted,
                        result: digit
                    });
                } else {
                    steps.unshift({
                        position: i,
                        original: original,
                        action: 'keep',
                        doubled: null,
                        subtracted: false,
                        result: digit
                    });
                }

                sum += digit;
                isDouble = !isDouble;
            }

            return {
                valid: (sum % 10) === 0,
                sum: sum,
                remainder: sum % 10,
                digits: digits,
                steps: steps,
                checkDigit: parseInt(digits[digits.length - 1], 10)
            };
        },

        /**
         * Detect the card network based on the card number prefix.
         * 
         * Known prefixes:
         * - Visa: starts with 4
         * - Mastercard: starts with 51-55 or 2221-2720
         * - American Express: starts with 34 or 37
         * - Discover: starts with 6011, 622126-622925, 644-649, or 65
         * - RuPay: starts with 60, 65, 81, or 82
         * 
         * @param {string} number - The card number
         * @returns {string} Network name ('visa', 'mastercard', 'amex', 'discover', 'rupay', 'unknown')
         */
        detectNetwork(number) {
            const digits = number.replace(/\D/g, '');

            if (!digits) return 'unknown';

            if (/^4/.test(digits)) return 'visa';
            if (/^5[1-5]/.test(digits) || /^2[2-7]/.test(digits)) return 'mastercard';
            if (/^3[47]/.test(digits)) return 'amex';
            if (/^6(?:011|5)/.test(digits)) return 'discover';
            if (/^(?:60|65|81|82)/.test(digits)) return 'rupay';

            return 'unknown';
        },

        /**
         * Get the display name and color for a card network.
         * @param {string} network - Network identifier
         * @returns {Object} { name, color, gradient }
         */
        getNetworkInfo(network) {
            const networks = {
                visa: { name: 'VISA', color: '#1a1faa', gradient: 'linear-gradient(135deg, #1a237e, #0d47a1, #1565c0)' },
                mastercard: { name: 'MASTERCARD', color: '#eb001b', gradient: 'linear-gradient(135deg, #b71c1c, #e65100, #ff6d00)' },
                amex: { name: 'AMEX', color: '#006fcf', gradient: 'linear-gradient(135deg, #004d40, #00695c, #00897b)' },
                discover: { name: 'DISCOVER', color: '#ff6000', gradient: 'linear-gradient(135deg, #e65100, #ff6d00, #ff9100)' },
                rupay: { name: 'RuPay', color: '#0072bc', gradient: 'linear-gradient(135deg, #1a237e, #0097a7, #00bcd4)' },
                unknown: { name: 'CARD', color: '#7c3aed', gradient: 'linear-gradient(135deg, #1a1a4e, #2d1b69, #5b21b6)' }
            };
            return networks[network] || networks.unknown;
        },

        /**
         * Format a card number with spaces for display.
         * Amex uses 4-6-5 grouping, others use 4-4-4-4.
         * @param {string} number - Raw card number digits
         * @returns {string} Formatted card number
         */
        formatNumber(number) {
            const digits = number.replace(/\D/g, '');
            const network = this.detectNetwork(digits);

            if (network === 'amex') {
                // Amex: 4-6-5
                return digits.replace(/(\d{4})(\d{0,6})(\d{0,5})/, (_, a, b, c) =>
                    [a, b, c].filter(Boolean).join(' ')
                );
            }

            // Default: 4-4-4-4
            return digits.replace(/(\d{4})(?=\d)/g, '$1 ').trim();
        }
    };

})();
