/**
 * ============================================================
 * RSA-2048 — Asymmetric Encryption & Digital Signatures
 * ============================================================
 * 
 * RSA is an asymmetric cryptographic algorithm that uses a KEY PAIR:
 * - Public Key: Shared openly — used to encrypt data or verify signatures
 * - Private Key: Kept secret — used to decrypt data or create signatures
 * 
 * Two RSA operations are used in payment systems:
 * 
 * 1. RSA-OAEP (Encryption/Key Wrapping):
 *    - The AES session key is encrypted with the gateway's PUBLIC key
 *    - Only the gateway can decrypt it with their PRIVATE key
 *    - This is how "hybrid encryption" works: fast AES for data, RSA for key exchange
 * 
 * 2. RSA-PSS (Digital Signatures):
 *    - The merchant SIGNS the transaction hash with their PRIVATE key
 *    - Anyone can VERIFY the signature with the merchant's PUBLIC key
 *    - Proves the transaction originated from the legitimate merchant
 * 
 * Configuration:
 * - Modulus length: 2048 bits (256 bytes)
 * - Hash algorithm: SHA-256
 * - OAEP padding for encryption
 * - PSS padding for signatures (salt length: 32 bytes)
 * 
 * Standard: PKCS #1 (RSA Cryptography Standard)
 * 
 * ============================================================
 */

(function () {
    'use strict';

    window.CryptoSim = window.CryptoSim || {};

    CryptoSim.RSA = {

        /**
         * Generate an RSA-OAEP key pair for encryption/decryption.
         * Used by the Payment Gateway to receive encrypted AES keys.
         * 
         * The PUBLIC key is shared with merchants.
         * The PRIVATE key stays at the gateway.
         * 
         * @returns {Promise<Object>} { keyPair, publicKeyPem, privateKeyInfo }
         */
        async generateEncryptionKeyPair() {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),  // 65537
                    hash: 'SHA-256'
                },
                true,       // Extractable
                ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
            );

            // Export public key for display
            const publicKeyPem = await this._exportPublicKeyPem(keyPair.publicKey);
            const publicKeyHex = await this._exportKeyHex(keyPair.publicKey, 'spki');

            return {
                keyPair: keyPair,
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                publicKeyPem: publicKeyPem,
                publicKeyHex: publicKeyHex,
                algorithm: 'RSA-OAEP',
                modulusLength: 2048,
                hash: 'SHA-256',
                purpose: 'Encryption / Key Wrapping'
            };
        },

        /**
         * Generate an RSA-PSS key pair for digital signatures.
         * Used by the Merchant to sign transactions.
         * 
         * The PRIVATE key stays with the merchant (for signing).
         * The PUBLIC key is registered with the gateway (for verification).
         * 
         * @returns {Promise<Object>} { keyPair, publicKeyPem, privateKeyInfo }
         */
        async generateSigningKeyPair() {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-PSS',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['sign', 'verify']
            );

            const publicKeyPem = await this._exportPublicKeyPem(keyPair.publicKey);
            const publicKeyHex = await this._exportKeyHex(keyPair.publicKey, 'spki');

            return {
                keyPair: keyPair,
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                publicKeyPem: publicKeyPem,
                publicKeyHex: publicKeyHex,
                algorithm: 'RSA-PSS',
                modulusLength: 2048,
                hash: 'SHA-256',
                purpose: 'Digital Signatures'
            };
        },

        /**
         * Wrap (encrypt) an AES session key with the RSA public key.
         * 
         * This is the "key exchange" step:
         * - The merchant generates a random AES key for this transaction
         * - The AES key is encrypted with the gateway's RSA public key
         * - Only the gateway can recover the AES key using their private key
         * 
         * @param {CryptoKey} aesKey - The AES session key to wrap
         * @param {CryptoKey} rsaPublicKey - The gateway's RSA-OAEP public key
         * @returns {Promise<Object>} { wrappedBuffer, wrappedHex, wrappedBase64 }
         */
        async wrapKey(aesKey, rsaPublicKey) {
            const wrappedBuffer = await crypto.subtle.wrapKey(
                'raw',          // Export format for the AES key
                aesKey,         // The key to wrap
                rsaPublicKey,   // Wrapping key (RSA public)
                { name: 'RSA-OAEP' }   // Wrapping algorithm
            );

            const wrappedArray = new Uint8Array(wrappedBuffer);
            const wrappedHex = Array.from(wrappedArray).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
            const wrappedBase64 = btoa(String.fromCharCode(...wrappedArray));

            return {
                wrappedBuffer: wrappedBuffer,
                wrappedHex: wrappedHex,
                wrappedBase64: wrappedBase64,
                wrappedLength: wrappedArray.length,
                algorithm: 'RSA-OAEP'
            };
        },

        /**
         * Unwrap (decrypt) an AES session key using the RSA private key.
         * 
         * This recovers the original AES key so the gateway can decrypt
         * the transaction payload.
         * 
         * @param {ArrayBuffer} wrappedBuffer - The wrapped (encrypted) AES key
         * @param {CryptoKey} rsaPrivateKey - The gateway's RSA-OAEP private key
         * @returns {Promise<CryptoKey>} The recovered AES key
         */
        async unwrapKey(wrappedBuffer, rsaPrivateKey) {
            return await crypto.subtle.unwrapKey(
                'raw',                      // Format of the key being unwrapped
                wrappedBuffer,              // Wrapped key data
                rsaPrivateKey,              // Unwrapping key (RSA private)
                { name: 'RSA-OAEP' },       // Algorithm used to wrap
                { name: 'AES-CBC', length: 256 },  // Algorithm of the unwrapped key
                true,                       // Extractable
                ['encrypt', 'decrypt']      // Usages for the unwrapped key
            );
        },

        /**
         * Create a digital signature for a message using RSA-PSS.
         * 
         * The merchant signs the transaction hash with their PRIVATE key.
         * This proves:
         * 1. The transaction came from this specific merchant (authentication)
         * 2. The merchant cannot deny sending it (non-repudiation)
         * 
         * @param {CryptoKey} privateKey - The merchant's RSA-PSS private key
         * @param {string} message - The message to sign (usually a hash)
         * @returns {Promise<Object>} { signatureBuffer, signatureHex, signatureBase64 }
         */
        async sign(privateKey, message) {
            const data = new TextEncoder().encode(message);

            const signatureBuffer = await crypto.subtle.sign(
                {
                    name: 'RSA-PSS',
                    saltLength: 32  // Salt length in bytes
                },
                privateKey,
                data
            );

            const sigArray = new Uint8Array(signatureBuffer);
            const signatureHex = Array.from(sigArray).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
            const signatureBase64 = btoa(String.fromCharCode(...sigArray));

            return {
                signatureBuffer: signatureBuffer,
                signatureHex: signatureHex,
                signatureBase64: signatureBase64,
                signatureLength: sigArray.length,
                algorithm: 'RSA-PSS',
                saltLength: 32
            };
        },

        /**
         * Verify a digital signature using the signer's public key.
         * 
         * The gateway/bank verifies the merchant's signature to confirm:
         * - The transaction genuinely came from the registered merchant
         * - The signed data has not been altered
         * 
         * @param {CryptoKey} publicKey - The merchant's RSA-PSS public key
         * @param {ArrayBuffer} signatureBuffer - The signature to verify
         * @param {string} message - The original message that was signed
         * @returns {Promise<boolean>} True if the signature is valid
         */
        async verify(publicKey, signatureBuffer, message) {
            const data = new TextEncoder().encode(message);

            return await crypto.subtle.verify(
                {
                    name: 'RSA-PSS',
                    saltLength: 32
                },
                publicKey,
                signatureBuffer,
                data
            );
        },

        /**
         * Export a public key as PEM-formatted string.
         * PEM is the standard format for displaying cryptographic keys.
         * 
         * @param {CryptoKey} key - The public key to export
         * @returns {Promise<string>} PEM-formatted public key
         */
        async _exportPublicKeyPem(key) {
            const exported = await crypto.subtle.exportKey('spki', key);
            const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));
            const lines = base64.match(/.{1,64}/g).join('\n');
            return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
        },

        /**
         * Export a key as hex string for display.
         * @param {CryptoKey} key - The key to export
         * @param {string} format - Export format ('spki' for public, 'pkcs8' for private)
         * @returns {Promise<string>} Hex string
         */
        async _exportKeyHex(key, format) {
            const exported = await crypto.subtle.exportKey(format, key);
            return Array.from(new Uint8Array(exported)).map(b =>
                b.toString(16).padStart(2, '0')
            ).join('');
        }
    };

})();
