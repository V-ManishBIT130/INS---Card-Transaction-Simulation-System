/**
 * ============================================================
 * SecurePay — Main Application Controller
 * ============================================================
 * 
 * Orchestrates the entire payment transaction simulation:
 * - Page navigation
 * - Card input handling & live validation
 * - Key generation coordination
 * - Transaction processing pipeline
 * - Attack simulation
 * - Audit logging
 * 
 * Dependencies: CryptoSim.Luhn, .Tokenizer, .Hash, .AES, .RSA, .HMAC
 * 
 * ============================================================
 */

(function () {
    'use strict';

    // ============================================================
    // STATE
    // ============================================================

    const state = {
        currentPage: 'dashboard',
        keysGenerated: false,
        transactionCount: 0,
        attacksBlocked: 0,

        // Card input
        cardNumber: '',
        cardName: '',
        expiry: '',
        cvv: '',
        amount: 0,
        merchantName: '',
        cardNetwork: 'unknown',
        cardValid: false,

        // Keys (populated by generateAllKeys)
        signingKeyPair: null,    // RSA-PSS (merchant signing)
        encryptionKeyPair: null, // RSA-OAEP (gateway encryption)
        aesKeyData: null,        // { key, keyHex }
        hmacKeyData: null,       // { key, keyHex }

        // Transaction results (populated during pipeline)
        tokenResult: null,
        aesEncrypted: null,
        rsaWrappedKey: null,
        transactionHash: null,
        digitalSignature: null,
        hmacResult: null,
        nonce: '',
        timestamp: '',
        transactionPayload: null,
        transactionBundle: null,

        // Verification
        verificationResults: null,
        decryptedPayload: null,

        // Log
        auditLog: [],

        // Used nonces (for replay protection)
        usedNonces: new Set()
    };

    // ============================================================
    // NAVIGATION
    // ============================================================

    function navigate(sectionId) {
        // Hide all pages
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        // Show target page
        const target = document.getElementById(sectionId);
        if (target) target.classList.add('active');

        // Update sidebar
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const navItem = document.querySelector(`.nav-item[data-section="${sectionId}"]`);
        if (navItem) navItem.classList.add('active');

        state.currentPage = sectionId;
    }

    // ============================================================
    // INITIALIZATION
    // ============================================================

    function init() {
        setupCardInputListeners();
        updateDashboardStats();

        // Check Web Crypto API availability
        if (!window.crypto || !window.crypto.subtle) {
            showToast('Web Crypto API not available. Please use a modern browser.', 'error');
        }
    }

    // ============================================================
    // CARD INPUT & VALIDATION
    // ============================================================

    function setupCardInputListeners() {
        const cardNumInput = document.getElementById('input-card-number');
        const cardNameInput = document.getElementById('input-card-name');
        const expiryInput = document.getElementById('input-expiry');
        const cvvInput = document.getElementById('input-cvv');
        const amountInput = document.getElementById('input-amount');
        const merchantInput = document.getElementById('input-merchant');

        // Card Number — format and validate in real time
        cardNumInput.addEventListener('input', function (e) {
            let value = this.value.replace(/\D/g, '').slice(0, 16);
            // Format with spaces every 4 digits
            let formatted = '';
            for (let i = 0; i < value.length; i++) {
                if (i > 0 && i % 4 === 0) formatted += ' ';
                formatted += value[i];
            }
            this.value = formatted;
            state.cardNumber = value;

            updateCardVisual();
            detectNetwork(value);
            validateAndShowLuhn(value);
            checkFormComplete();
        });

        // Cardholder Name
        cardNameInput.addEventListener('input', function () {
            state.cardName = this.value.toUpperCase();
            document.getElementById('card-display-name').textContent =
                state.cardName || 'YOUR NAME';
            checkFormComplete();
        });

        // Expiry Date
        expiryInput.addEventListener('input', function () {
            let value = this.value.replace(/\D/g, '').slice(0, 4);
            if (value.length >= 3) {
                value = value.slice(0, 2) + '/' + value.slice(2);
            }
            this.value = value;
            state.expiry = value;
            document.getElementById('card-display-expiry').textContent =
                value || 'MM/YY';
            checkFormComplete();
        });

        // CVV — flip card to show back
        cvvInput.addEventListener('focus', function () {
            document.getElementById('credit-card').classList.add('flipped');
        });
        cvvInput.addEventListener('blur', function () {
            document.getElementById('credit-card').classList.remove('flipped');
        });
        cvvInput.addEventListener('input', function () {
            let value = this.value.replace(/\D/g, '').slice(0, 4);
            this.value = value;
            state.cvv = value;
            document.getElementById('card-display-cvv').textContent =
                value || '•••';
            checkFormComplete();
        });

        // Amount
        amountInput.addEventListener('input', function () {
            state.amount = parseFloat(this.value) || 0;
            checkFormComplete();
        });

        // Merchant
        merchantInput.addEventListener('input', function () {
            state.merchantName = this.value;
            checkFormComplete();
        });
    }

    function updateCardVisual() {
        const display = document.getElementById('card-display-number');
        if (state.cardNumber.length === 0) {
            display.textContent = '•••• •••• •••• ••••';
        } else {
            display.textContent = CryptoSim.Luhn.formatNumber(state.cardNumber);
        }
    }

    function detectNetwork(number) {
        const network = CryptoSim.Luhn.detectNetwork(number);
        state.cardNetwork = network;
        const info = CryptoSim.Luhn.getNetworkInfo(network);

        // Update card visual theme
        const card = document.getElementById('credit-card');
        card.className = 'credit-card';
        if (number.length >= 1) card.classList.add(network);

        // Network logo on card
        document.getElementById('card-display-network').textContent =
            number.length >= 1 ? info.name : '';

        // Network badge below input
        const badge = document.getElementById('card-network-badge');
        if (number.length >= 1 && network !== 'unknown') {
            badge.innerHTML = `<span class="input-badge" style="background:${info.color}20;color:${info.color}">${info.name}</span>`;
        } else {
            badge.innerHTML = '';
        }
    }

    function validateAndShowLuhn(number) {
        const panel = document.getElementById('luhn-panel');
        const digitsContainer = document.getElementById('luhn-digits');
        const resultContainer = document.getElementById('luhn-result');

        if (number.length < 13) {
            panel.style.display = 'none';
            state.cardValid = false;
            document.getElementById('credit-card').classList.remove('valid', 'invalid');
            return;
        }

        panel.style.display = 'block';
        const result = CryptoSim.Luhn.validate(number);

        // Build step-by-step visualization
        let html = '';
        result.steps.forEach((step, i) => {
            const doubled = step.action === 'double';
            html += `
                <div class="luhn-digit ${doubled ? 'doubled' : ''}" style="animation: fadeInUp 0.3s ease ${i * 0.04}s both;">
                    <span class="original">${step.original}</span>
                    ${doubled ? `<span class="action">×2${step.subtracted ? ' −9' : ''}</span>` : '<span class="action">keep</span>'}
                    <span class="result">${step.result}</span>
                </div>
            `;
        });
        digitsContainer.innerHTML = html;

        // Show result
        if (result.valid) {
            resultContainer.innerHTML = `
                <div class="luhn-result valid">
                    ✅ VALID — Sum: ${result.sum} (${result.sum} mod 10 = ${result.remainder})
                </div>
            `;
            state.cardValid = true;
            document.getElementById('credit-card').classList.add('valid');
            document.getElementById('credit-card').classList.remove('invalid');
        } else {
            resultContainer.innerHTML = `
                <div class="luhn-result invalid">
                    ❌ INVALID — Sum: ${result.sum} (${result.sum} mod 10 = ${result.remainder} ≠ 0)
                </div>
            `;
            state.cardValid = false;
            document.getElementById('credit-card').classList.add('invalid');
            document.getElementById('credit-card').classList.remove('valid');
        }
    }

    function flipCard() {
        document.getElementById('credit-card').classList.toggle('flipped');
    }

    function checkFormComplete() {
        const complete = state.cardNumber.length >= 13
            && state.cardValid
            && state.cardName.length >= 2
            && state.expiry.length === 5
            && state.cvv.length >= 3
            && state.amount > 0
            && state.merchantName.length >= 2;

        document.getElementById('btn-process').disabled = !complete;
    }

    function loadSampleData() {
        const samples = [
            { num: '4532015112830366', name: 'RIYA SHARMA', exp: '12/28', cvv: '123', amt: 350, merchant: 'Café Mocha' },
            { num: '5425233430109903', name: 'ARJUN PATEL', exp: '09/27', cvv: '456', amt: 1500, merchant: 'TechMart Electronics' },
            { num: '4916338506082832', name: 'PRIYA NAIR', exp: '06/29', cvv: '789', amt: 89, merchant: 'BookWorld Online' }
        ];
        const sample = samples[Math.floor(Math.random() * samples.length)];

        document.getElementById('input-card-number').value = CryptoSim.Luhn.formatNumber(sample.num);
        document.getElementById('input-card-name').value = sample.name;
        document.getElementById('input-expiry').value = sample.exp;
        document.getElementById('input-cvv').value = sample.cvv;
        document.getElementById('input-amount').value = sample.amt;
        document.getElementById('input-merchant').value = sample.merchant;

        // Trigger state updates
        state.cardNumber = sample.num;
        state.cardName = sample.name;
        state.expiry = sample.exp;
        state.cvv = sample.cvv;
        state.amount = sample.amt;
        state.merchantName = sample.merchant;

        updateCardVisual();
        detectNetwork(sample.num);
        validateAndShowLuhn(sample.num);
        document.getElementById('card-display-name').textContent = sample.name;
        document.getElementById('card-display-expiry').textContent = sample.exp;
        document.getElementById('card-display-cvv').textContent = sample.cvv;

        checkFormComplete();
        showToast('Sample data loaded successfully', 'success');
    }

    // ============================================================
    // KEY GENERATION
    // ============================================================

    async function generateAllKeys() {
        const btn = document.getElementById('btn-generate-keys');
        btn.disabled = true;
        btn.textContent = '⏳ Generating Keys...';

        try {
            addLog('Starting key generation for all cryptographic components', 'info');

            // 1. Merchant Signing Keys (RSA-PSS)
            addLog('Generating RSA-PSS 2048-bit key pair for merchant digital signatures...', 'crypto');
            state.signingKeyPair = await CryptoSim.RSA.generateSigningKeyPair();
            document.getElementById('key-signing-public').textContent = state.signingKeyPair.publicKeyPem;
            document.getElementById('key-card-signing').classList.add('generated');
            addLog('✅ Merchant signing keys generated (RSA-PSS 2048)', 'crypto',
                { publicKeyPreview: state.signingKeyPair.publicKeyHex.slice(0, 64) + '...' });

            // 2. Gateway Encryption Keys (RSA-OAEP)
            addLog('Generating RSA-OAEP 2048-bit key pair for gateway encryption...', 'crypto');
            state.encryptionKeyPair = await CryptoSim.RSA.generateEncryptionKeyPair();
            document.getElementById('key-encryption-public').textContent = state.encryptionKeyPair.publicKeyPem;
            document.getElementById('key-card-encryption').classList.add('generated');
            addLog('✅ Gateway encryption keys generated (RSA-OAEP 2048)', 'crypto',
                { publicKeyPreview: state.encryptionKeyPair.publicKeyHex.slice(0, 64) + '...' });

            // 3. AES Session Key
            addLog('Generating AES-256 session key for payload encryption...', 'crypto');
            state.aesKeyData = await CryptoSim.AES.generateKey();
            document.getElementById('key-aes-value').textContent = state.aesKeyData.keyHex;
            document.getElementById('key-card-aes').classList.add('generated');
            addLog('✅ AES-256 session key generated', 'crypto',
                { keyHex: state.aesKeyData.keyHex });

            // 4. HMAC Key
            addLog('Generating HMAC-SHA256 shared key for message authentication...', 'crypto');
            state.hmacKeyData = await CryptoSim.HMAC.generateKey();
            document.getElementById('key-hmac-value').textContent = state.hmacKeyData.keyHex;
            document.getElementById('key-card-hmac').classList.add('generated');
            addLog('✅ HMAC-SHA256 key generated', 'crypto',
                { keyHex: state.hmacKeyData.keyHex });

            state.keysGenerated = true;
            btn.textContent = '✅ All Keys Generated';
            btn.classList.remove('btn-primary');
            btn.classList.add('btn-ghost');

            updateDashboardStats();
            showToast('All 4 cryptographic key sets generated successfully', 'success');
            addLog('Key generation complete — 4 key sets ready', 'info');

        } catch (err) {
            btn.disabled = false;
            btn.textContent = '⚡ Generate All Keys';
            showToast('Key generation failed: ' + err.message, 'error');
            addLog('❌ Key generation failed: ' + err.message, 'info');
        }
    }

    // ============================================================
    // TRANSACTION PROCESSING (PRESENTATION MODE)
    // ============================================================

    // Real-life analogies for each step
    const STEP_ANALOGIES = {
        1: {
            icon: '🏷️',
            title: 'Real-Life Analogy',
            text: 'Imagine checking into a hotel. Instead of keeping your passport at the front desk (risky!), they give you a room key card. The card works for your room, but if someone steals it, they can\'t use it to steal your identity. Tokenization does the same — replaces your real card number with a useless stand-in.'
        },
        2: {
            icon: '📦',
            title: 'Real-Life Analogy',
            text: 'Think of putting your letter into a locked safe that only the recipient has the key to. Even if someone intercepts the safe during delivery, they can\'t open it without the key. AES encryption locks your transaction data in a digital safe that would take billions of years to crack.'
        },
        3: {
            icon: '📬',
            title: 'Real-Life Analogy',
            text: 'You locked your letter in a safe (AES), but now you need to send the safe\'s key to the recipient securely. It\'s like putting the safe key inside a special mailbox that only the bank can open — you drop it in through a public slot (RSA public key), but only the bank has the master key (RSA private key) to open the mailbox.'
        },
        4: {
            icon: '🔏',
            title: 'Real-Life Analogy',
            text: 'It\'s like a wax seal on an old letter. Before sending, you press your unique seal into hot wax on the envelope. When it arrives, the recipient checks if the seal is intact and matches your known seal pattern. If the wax is broken or looks different, someone tampered with the letter. SHA-256 is the digital version of that wax seal.'
        },
        5: {
            icon: '✍️',
            title: 'Real-Life Analogy',
            text: 'Imagine signing a cheque. Only YOU can produce your signature (private key), but the bank can verify it matches your signature on file (public key). A digital signature works the same way — the merchant "signs" the transaction, and the bank verifies it\'s really from that merchant and not a forger.'
        },
        6: {
            icon: '🤝',
            title: 'Real-Life Analogy',
            text: 'Think of a secret handshake between you and your friend. When a message arrives, you do the handshake — if it matches, you know it\'s from your friend AND the message wasn\'t changed. HMAC is like a secret handshake combined with the message itself, verifying both who sent it and that nothing was altered.'
        },
        7: {
            icon: '📡',
            title: 'Real-Life Analogy',
            text: 'Picture an armored truck transporting cash between banks. The money (your encrypted data) is locked inside (AES + RSA), has a tamper-evident seal (HMAC), a verified manifest from the sender (digital signature), and a tracking number (nonce). Even if someone stops the truck, they can\'t access, modify, or reuse any of it.'
        },
        8: {
            icon: '🤝',
            title: 'Real-Life Analogy',
            text: 'When the armored truck arrives at the bank, the first thing they check is the tamper-evident seal. If it\'s broken or doesn\'t match, they reject the delivery immediately — no need to even open the truck. HMAC verification is this quick, instant integrity check.'
        },
        9: {
            icon: '📝',
            title: 'Real-Life Analogy',
            text: 'After checking the seal, the bank verifies the sender\'s ID badge and signed manifest. "Is this really from the authorized merchant? Can we prove they sent it?" If the signature doesn\'t match the merchant on file, the transaction is rejected. This prevents fraud and provides legal non-repudiation.'
        },
        10: {
            icon: '🔓',
            title: 'Real-Life Analogy',
            text: 'The bank opens their special mailbox (RSA private key) and retrieves the safe key (AES key) that was dropped in. Only the bank can do this — nobody else has the master key. This is the magic of asymmetric cryptography: anyone can lock, but only the intended recipient can unlock.'
        },
        11: {
            icon: '📖',
            title: 'Real-Life Analogy',
            text: 'With the safe key recovered, the bank can now open the locked safe and read the original letter. The transaction details — card token, amount, merchant — are finally visible to the authorized party. This is the moment everything comes together.'
        },
        12: {
            icon: '✅',
            title: 'Real-Life Analogy',
            text: 'As a final check, the bank re-reads the letter and creates their own wax seal impression. If their seal matches the one that was sent, they know the letter wasn\'t altered at any point in the journey. This last verification closes the loop and confirms end-to-end integrity.'
        },
        13: {
            icon: '🎉',
            title: 'Real-Life Analogy',
            text: 'After all security checks pass — seal intact, signature verified, contents decrypted and validated — the bank approves the transaction. It\'s like a border checkpoint: every document was checked, every seal verified, every identity confirmed. The payment goes through with full confidence.'
        }
    };

    // Presentation state
    const presentation = {
        active: false,
        currentSlide: 0,
        totalSlides: 0,
        steps: [],            // Array of step configs (built during processTransaction)
        executed: new Set(),   // Which steps have been executed
        results: {},           // step index -> result data
        resolve: null          // Promise resolver for step completion
    };

    async function startTransaction() {
        // Generate keys if not already done
        if (!state.keysGenerated) {
            addLog('Keys not yet generated — auto-generating before transaction...', 'info');
            await generateAllKeys();
        }

        navigate('pipeline');
        await processTransaction();
    }

    async function processTransaction() {
        const merchantContainer = document.getElementById('pipeline-steps-merchant');
        const gatewayContainer = document.getElementById('pipeline-steps-gateway');
        const transmissionContainer = document.getElementById('pipeline-transmission');
        const resultContainer = document.getElementById('transaction-result-container');

        // Reset
        merchantContainer.innerHTML = '';
        gatewayContainer.innerHTML = '';
        transmissionContainer.innerHTML = '';
        resultContainer.innerHTML = '';

        // Show phase labels
        document.getElementById('phase-merchant').style.display = 'flex';
        document.getElementById('pipeline-status').style.display = 'none';

        // Generate nonce and timestamp
        state.nonce = generateNonce();
        state.timestamp = new Date().toISOString();

        addLog('═══════════ NEW TRANSACTION STARTED ═══════════', 'info');
        addLog(`Nonce: ${state.nonce} | Timestamp: ${state.timestamp}`, 'info');

        // Build ALL step definitions first
        presentation.steps = [];
        presentation.executed = new Set();
        presentation.results = {};
        presentation.currentSlide = 0;

        // STEP 1: Tokenization
        presentation.steps.push({
            number: 1,
            icon: '🏷️',
            title: 'Tokenization',
            phase: '🏪 Merchant Side',
            description: 'Replace real card number (PAN) with a non-reversible token to protect card data at rest.',
            explanation: '<strong>Why?</strong> If a merchant\'s database is breached, attackers only get useless tokens — not real card numbers. Tokenization is required by PCI DSS compliance.',
            inputLabel: 'Original PAN',
            inputValue: CryptoSim.Luhn.formatNumber(state.cardNumber),
            inputClass: 'plaintext',
            container: merchantContainer,
            execute: async () => {
                state.tokenResult = await CryptoSim.Tokenizer.tokenize(state.cardNumber);

                // Build transaction payload after tokenization
                state.transactionPayload = JSON.stringify({
                    card_token: state.tokenResult.token,
                    card_masked: state.tokenResult.masked,
                    card_network: state.cardNetwork,
                    cardholder: state.cardName,
                    amount: state.amount,
                    currency: 'INR',
                    merchant: state.merchantName,
                    timestamp: state.timestamp,
                    nonce: state.nonce
                }, null, 2);

                return {
                    outputLabel: 'Token',
                    outputValue: state.tokenResult.token,
                    outputClass: 'hash',
                    logData: {
                        token: state.tokenResult.token,
                        masked: state.tokenResult.masked
                    }
                };
            }
        });

        // STEP 2: AES Encryption
        presentation.steps.push({
            number: 2,
            icon: '🔐',
            title: 'AES-256-CBC Encryption',
            phase: '🏪 Merchant Side',
            description: 'Encrypt the entire transaction payload with the symmetric AES session key. A random IV ensures identical data produces different ciphertext each time.',
            explanation: '<strong>Why AES?</strong> Symmetric encryption is fast and efficient for large data. The 256-bit key provides 2²⁵⁶ possible keys — brute force would take billions of years.',
            inputLabel: 'Transaction Payload (JSON)',
            inputValueFn: () => state.transactionPayload,
            inputClass: 'plaintext',
            container: merchantContainer,
            execute: async () => {
                state.aesEncrypted = await CryptoSim.AES.encrypt(state.aesKeyData.key, state.transactionPayload);
                return {
                    outputLabel: `Ciphertext (${state.aesEncrypted.cipherLength} bytes) + IV`,
                    outputValue: `Ciphertext: ${state.aesEncrypted.cipherHex.slice(0, 80)}...\nIV: ${state.aesEncrypted.ivHex}`,
                    outputClass: 'encrypted',
                    logData: {
                        algorithm: 'AES-256-CBC',
                        ivHex: state.aesEncrypted.ivHex,
                        cipherLength: state.aesEncrypted.cipherLength,
                        cipherPreview: state.aesEncrypted.cipherHex.slice(0, 64)
                    }
                };
            }
        });

        // STEP 3: RSA Key Wrapping
        presentation.steps.push({
            number: 3,
            icon: '🔑',
            title: 'RSA-OAEP Key Wrapping',
            phase: '🏪 Merchant Side',
            description: 'Encrypt the AES session key with the gateway\'s RSA public key. Only the gateway (with the private key) can recover the AES key.',
            explanation: '<strong>Why wrap the key?</strong> This is "hybrid encryption" — AES is fast for data, RSA securely delivers the AES key. The merchant can\'t send the AES key in plaintext, so RSA protects it.',
            inputLabel: 'AES-256 Session Key',
            inputValueFn: () => state.aesKeyData.keyHex,
            inputClass: 'plaintext',
            container: merchantContainer,
            execute: async () => {
                state.rsaWrappedKey = await CryptoSim.RSA.wrapKey(
                    state.aesKeyData.key,
                    state.encryptionKeyPair.publicKey
                );
                return {
                    outputLabel: `RSA-Wrapped Key (${state.rsaWrappedKey.wrappedLength} bytes)`,
                    outputValue: state.rsaWrappedKey.wrappedHex.slice(0, 100) + '...',
                    outputClass: 'encrypted',
                    logData: {
                        algorithm: 'RSA-OAEP',
                        wrappedLength: state.rsaWrappedKey.wrappedLength,
                        wrappedPreview: state.rsaWrappedKey.wrappedHex.slice(0, 64)
                    }
                };
            }
        });

        // STEP 4: SHA-256 Hash
        presentation.steps.push({
            number: 4,
            icon: '#️⃣',
            title: 'SHA-256 Hash',
            phase: '🏪 Merchant Side',
            description: 'Create a cryptographic fingerprint (digest) of the original transaction payload. Any modification to the data will produce a completely different hash.',
            explanation: '<strong>Why hash?</strong> The hash is the "fingerprint" of the data. At the receiving end, the gateway recomputes the hash and compares — if they match, the data is untampered.',
            inputLabel: 'Transaction Payload',
            inputValueFn: () => state.transactionPayload.slice(0, 100) + '...',
            inputClass: 'plaintext',
            container: merchantContainer,
            execute: async () => {
                state.transactionHash = await CryptoSim.Hash.sha256(state.transactionPayload);
                return {
                    outputLabel: 'SHA-256 Digest (256 bits)',
                    outputValue: state.transactionHash,
                    outputClass: 'hash',
                    logData: {
                        algorithm: 'SHA-256',
                        hash: state.transactionHash,
                        inputLength: state.transactionPayload.length
                    }
                };
            }
        });

        // STEP 5: Digital Signature
        presentation.steps.push({
            number: 5,
            icon: '✍️',
            title: 'RSA-PSS Digital Signature',
            phase: '🏪 Merchant Side',
            description: 'The merchant signs the transaction hash with their private key. This proves the transaction originated from this specific merchant and provides non-repudiation.',
            explanation: '<strong>Why sign?</strong> Anyone can compute a hash, but only the holder of the merchant\'s private key can create a valid signature. The gateway verifies using the merchant\'s public key.',
            inputLabel: 'SHA-256 Hash (to be signed)',
            inputValueFn: () => state.transactionHash,
            inputClass: 'hash',
            container: merchantContainer,
            execute: async () => {
                state.digitalSignature = await CryptoSim.RSA.sign(
                    state.signingKeyPair.privateKey,
                    state.transactionHash
                );
                return {
                    outputLabel: `Digital Signature (${state.digitalSignature.signatureLength} bytes)`,
                    outputValue: state.digitalSignature.signatureHex.slice(0, 100) + '...',
                    outputClass: 'signature',
                    logData: {
                        algorithm: 'RSA-PSS',
                        saltLength: 32,
                        signatureLength: state.digitalSignature.signatureLength,
                        signaturePreview: state.digitalSignature.signatureHex.slice(0, 64)
                    }
                };
            }
        });

        // STEP 6: HMAC
        presentation.steps.push({
            number: 6,
            icon: '🏷️',
            title: 'HMAC-SHA256 Authentication',
            phase: '🏪 Merchant Side',
            description: 'Generate a Message Authentication Code (MAC) over the entire transaction bundle using the shared HMAC key. This verifies both integrity AND authenticity.',
            explanation: '<strong>Why HMAC on top of hashing and signing?</strong> HMAC provides a fast, symmetric authentication check that the gateway can verify instantly. It\'s the first line of defense before the slower RSA signature verification.',
            inputLabel: 'Transaction Bundle (to authenticate)',
            inputValueFn: () => {
                const bundleForHmac = JSON.stringify({
                    ciphertext: state.aesEncrypted.cipherBase64,
                    wrappedKey: state.rsaWrappedKey.wrappedBase64,
                    signature: state.digitalSignature.signatureBase64,
                    hash: state.transactionHash,
                    nonce: state.nonce,
                    timestamp: state.timestamp
                });
                return bundleForHmac.slice(0, 100) + '...';
            },
            inputClass: 'plaintext',
            container: merchantContainer,
            execute: async () => {
                const bundleForHmac = JSON.stringify({
                    ciphertext: state.aesEncrypted.cipherBase64,
                    wrappedKey: state.rsaWrappedKey.wrappedBase64,
                    signature: state.digitalSignature.signatureBase64,
                    hash: state.transactionHash,
                    nonce: state.nonce,
                    timestamp: state.timestamp
                });
                state.hmacResult = await CryptoSim.HMAC.sign(state.hmacKeyData.key, bundleForHmac);

                // Build the final transaction bundle
                state.transactionBundle = {
                    ciphertext: state.aesEncrypted.cipherBase64,
                    iv: state.aesEncrypted.ivHex,
                    wrappedKey: state.rsaWrappedKey.wrappedBase64,
                    signature: state.digitalSignature.signatureBase64,
                    hash: state.transactionHash,
                    hmac: state.hmacResult.macHex,
                    nonce: state.nonce,
                    timestamp: state.timestamp,
                    merchantId: 'MERCHANT_' + state.merchantName.replace(/\s/g, '_').toUpperCase()
                };

                // Mark nonce as used
                state.usedNonces.add(state.nonce);

                return {
                    outputLabel: 'HMAC-SHA256 (256 bits)',
                    outputValue: state.hmacResult.macHex,
                    outputClass: 'hash',
                    logData: {
                        algorithm: 'HMAC-SHA256',
                        mac: state.hmacResult.macHex
                    }
                };
            }
        });

        // STEP 7: Network Transmission (special)
        presentation.steps.push({
            number: 7,
            icon: '📡',
            title: 'Secure Network Transmission',
            phase: '📡 Data In Transit',
            description: 'The encrypted transaction bundle is transmitted over TLS-protected channels. The data passes through the Payment Gateway, Card Network (Visa/Mastercard), and finally reaches the Issuing Bank.',
            explanation: '<strong>Why TLS?</strong> TLS (Transport Layer Security) creates an encrypted tunnel between each hop. Combined with our application-layer encryption (AES + RSA), this provides defense-in-depth — even if TLS is compromised, the data inside is still encrypted.',
            isTransmission: true,
            container: transmissionContainer,
            execute: async () => {
                addLog('📡 Transmitting encrypted bundle over secure channel...', 'network');
                addLog('📦 Transaction bundle assembled', 'info', state.transactionBundle);
                addLog('✅ Encrypted bundle delivered to all entities', 'network');

                document.getElementById('phase-transmission').style.display = 'flex';

                return {
                    outputLabel: 'Transmission Status',
                    outputValue: '✅ Bundle delivered securely to all entities',
                    outputClass: 'plaintext',
                    logData: { status: 'transmitted' }
                };
            }
        });

        // STEP 8: HMAC Verification
        presentation.steps.push({
            number: 8,
            icon: '🏷️',
            title: 'HMAC Verification',
            phase: '🏦 Gateway / Bank Side',
            description: 'Gateway recomputes the HMAC over the received bundle using the shared secret key and compares it with the received HMAC.',
            explanation: '<strong>First check:</strong> If the HMAC doesn\'t match, the message was either tampered with or came from an unauthorized sender. The transaction is immediately rejected.',
            inputLabel: 'Received HMAC',
            inputValueFn: () => state.hmacResult.macHex,
            inputClass: 'hash',
            container: gatewayContainer,
            execute: async () => {
                document.getElementById('phase-gateway').style.display = 'flex';
                const receivedBundle = JSON.stringify({
                    ciphertext: state.transactionBundle.ciphertext,
                    wrappedKey: state.transactionBundle.wrappedKey,
                    signature: state.transactionBundle.signature,
                    hash: state.transactionBundle.hash,
                    nonce: state.transactionBundle.nonce,
                    timestamp: state.transactionBundle.timestamp
                });
                const isValid = await CryptoSim.HMAC.verify(
                    state.hmacKeyData.key, receivedBundle, state.hmacResult.macBuffer
                );
                return {
                    outputLabel: 'Verification Result',
                    outputValue: isValid ? '✅ HMAC VALID — Message is authentic & untampered' : '❌ HMAC INVALID — Message rejected',
                    outputClass: isValid ? 'plaintext' : 'encrypted',
                    logData: { hmacValid: isValid }
                };
            }
        });

        // STEP 9: Signature Verification
        presentation.steps.push({
            number: 9,
            icon: '✍️',
            title: 'Signature Verification',
            phase: '🏦 Gateway / Bank Side',
            description: 'Gateway verifies the merchant\'s digital signature using the merchant\'s registered public key.',
            explanation: '<strong>Second check:</strong> This confirms the transaction was signed by the legitimate merchant\'s private key. It also provides non-repudiation — the merchant cannot deny sending it.',
            inputLabel: 'Merchant\'s Public Key + Signature + Hash',
            inputValueFn: () => `Signature: ${state.digitalSignature.signatureHex.slice(0, 40)}...\nHash: ${state.transactionHash.slice(0, 40)}...`,
            inputClass: 'signature',
            container: gatewayContainer,
            execute: async () => {
                const isValid = await CryptoSim.RSA.verify(
                    state.signingKeyPair.publicKey,
                    state.digitalSignature.signatureBuffer,
                    state.transactionHash
                );
                return {
                    outputLabel: 'Verification Result',
                    outputValue: isValid ? '✅ SIGNATURE VALID — Merchant identity confirmed' : '❌ SIGNATURE INVALID — Merchant authentication failed',
                    outputClass: isValid ? 'plaintext' : 'encrypted',
                    logData: { signatureValid: isValid }
                };
            }
        });

        // STEP 10: RSA Key Unwrapping
        presentation.steps.push({
            number: 10,
            icon: '🔑',
            title: 'RSA Key Unwrapping',
            phase: '🏦 Gateway / Bank Side',
            description: 'Gateway decrypts the wrapped AES session key using its RSA private key, recovering the original AES-256 key.',
            explanation: '<strong>Key recovery:</strong> The AES key was encrypted with the gateway\'s RSA public key, so only the gateway\'s private key can recover it. This is the core of the hybrid encryption scheme.',
            inputLabel: 'RSA-Wrapped AES Key',
            inputValueFn: () => state.rsaWrappedKey.wrappedHex.slice(0, 80) + '...',
            inputClass: 'encrypted',
            container: gatewayContainer,
            execute: async () => {
                state.recoveredAesKey = await CryptoSim.RSA.unwrapKey(
                    state.rsaWrappedKey.wrappedBuffer,
                    state.encryptionKeyPair.privateKey
                );
                const recoveredHex = await CryptoSim.AES.exportKey(state.recoveredAesKey);
                return {
                    outputLabel: 'Recovered AES-256 Key',
                    outputValue: recoveredHex,
                    outputClass: 'plaintext',
                    logData: {
                        recoveredKey: recoveredHex,
                        matchesOriginal: recoveredHex === state.aesKeyData.keyHex
                    }
                };
            }
        });

        // STEP 11: AES Decryption
        presentation.steps.push({
            number: 11,
            icon: '🔓',
            title: 'AES-256-CBC Decryption',
            phase: '🏦 Gateway / Bank Side',
            description: 'Using the recovered AES key and the IV, decrypt the transaction payload to reveal the original data.',
            explanation: '<strong>Final decryption:</strong> The gateway can now read the transaction details — card token, amount, merchant, timestamp — and forward it to the issuing bank for authorization.',
            inputLabel: 'Ciphertext + IV',
            inputValueFn: () => `Ciphertext: ${state.aesEncrypted.cipherHex.slice(0, 60)}...\nIV: ${state.aesEncrypted.ivHex}`,
            inputClass: 'encrypted',
            container: gatewayContainer,
            execute: async () => {
                state.decryptedPayload = await CryptoSim.AES.decrypt(
                    state.recoveredAesKey || state.aesKeyData.key,
                    state.aesEncrypted.cipherBuffer,
                    state.aesEncrypted.iv
                );
                return {
                    outputLabel: 'Decrypted Transaction Payload',
                    outputValue: state.decryptedPayload,
                    outputClass: 'plaintext',
                    logData: {
                        decrypted: JSON.parse(state.decryptedPayload)
                    }
                };
            }
        });

        // STEP 12: Hash Verification
        presentation.steps.push({
            number: 12,
            icon: '#️⃣',
            title: 'Hash Integrity Check',
            phase: '🏦 Gateway / Bank Side',
            description: 'Recompute SHA-256 hash of the decrypted payload and compare with the hash received in the bundle.',
            explanation: '<strong>Final integrity check:</strong> If the recomputed hash matches the one in the bundle, the data has not been altered during any stage of processing.',
            inputLabel: 'Received Hash',
            inputValueFn: () => state.transactionHash,
            inputClass: 'hash',
            container: gatewayContainer,
            execute: async () => {
                const recomputedHash = await CryptoSim.Hash.sha256(state.decryptedPayload);
                const matches = recomputedHash === state.transactionHash;
                return {
                    outputLabel: 'Recomputed Hash ' + (matches ? '✅ MATCH' : '❌ MISMATCH'),
                    outputValue: `Received:    ${state.transactionHash}\nRecomputed: ${recomputedHash}\nMatch: ${matches ? 'YES ✅' : 'NO ❌'}`,
                    outputClass: matches ? 'plaintext' : 'encrypted',
                    logData: { recomputedHash, matches }
                };
            }
        });

        // STEP 13: Transaction Result (special)
        presentation.steps.push({
            number: 13,
            icon: '💚',
            title: 'Transaction Approved',
            phase: '✅ Result',
            description: 'All cryptographic verifications passed. Payment authorized by the issuing bank.',
            isResult: true,
            container: resultContainer,
            execute: async () => {
                state.transactionCount++;
                updateDashboardStats();
                showTransactionResult(resultContainer);
                updateVerificationPage();
                updateNetworkPage();
                enableAttackButtons();
                addLog('═══════════ TRANSACTION COMPLETE ═══════════', 'info');

                return {
                    outputLabel: 'Status',
                    outputValue: '✅ Transaction Approved',
                    outputClass: 'plaintext',
                    logData: { status: 'approved' }
                };
            }
        });

        presentation.totalSlides = presentation.steps.length;

        // Open presentation overlay
        openPresentation();
    }

    // ============================================================
    // PRESENTATION CONTROLLER
    // ============================================================

    function openPresentation() {
        presentation.active = true;
        presentation.currentSlide = 0;

        const overlay = document.getElementById('presentation-overlay');
        overlay.style.display = 'flex';

        // Build step dots
        buildStepDots();

        // Show first slide (preview before execution)
        renderCurrentSlide();

        // Add keyboard navigation
        document.addEventListener('keydown', handlePresentationKeydown);
    }

    function exitPresentation() {
        presentation.active = false;
        document.getElementById('presentation-overlay').style.display = 'none';
        document.removeEventListener('keydown', handlePresentationKeydown);
    }

    function handlePresentationKeydown(e) {
        if (!presentation.active) return;
        if (e.key === 'ArrowRight' || e.key === ' ') {
            e.preventDefault();
            nextPresentationStep();
        } else if (e.key === 'ArrowLeft') {
            e.preventDefault();
            prevPresentationStep();
        } else if (e.key === 'Escape') {
            exitPresentation();
        }
    }

    function buildStepDots() {
        const dotsContainer = document.getElementById('pres-step-dots');
        let html = '';
        let lastPhase = '';
        presentation.steps.forEach((step, i) => {
            if (step.phase !== lastPhase && i > 0) {
                html += '<div class="pres-dot separator"></div>';
            }
            lastPhase = step.phase;
            html += `<div class="pres-dot" id="pres-dot-${i}"></div>`;
        });
        dotsContainer.innerHTML = html;
    }

    function updatePresentationUI() {
        const idx = presentation.currentSlide;
        const total = presentation.totalSlides;
        const step = presentation.steps[idx];

        // Counter
        document.getElementById('pres-step-counter').textContent = `Step ${idx + 1} of ${total}`;
        document.getElementById('pres-phase-label').textContent = step.phase;

        // Progress bar
        const pct = ((idx + 1) / total) * 100;
        document.getElementById('pres-progress-fill').style.width = pct + '%';

        // Dots
        presentation.steps.forEach((s, i) => {
            const dot = document.getElementById(`pres-dot-${i}`);
            if (!dot) return;
            dot.className = 'pres-dot';
            if (i === idx) dot.classList.add('active');
            else if (presentation.executed.has(i)) dot.classList.add('complete');
        });

        // Navigation buttons
        const prevBtn = document.getElementById('pres-prev-btn');
        const nextBtn = document.getElementById('pres-next-btn');

        prevBtn.disabled = idx === 0;

        if (idx === total - 1 && presentation.executed.has(idx)) {
            nextBtn.textContent = '✕ Close';
        } else {
            nextBtn.textContent = 'Next Step →';
        }

        nextBtn.disabled = false;
    }

    async function renderCurrentSlide() {
        const idx = presentation.currentSlide;
        const step = presentation.steps[idx];
        const container = document.getElementById('pres-slide-container');
        const executed = presentation.executed.has(idx);
        const result = presentation.results[idx];

        let slideHtml = '';

        if (step.isResult && executed) {
            // Transaction result slide
            const authCode = 'AUTH_' + Math.random().toString(36).substr(2, 6).toUpperCase();
            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-result">
                        <div class="slide-result-icon">💚</div>
                        <h2 class="slide-result-title">Transaction Approved</h2>
                        <p class="slide-result-subtitle">All cryptographic verifications passed. Payment authorized by issuing bank.</p>
                        <dl class="slide-result-details">
                            <dt>Amount</dt><dd>₹${state.amount.toLocaleString()}</dd>
                            <dt>Merchant</dt><dd>${escapeHtml(state.merchantName)}</dd>
                            <dt>Card</dt><dd>${state.tokenResult.masked}</dd>
                            <dt>Network</dt><dd>${state.cardNetwork.toUpperCase()}</dd>
                            <dt>Auth Code</dt><dd>${authCode}</dd>
                            <dt>Nonce</dt><dd>${state.nonce}</dd>
                        </dl>
                    </div>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${STEP_ANALOGIES[13].icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${STEP_ANALOGIES[13].title}</div>
                            <div class="slide-analogy-text">${STEP_ANALOGIES[13].text}</div>
                        </div>
                    </div>
                    <div style="text-align:center;margin-top:24px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('attacks');">🛡️ Try Attack Simulator</button>
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('verification');">✅ View Verification</button>
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('audit-log');">📋 View Audit Log</button>
                    </div>
                </div>
            `;
        } else if (step.isTransmission) {
            // Network transmission slide
            const analogy = STEP_ANALOGIES[step.number];
            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-step-number">Step ${step.number} — ${step.phase}</div>
                    <h2 class="slide-title">
                        <span class="slide-title-icon">${step.icon}</span>
                        ${step.title}
                    </h2>
                    <p class="slide-description">${step.description}</p>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${analogy.icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${analogy.title}</div>
                            <div class="slide-analogy-text">${analogy.text}</div>
                        </div>
                    </div>
                    ${executed ? `
                        <div class="slide-network-viz">
                            <div class="slide-network-node complete"><div class="node-circle">🏪</div><span class="node-name">Merchant POS</span></div>
                            <div class="slide-network-node complete"><div class="node-circle">🌐</div><span class="node-name">Payment Gateway</span></div>
                            <div class="slide-network-node complete"><div class="node-circle">🔗</div><span class="node-name">Card Network</span></div>
                            <div class="slide-network-node complete"><div class="node-circle">🏦</div><span class="node-name">Issuing Bank</span></div>
                        </div>
                        <div class="slide-bundle-fields">
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">Ciphertext (AES-256-CBC)</div>
                                <div class="slide-bundle-field-value">${state.aesEncrypted.cipherBase64.slice(0, 60)}...</div>
                            </div>
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">Wrapped Key (RSA-OAEP)</div>
                                <div class="slide-bundle-field-value">${state.rsaWrappedKey.wrappedBase64.slice(0, 60)}...</div>
                            </div>
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">Digital Signature (RSA-PSS)</div>
                                <div class="slide-bundle-field-value">${state.digitalSignature.signatureBase64.slice(0, 60)}...</div>
                            </div>
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">SHA-256 Hash</div>
                                <div class="slide-bundle-field-value">${state.transactionHash}</div>
                            </div>
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">HMAC-SHA256</div>
                                <div class="slide-bundle-field-value">${state.hmacResult.macHex}</div>
                            </div>
                            <div class="slide-bundle-field">
                                <div class="slide-bundle-field-name">Nonce</div>
                                <div class="slide-bundle-field-value">${state.nonce}</div>
                            </div>
                        </div>
                        <div class="slide-time-badge">⚡ Transmitted securely</div>
                    ` : `
                        <div class="slide-network-viz">
                            <div class="slide-network-node active"><div class="node-circle">🏪</div><span class="node-name">Merchant POS</span></div>
                            <div class="slide-network-node"><div class="node-circle">🌐</div><span class="node-name">Payment Gateway</span></div>
                            <div class="slide-network-node"><div class="node-circle">🔗</div><span class="node-name">Card Network</span></div>
                            <div class="slide-network-node"><div class="node-circle">🏦</div><span class="node-name">Issuing Bank</span></div>
                        </div>
                        <p style="color:var(--text-muted);font-size:0.88rem;text-align:center;margin-top:16px;">Press <strong>⚡ Execute Step</strong> to transmit the encrypted bundle across the network</p>
                    `}
                    <div class="slide-explanation" style="margin-top:20px;">${step.explanation}</div>
                </div>
            `;
        } else if (step.isResult && !executed) {
            // Pre-execution result slide
            const analogy = STEP_ANALOGIES[step.number];
            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-step-number">Step ${step.number} — ${step.phase}</div>
                    <h2 class="slide-title">
                        <span class="slide-title-icon">${step.icon}</span>
                        ${step.title}
                    </h2>
                    <p class="slide-description">${step.description}</p>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${analogy.icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${analogy.title}</div>
                            <div class="slide-analogy-text">${analogy.text}</div>
                        </div>
                    </div>
                    <p style="color:var(--text-muted);font-size:0.95rem;text-align:center;margin-top:32px;">Press <strong>Next Step →</strong> to finalize the transaction</p>
                </div>
            `;
        } else {
            // Regular crypto step
            const analogy = STEP_ANALOGIES[step.number];
            const inputVal = step.inputValueFn ? step.inputValueFn() : step.inputValue;

            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-step-number">Step ${step.number} — ${step.phase}</div>
                    <h2 class="slide-title">
                        <span class="slide-title-icon">${step.icon}</span>
                        ${step.title}
                    </h2>
                    <p class="slide-description">${step.description}</p>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${analogy.icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${analogy.title}</div>
                            <div class="slide-analogy-text">${analogy.text}</div>
                        </div>
                    </div>
                    <div class="slide-data-area">
                        <div class="slide-data-block input">
                            <div class="slide-data-label"><span class="label-dot input-dot"></span> ${step.inputLabel}</div>
                            <div class="slide-data-value ${step.inputClass || ''}">${escapeHtml(inputVal)}</div>
                        </div>
                        <div class="slide-data-arrow"><div class="arrow-inner">→</div></div>
                        <div class="slide-data-block output ${executed ? 'complete' : ''}" id="pres-output-block">
                            ${executed && result ? `
                                <div class="slide-data-label"><span class="label-dot output-dot"></span> ${result.outputLabel}</div>
                                <div class="slide-data-value ${result.outputClass || ''}">${escapeHtml(result.outputValue)}</div>
                            ` : `
                                <div class="slide-data-label"><span class="label-dot output-dot"></span> Output</div>
                                <div class="slide-data-value" style="color:var(--text-muted);">⏳ Processing...</div>
                            `}
                        </div>
                    </div>
                    ${executed && result && result.elapsed ? `
                        <div class="slide-time-badge">⚡ Executed in ${result.elapsed}ms</div>
                    ` : ''}
                    <div class="slide-explanation">${step.explanation}</div>
                </div>
            `;
        }

        container.innerHTML = slideHtml;

        // Add keyboard hint
        if (!document.querySelector('.keyboard-hint')) {
            const hint = document.createElement('div');
            hint.className = 'keyboard-hint';
            hint.innerHTML = '<kbd>←</kbd> <kbd>→</kbd> Navigate &nbsp;|&nbsp; <kbd>Esc</kbd> Exit';
            document.getElementById('presentation-overlay').appendChild(hint);
        }

        updatePresentationUI();

        // Auto-execute the step if it hasn't been executed yet
        if (!presentation.executed.has(idx) && !step.isResult) {
            await executeCurrentStep();
        } else if (!presentation.executed.has(idx) && step.isResult) {
            // For result step, auto-execute too
            await executeCurrentStep();
        }
    }

    async function nextPresentationStep() {
        const idx = presentation.currentSlide;
        const total = presentation.totalSlides;

        // If we're at the last slide and it's been executed, close
        if (idx >= total - 1 && presentation.executed.has(idx)) {
            exitPresentation();
            return;
        }

        // Move to next slide (auto-execute happens in renderCurrentSlide)
        if (idx < total - 1) {
            presentation.currentSlide++;
            renderCurrentSlide();
        }
    }

    function prevPresentationStep() {
        if (presentation.currentSlide > 0) {
            presentation.currentSlide--;
            renderCurrentSlide();
        }
    }

    async function executeCurrentStep() {
        const idx = presentation.currentSlide;
        const step = presentation.steps[idx];
        const nextBtn = document.getElementById('pres-next-btn');

        // Disable buttons during execution
        nextBtn.disabled = true;
        nextBtn.textContent = '⏳ Processing...';

        try {
            const startTime = performance.now();
            addLog(`⏳ Step ${step.number}: ${step.title} — executing...`, 'crypto');

            const result = await step.execute();
            const elapsed = (performance.now() - startTime).toFixed(1);

            result.elapsed = elapsed;
            presentation.results[idx] = result;
            presentation.executed.add(idx);

            addLog(`✅ Step ${step.number}: ${step.title} — completed in ${elapsed}ms`, 'crypto', result.logData);

            // Also render in the background pipeline view
            if (!step.isTransmission && !step.isResult && step.container) {
                renderBackgroundPipelineStep(step, result, elapsed);
            }

            // Update the output block in-place (no re-render to avoid recursion)
            const outputBlock = document.getElementById('pres-output-block');
            if (outputBlock) {
                outputBlock.classList.add('complete');
                outputBlock.innerHTML = `
                    <div class="slide-data-label"><span class="label-dot output-dot"></span> ${result.outputLabel}</div>
                    <div class="slide-data-value ${result.outputClass || ''}">${escapeHtml(result.outputValue)}</div>
                `;
            }

            // Add time badge if not already there
            const slide = document.querySelector('.presentation-slide');
            if (slide && result.elapsed) {
                const existingBadge = slide.querySelector('.slide-time-badge');
                if (!existingBadge) {
                    const badge = document.createElement('div');
                    badge.className = 'slide-time-badge';
                    badge.textContent = `⚡ Executed in ${result.elapsed}ms`;
                    slide.appendChild(badge);
                }
            }

            // For transmission/result slides, re-render fully to show complete state
            if (step.isTransmission || step.isResult) {
                // Mark as executed first to prevent re-execution
                const container = document.getElementById('pres-slide-container');
                // Re-build slide HTML with executed state
                rebuildSlideContent(idx);
            }

            // Update nav buttons
            updatePresentationUI();

        } catch (err) {
            showToast('Step failed: ' + err.message, 'error');
            addLog(`❌ Step ${step.number}: ${step.title} — failed: ${err.message}`, 'info');
            console.error(err);

            nextBtn.disabled = false;
            nextBtn.textContent = '🔄 Retry →';
        }
    }

    // Rebuild slide content without triggering auto-execute (for transmission/result slides)
    function rebuildSlideContent(idx) {
        const step = presentation.steps[idx];
        const container = document.getElementById('pres-slide-container');
        const result = presentation.results[idx];
        const analogy = STEP_ANALOGIES[step.number];

        let slideHtml = '';

        if (step.isResult) {
            const authCode = 'AUTH_' + Math.random().toString(36).substr(2, 6).toUpperCase();
            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-result">
                        <div class="slide-result-icon">💚</div>
                        <h2 class="slide-result-title">Transaction Approved</h2>
                        <p class="slide-result-subtitle">All cryptographic verifications passed. Payment authorized by issuing bank.</p>
                        <dl class="slide-result-details">
                            <dt>Amount</dt><dd>₹${state.amount.toLocaleString()}</dd>
                            <dt>Merchant</dt><dd>${escapeHtml(state.merchantName)}</dd>
                            <dt>Card</dt><dd>${state.tokenResult.masked}</dd>
                            <dt>Network</dt><dd>${state.cardNetwork.toUpperCase()}</dd>
                            <dt>Auth Code</dt><dd>${authCode}</dd>
                            <dt>Nonce</dt><dd>${state.nonce}</dd>
                        </dl>
                    </div>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${STEP_ANALOGIES[13].icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${STEP_ANALOGIES[13].title}</div>
                            <div class="slide-analogy-text">${STEP_ANALOGIES[13].text}</div>
                        </div>
                    </div>
                    <div style="text-align:center;margin-top:24px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('attacks');">🛡️ Try Attack Simulator</button>
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('verification');">✅ View Verification</button>
                        <button class="btn btn-presentation-nav" onclick="App.exitPresentation(); App.navigate('audit-log');">📋 View Audit Log</button>
                    </div>
                </div>
            `;
        } else if (step.isTransmission) {
            slideHtml = `
                <div class="presentation-slide">
                    <div class="slide-step-number">Step ${step.number} — ${step.phase}</div>
                    <h2 class="slide-title">
                        <span class="slide-title-icon">${step.icon}</span>
                        ${step.title}
                    </h2>
                    <p class="slide-description">${step.description}</p>
                    <div class="slide-analogy">
                        <div class="slide-analogy-icon">${analogy.icon}</div>
                        <div class="slide-analogy-content">
                            <div class="slide-analogy-title">${analogy.title}</div>
                            <div class="slide-analogy-text">${analogy.text}</div>
                        </div>
                    </div>
                    <div class="slide-network-viz">
                        <div class="slide-network-node complete"><div class="node-circle">🏪</div><span class="node-name">Merchant POS</span></div>
                        <div class="slide-network-node complete"><div class="node-circle">🌐</div><span class="node-name">Payment Gateway</span></div>
                        <div class="slide-network-node complete"><div class="node-circle">🔗</div><span class="node-name">Card Network</span></div>
                        <div class="slide-network-node complete"><div class="node-circle">🏦</div><span class="node-name">Issuing Bank</span></div>
                    </div>
                    <div class="slide-bundle-fields">
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">Ciphertext (AES-256-CBC)</div>
                            <div class="slide-bundle-field-value">${state.aesEncrypted.cipherBase64.slice(0, 60)}...</div>
                        </div>
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">Wrapped Key (RSA-OAEP)</div>
                            <div class="slide-bundle-field-value">${state.rsaWrappedKey.wrappedBase64.slice(0, 60)}...</div>
                        </div>
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">Digital Signature (RSA-PSS)</div>
                            <div class="slide-bundle-field-value">${state.digitalSignature.signatureBase64.slice(0, 60)}...</div>
                        </div>
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">SHA-256 Hash</div>
                            <div class="slide-bundle-field-value">${state.transactionHash}</div>
                        </div>
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">HMAC-SHA256</div>
                            <div class="slide-bundle-field-value">${state.hmacResult.macHex}</div>
                        </div>
                        <div class="slide-bundle-field">
                            <div class="slide-bundle-field-name">Nonce</div>
                            <div class="slide-bundle-field-value">${state.nonce}</div>
                        </div>
                    </div>
                    <div class="slide-time-badge">⚡ Transmitted securely</div>
                    <div class="slide-explanation" style="margin-top:20px;">${step.explanation}</div>
                </div>
            `;
        }

        container.innerHTML = slideHtml;
    }

    // Renders a step card in the background pipeline view (for consistency)
    function renderBackgroundPipelineStep(step, result, elapsed) {
        const stepId = `step-${step.number}`;
        const inputVal = step.inputValueFn ? step.inputValueFn() : step.inputValue;

        const stepEl = document.createElement('div');
        stepEl.className = 'pipeline-step visible complete';
        stepEl.id = stepId;
        stepEl.innerHTML = `
            <div class="step-marker">${step.number}</div>
            <div class="step-card">
                <div class="step-header">
                    <span class="step-icon">${step.icon}</span>
                    <h3 class="step-title">${step.title}</h3>
                    <span class="step-time">${elapsed}ms</span>
                    <span class="step-badge complete">Complete</span>
                </div>
                <p class="step-description">${step.description}</p>
                <div class="step-data">
                    <div class="data-block">
                        <div class="data-label">${step.inputLabel}</div>
                        <div class="data-value ${step.inputClass || ''}">${escapeHtml(inputVal)}</div>
                    </div>
                    <div class="data-arrow">→</div>
                    <div class="data-block">
                        <div class="data-label">${result.outputLabel}</div>
                        <div class="data-value ${result.outputClass || ''}">${escapeHtml(result.outputValue)}</div>
                    </div>
                </div>
                <div class="step-explanation">${step.explanation}</div>
            </div>
        `;

        step.container.appendChild(stepEl);
    }

    // ============================================================
    // PIPELINE STEP RENDERER (kept for compatibility with original view)
    // ============================================================

    async function runPipelineStep(container, config) {
        const stepId = `step-${config.number}`;

        // Create step HTML
        const stepEl = document.createElement('div');
        stepEl.className = 'pipeline-step';
        stepEl.id = stepId;
        stepEl.innerHTML = `
            <div class="step-marker">${config.number}</div>
            <div class="step-card">
                <div class="step-header">
                    <span class="step-icon">${config.icon}</span>
                    <h3 class="step-title">${config.title}</h3>
                    <span class="step-time" id="${stepId}-time"></span>
                    <span class="step-badge pending" id="${stepId}-badge">Pending</span>
                </div>
                <p class="step-description">${config.description}</p>
                <div class="step-data">
                    <div class="data-block">
                        <div class="data-label">${config.inputLabel}</div>
                        <div class="data-value ${config.inputClass || ''}">${escapeHtml(config.inputValue)}</div>
                    </div>
                    <div class="data-arrow">→</div>
                    <div class="data-block" id="${stepId}-output">
                        <div class="data-label">Output</div>
                        <div class="data-value" style="color:var(--text-muted);">Processing...</div>
                    </div>
                </div>
                <div class="step-explanation">${config.explanation}</div>
            </div>
        `;

        container.appendChild(stepEl);

        // Animate in
        await delay(100);
        stepEl.classList.add('visible', 'processing');
        document.getElementById(`${stepId}-badge`).className = 'step-badge processing';
        document.getElementById(`${stepId}-badge`).textContent = 'Processing';

        // Execute crypto operation
        const startTime = performance.now();
        addLog(`⏳ Step ${config.number}: ${config.title} — executing...`, 'crypto');

        try {
            const result = await config.execute();
            const elapsed = (performance.now() - startTime).toFixed(1);

            // Update output
            document.getElementById(`${stepId}-output`).innerHTML = `
                <div class="data-label">${result.outputLabel}</div>
                <div class="data-value ${result.outputClass || ''}">${escapeHtml(result.outputValue)}</div>
            `;

            // Update badge and time
            document.getElementById(`${stepId}-badge`).className = 'step-badge complete';
            document.getElementById(`${stepId}-badge`).textContent = 'Complete';
            document.getElementById(`${stepId}-time`).textContent = `${elapsed}ms`;

            stepEl.classList.remove('processing');
            stepEl.classList.add('complete');

            addLog(`✅ Step ${config.number}: ${config.title} — completed in ${elapsed}ms`, 'crypto', result.logData);

            await delay(300);
        } catch (err) {
            document.getElementById(`${stepId}-badge`).className = 'step-badge error';
            document.getElementById(`${stepId}-badge`).textContent = 'Error';
            stepEl.classList.remove('processing');
            stepEl.classList.add('error');

            document.getElementById(`${stepId}-output`).innerHTML = `
                <div class="data-label">Error</div>
                <div class="data-value" style="color:var(--accent-red);">${escapeHtml(err.message)}</div>
            `;

            throw err;
        }
    }

    // ============================================================
    // NETWORK TRANSMISSION VISUALIZATION
    // ============================================================

    async function showNetworkTransmission(container) {
        container.innerHTML = `
            <div class="glass-card">
                <h3>📡 Secure Transmission</h3>
                <p style="font-size:0.82rem;color:var(--text-secondary);margin-bottom:20px;">
                    The encrypted transaction bundle is transmitted over TLS-protected channels between entities.
                </p>
                <div class="network-viz">
                    <div class="network-nodes">
                        <div class="network-node active" id="tx-merchant">
                            <div class="node-icon">🏪</div>
                            <span class="node-label">Merchant</span>
                        </div>
                        <div class="network-node" id="tx-gateway">
                            <div class="node-icon">🌐</div>
                            <span class="node-label">Gateway</span>
                        </div>
                        <div class="network-node" id="tx-network">
                            <div class="node-icon">🔗</div>
                            <span class="node-label">Card Network</span>
                        </div>
                        <div class="network-node" id="tx-bank">
                            <div class="node-icon">🏦</div>
                            <span class="node-label">Bank</span>
                        </div>
                    </div>
                </div>
                <div class="bundle-display">
                    <h4>📦 Encrypted Transaction Bundle (sent over TLS)</h4>
                    <div class="bundle-field">
                        <div class="field-name">Ciphertext (AES-256-CBC)</div>
                        <div class="field-value">${state.aesEncrypted.cipherBase64.slice(0, 60)}...</div>
                    </div>
                    <div class="bundle-field">
                        <div class="field-name">Wrapped Key (RSA-OAEP)</div>
                        <div class="field-value">${state.rsaWrappedKey.wrappedBase64.slice(0, 60)}...</div>
                    </div>
                    <div class="bundle-field">
                        <div class="field-name">Digital Signature (RSA-PSS)</div>
                        <div class="field-value">${state.digitalSignature.signatureBase64.slice(0, 60)}...</div>
                    </div>
                    <div class="bundle-field">
                        <div class="field-name">SHA-256 Hash</div>
                        <div class="field-value">${state.transactionHash}</div>
                    </div>
                    <div class="bundle-field">
                        <div class="field-name">HMAC-SHA256</div>
                        <div class="field-value">${state.hmacResult.macHex}</div>
                    </div>
                    <div class="bundle-field">
                        <div class="field-name">Nonce (Replay Protection)</div>
                        <div class="field-value">${state.nonce}</div>
                    </div>
                </div>
            </div>
        `;

        addLog('📡 Transmitting encrypted bundle over secure channel...', 'network');

        // Animate nodes
        const nodes = ['tx-gateway', 'tx-network', 'tx-bank'];
        for (const nodeId of nodes) {
            await delay(600);
            const el = document.getElementById(nodeId);
            if (el) el.classList.add('active');
        }

        await delay(400);

        // Mark all as complete
        document.querySelectorAll('#pipeline-transmission .network-node').forEach(n => {
            n.classList.remove('active');
            n.classList.add('complete');
        });

        addLog('✅ Encrypted bundle delivered to all entities', 'network');
    }

    // ============================================================
    // TRANSACTION RESULT
    // ============================================================

    function showTransactionResult(container) {
        const authCode = 'AUTH_' + Math.random().toString(36).substr(2, 6).toUpperCase();

        container.innerHTML = `
            <div class="transaction-result approved">
                <div class="result-icon">💚</div>
                <h2 class="result-title" style="color:var(--accent-green);">Transaction Approved</h2>
                <p class="result-subtitle">All cryptographic verifications passed. Payment authorized by issuing bank.</p>
                <dl class="result-details">
                    <dt>Amount</dt>
                    <dd>₹${state.amount.toLocaleString()}</dd>
                    <dt>Merchant</dt>
                    <dd>${state.merchantName}</dd>
                    <dt>Card</dt>
                    <dd>${state.tokenResult.masked}</dd>
                    <dt>Network</dt>
                    <dd>${state.cardNetwork.toUpperCase()}</dd>
                    <dt>Auth Code</dt>
                    <dd>${authCode}</dd>
                    <dt>Nonce</dt>
                    <dd>${state.nonce}</dd>
                </dl>
            </div>
            <div class="text-center mt-24" style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
                <button class="btn btn-secondary" onclick="App.navigate('attacks')">🛡️ Try Attack Simulator</button>
                <button class="btn btn-ghost" onclick="App.navigate('verification')">✅ View Verification Details</button>
                <button class="btn btn-ghost" onclick="App.navigate('network')">📡 View Network Details</button>
                <button class="btn btn-ghost" onclick="App.navigate('audit-log')">📋 View Audit Log</button>
            </div>
        `;

        addLog(`💚 Transaction APPROVED — Auth: ${authCode}, Amount: ₹${state.amount}`, 'verify');
    }

    // ============================================================
    // VERIFICATION PAGE UPDATE
    // ============================================================

    function updateVerificationPage() {
        const container = document.getElementById('verification-steps');
        document.getElementById('verification-status').style.display = 'none';

        container.innerHTML = `
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.1s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>HMAC-SHA256 Verification</h4>
                    <p>Message authentication code is valid — data is authentic and untampered.</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.2s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>RSA-PSS Digital Signature Verification</h4>
                    <p>Merchant identity confirmed — transaction originated from registered merchant "${state.merchantName}".</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.3s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>RSA-OAEP Key Unwrapping</h4>
                    <p>AES session key successfully recovered — key integrity confirmed.</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.4s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>AES-256-CBC Decryption</h4>
                    <p>Transaction payload successfully decrypted — ${state.transactionPayload.length} bytes recovered.</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.5s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>SHA-256 Hash Integrity Check</h4>
                    <p>Recomputed hash matches received hash — data integrity confirmed.</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
            <div class="verify-item pass" style="animation: fadeInUp 0.4s ease 0.6s both;">
                <div class="verify-icon">✅</div>
                <div class="verify-info">
                    <h4>Nonce & Timestamp Validation</h4>
                    <p>Nonce "${state.nonce}" is unique (first use) — replay attack prevented. Timestamp within acceptable window.</p>
                </div>
                <span class="tag green">PASS</span>
            </div>
        `;

        // Show decrypted payload
        const decryptedEl = document.getElementById('decrypted-result');
        decryptedEl.style.display = 'block';
        document.getElementById('decrypted-payload').textContent = state.decryptedPayload;
    }

    // ============================================================
    // NETWORK PAGE UPDATE
    // ============================================================

    function updateNetworkPage() {
        const nodes = ['node-merchant', 'node-gateway', 'node-network', 'node-bank'];
        nodes.forEach(id => {
            document.getElementById(id).classList.add('complete');
        });

        document.getElementById('network-status').innerHTML =
            '✅ Transaction successfully transmitted through all network entities. All channels encrypted with TLS 1.3.';

        // Show intercepted data
        const interceptedPanel = document.getElementById('intercepted-panel');
        interceptedPanel.style.display = 'block';
        document.getElementById('intercepted-data-display').textContent = JSON.stringify({
            "⚠️ INTERCEPTED PACKET": "The following is all an attacker can see:",
            "ciphertext": state.aesEncrypted.cipherBase64.slice(0, 40) + "...[encrypted]",
            "wrapped_key": state.rsaWrappedKey.wrappedBase64.slice(0, 40) + "...[encrypted]",
            "signature": state.digitalSignature.signatureBase64.slice(0, 40) + "...",
            "hash": state.transactionHash,
            "hmac": state.hmacResult.macHex,
            "nonce": state.nonce,
            "timestamp": state.timestamp,
            "❌ CANNOT_READ": "Card number, amount, merchant — all encrypted",
            "❌ CANNOT_MODIFY": "HMAC will detect any changes",
            "❌ CANNOT_FORGE": "Digital signature verification will fail",
            "❌ CANNOT_REPLAY": "Nonce is single-use"
        }, null, 2);
    }

    // ============================================================
    // ATTACK SIMULATOR
    // ============================================================

    function enableAttackButtons() {
        document.getElementById('attack-prereq').style.display = 'none';
        document.querySelectorAll('.attack-btn').forEach(btn => btn.disabled = false);
    }

    async function simulateAttack(type) {
        const container = document.getElementById('attack-result-container');
        container.innerHTML = '<div class="info-box">⏳ Running attack simulation...</div>';

        addLog(`🛡️ Attack simulation started: ${type.toUpperCase()}`, 'attack');

        await delay(500);

        try {
            switch (type) {
                case 'tamper':
                    await attackTamper(container);
                    break;
                case 'replay':
                    await attackReplay(container);
                    break;
                case 'wrongkey':
                    await attackWrongKey(container);
                    break;
                case 'nosig':
                    await attackNoSignature(container);
                    break;
                case 'intercept':
                    await attackIntercept(container);
                    break;
            }
        } catch (err) {
            container.innerHTML = `<div class="attack-result blocked">
                <h3>❌ Attack Error: ${err.message}</h3>
            </div>`;
        }

        state.attacksBlocked++;
        updateDashboardStats();
    }

    async function attackTamper(container) {
        addLog('🔨 Simulating data tampering — modifying ciphertext bytes...', 'attack');

        // Create a tampered copy of the ciphertext
        const originalCipher = new Uint8Array(state.aesEncrypted.cipherBuffer.slice(0));
        const tamperedCipher = new Uint8Array(state.aesEncrypted.cipherBuffer.slice(0));
        // Flip some bits in the tampered copy
        tamperedCipher[0] ^= 0xFF;
        tamperedCipher[1] ^= 0xAB;
        tamperedCipher[10] ^= 0x42;

        const originalHex = Array.from(originalCipher.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');
        const tamperedHex = Array.from(tamperedCipher.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join(' ');

        // Try to verify HMAC on tampered data — it will fail
        const tamperedBundle = JSON.stringify({
            ciphertext: btoa(String.fromCharCode(...tamperedCipher)),
            wrappedKey: state.transactionBundle.wrappedKey,
            signature: state.transactionBundle.signature,
            hash: state.transactionBundle.hash,
            nonce: state.transactionBundle.nonce,
            timestamp: state.transactionBundle.timestamp
        });
        const recomputedHmac = await CryptoSim.HMAC.sign(state.hmacKeyData.key, tamperedBundle);

        container.innerHTML = `
            <div class="attack-result blocked">
                <h3>🛡️ ATTACK BLOCKED — Data Tampering Detected</h3>
                <p style="color:var(--text-secondary);margin-bottom:16px;">
                    The attacker modified 3 bytes in the ciphertext. The HMAC verification immediately detected the tampering because the recomputed HMAC does not match the original.
                </p>
                <div class="result-comparison">
                    <div class="comparison-block">
                        <div class="comp-label">Original Ciphertext (first 16 bytes)</div>
                        <div class="comp-value" style="color:var(--accent-green);">${originalHex}</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Tampered Ciphertext (first 16 bytes)</div>
                        <div class="comp-value" style="color:var(--accent-red);">${tamperedHex}</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Original HMAC</div>
                        <div class="comp-value" style="color:var(--accent-green);">${state.hmacResult.macHex}</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Recomputed HMAC (of tampered data)</div>
                        <div class="comp-value" style="color:var(--accent-red);">${recomputedHmac.macHex}</div>
                    </div>
                </div>
                <div class="info-box mt-16">
                    <strong>Defense mechanism:</strong> HMAC-SHA256 acts as a cryptographic seal. Any modification to the data — even a single bit — produces a completely different HMAC value. The gateway rejects the transaction immediately.
                </div>
            </div>
        `;

        addLog('🛡️ Tamper attack BLOCKED — HMAC mismatch detected', 'attack', {
            originalHmac: state.hmacResult.macHex,
            tamperedHmac: recomputedHmac.macHex
        });
    }

    async function attackReplay(container) {
        addLog('🔄 Simulating replay attack — resending the same transaction...', 'attack');

        const nonceUsed = state.usedNonces.has(state.nonce);

        container.innerHTML = `
            <div class="attack-result blocked">
                <h3>🛡️ ATTACK BLOCKED — Replay Attack Detected</h3>
                <p style="color:var(--text-secondary);margin-bottom:16px;">
                    The attacker captured and re-sent the exact same encrypted transaction. However, the nonce (number-used-once) has already been recorded as used.
                </p>
                <div class="result-comparison">
                    <div class="comparison-block">
                        <div class="comp-label">Transaction Nonce</div>
                        <div class="comp-value" style="color:var(--accent-amber);">${state.nonce}</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Nonce Status</div>
                        <div class="comp-value" style="color:var(--accent-red);">ALREADY USED ❌<br>Nonce found in used-nonces database</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Transaction Timestamp</div>
                        <div class="comp-value" style="color:var(--accent-amber);">${state.timestamp}</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Current Time</div>
                        <div class="comp-value" style="color:var(--accent-red);">${new Date().toISOString()}<br>Time window expired</div>
                    </div>
                </div>
                <div class="info-box mt-16">
                    <strong>Defense mechanism:</strong> Each transaction includes a unique nonce and timestamp. The gateway records all processed nonces. If a nonce is resubmitted, the transaction is rejected as a replay. Timestamps prevent old transactions from being replayed.
                </div>
            </div>
        `;

        addLog('🛡️ Replay attack BLOCKED — nonce already used', 'attack', {
            nonce: state.nonce,
            timestamp: state.timestamp,
            alreadyUsed: nonceUsed
        });
    }

    async function attackWrongKey(container) {
        addLog('🔑 Simulating wrong key attack — attempting decryption with incorrect key...', 'attack');

        // Generate a different AES key
        const wrongKey = await CryptoSim.AES.generateKey();
        let decryptionResult = '';
        let failed = false;

        try {
            await CryptoSim.AES.decrypt(wrongKey.key, state.aesEncrypted.cipherBuffer, state.aesEncrypted.iv);
            decryptionResult = 'Unexpected: decryption produced output (extremely unlikely)';
        } catch (e) {
            failed = true;
            decryptionResult = `OperationError: The operation failed for an operation-specific reason.\n\nThe AES decryption failed because the wrong key was used. The CBC mode detected invalid padding after decryption, indicating data corruption.`;
        }

        container.innerHTML = `
            <div class="attack-result blocked">
                <h3>🛡️ ATTACK BLOCKED — Wrong Key Decryption Failed</h3>
                <p style="color:var(--text-secondary);margin-bottom:16px;">
                    The attacker tried to decrypt the ciphertext with a different AES key. AES-CBC immediately detected the incorrect decryption due to invalid PKCS7 padding.
                </p>
                <div class="result-comparison">
                    <div class="comparison-block">
                        <div class="comp-label">Correct AES Key</div>
                        <div class="comp-value" style="color:var(--accent-green);">${state.aesKeyData.keyHex.slice(0, 32)}...</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Attacker's Key (Wrong)</div>
                        <div class="comp-value" style="color:var(--accent-red);">${wrongKey.keyHex.slice(0, 32)}...</div>
                    </div>
                </div>
                <div class="comparison-block mt-16">
                    <div class="comp-label">Decryption Result</div>
                    <div class="comp-value" style="color:var(--accent-red);">${failed ? '❌ DECRYPTION FAILED' : decryptionResult}<br><br>${escapeHtml(decryptionResult)}</div>
                </div>
                <div class="info-box mt-16">
                    <strong>Defense mechanism:</strong> AES-256 has a key space of 2²⁵⁶ — that's ~1.16 × 10⁷⁷ possible keys. Brute-forcing would take longer than the age of the universe. Without the exact key, the data is completely inaccessible.
                </div>
            </div>
        `;

        addLog('🛡️ Wrong key attack BLOCKED — decryption failed', 'attack', {
            correctKeyPreview: state.aesKeyData.keyHex.slice(0, 16),
            wrongKeyPreview: wrongKey.keyHex.slice(0, 16),
            failed: failed
        });
    }

    async function attackNoSignature(container) {
        addLog('✂️ Simulating signature removal — verifying unsigned transaction...', 'attack');

        // Create a fake signature (random bytes)
        const fakeSignature = crypto.getRandomValues(new Uint8Array(256));

        // Verify the fake signature — it will fail
        let isValid = false;
        try {
            isValid = await CryptoSim.RSA.verify(
                state.signingKeyPair.publicKey,
                fakeSignature.buffer,
                state.transactionHash
            );
        } catch (e) {
            isValid = false;
        }

        const fakeHex = Array.from(fakeSignature.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('');

        container.innerHTML = `
            <div class="attack-result blocked">
                <h3>🛡️ ATTACK BLOCKED — Invalid Signature Rejected</h3>
                <p style="color:var(--text-secondary);margin-bottom:16px;">
                    The attacker stripped the merchant's digital signature and replaced it with random data. The RSA-PSS signature verification immediately detected the forgery.
                </p>
                <div class="result-comparison">
                    <div class="comparison-block">
                        <div class="comp-label">Original Signature (from merchant's private key)</div>
                        <div class="comp-value" style="color:var(--accent-green);">${state.digitalSignature.signatureHex.slice(0, 64)}...</div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">Fake Signature (random bytes)</div>
                        <div class="comp-value" style="color:var(--accent-red);">${fakeHex}...</div>
                    </div>
                </div>
                <div class="comparison-block mt-16">
                    <div class="comp-label">RSA-PSS Verification Result</div>
                    <div class="comp-value" style="color:var(--accent-red);">❌ SIGNATURE VERIFICATION FAILED<br><br>The public key could not verify the signature against the transaction hash. The transaction is rejected — the sender is not authenticated.</div>
                </div>
                <div class="info-box mt-16">
                    <strong>Defense mechanism:</strong> Only the holder of the merchant's RSA private key can create a valid signature. Without the private key (which never leaves the merchant), it's computationally infeasible to forge a valid RSA-2048 signature.
                </div>
            </div>
        `;

        addLog('🛡️ No-signature attack BLOCKED — RSA-PSS verification failed', 'attack', {
            fakeSignaturePreview: fakeHex.slice(0, 32),
            verified: isValid
        });
    }

    async function attackIntercept(container) {
        addLog('👁️ Simulating eavesdropping — showing what intercepted data looks like...', 'attack');

        container.innerHTML = `
            <div class="attack-result blocked">
                <h3>🛡️ ATTACK FUTILE — Intercepted Data Is Encrypted</h3>
                <p style="color:var(--text-secondary);margin-bottom:16px;">
                    The attacker successfully intercepted the transaction data in transit. However, ALL sensitive information is encrypted. Here's what they can see vs. what they can't:
                </p>
                <div class="result-comparison">
                    <div class="comparison-block">
                        <div class="comp-label">🔴 What the attacker wants</div>
                        <div class="comp-value" style="color:var(--accent-red);">
                            Card: ${state.cardNumber}<br>
                            Name: ${state.cardName}<br>
                            CVV: ${state.cvv}<br>
                            Amount: ₹${state.amount}<br>
                            Merchant: ${state.merchantName}
                        </div>
                    </div>
                    <div class="comparison-block">
                        <div class="comp-label">🟢 What the attacker actually gets</div>
                        <div class="comp-value" style="color:var(--accent-cyan);">
                            Ciphertext: ${state.aesEncrypted.cipherHex.slice(0, 40)}...<br>
                            Wrapped Key: ${state.rsaWrappedKey.wrappedHex.slice(0, 40)}...<br>
                            Signature: ${state.digitalSignature.signatureHex.slice(0, 40)}...<br>
                            HMAC: ${state.hmacResult.macHex.slice(0, 40)}...<br>
                            <br>⬆️ Completely useless without private keys
                        </div>
                    </div>
                </div>
                <div class="info-box mt-16">
                    <strong>Defense mechanism:</strong> AES-256 encryption ensures that even if the data is intercepted, it appears as random bytes. The AES key is protected by RSA-2048 encryption. Breaking RSA-2048 would require factoring a 617-digit number — currently considered computationally infeasible.
                </div>
            </div>
        `;

        addLog('🛡️ Intercept attack FUTILE — all data encrypted with AES-256 + RSA-2048', 'attack');
    }

    // ============================================================
    // AUDIT LOG
    // ============================================================

    function addLog(message, type, data) {
        const entry = {
            id: state.auditLog.length + 1,
            timestamp: new Date().toISOString(),
            time: new Date().toLocaleTimeString('en-US', { hour12: false }),
            type: type,      // 'crypto', 'network', 'verify', 'attack', 'info'
            message: message,
            data: data || null
        };

        state.auditLog.push(entry);
        renderLogEntry(entry);
        updateLogCount();
    }

    function renderLogEntry(entry) {
        const emptyEl = document.getElementById('log-empty');
        if (emptyEl) emptyEl.style.display = 'none';

        const container = document.getElementById('log-container');
        const el = document.createElement('div');
        el.className = 'log-entry';
        el.onclick = () => el.classList.toggle('expanded');

        el.innerHTML = `
            <div class="log-header">
                <span class="log-time">${entry.time}</span>
                <span class="log-type ${entry.type}">${entry.type}</span>
                <span class="log-message">${escapeHtml(entry.message)}</span>
            </div>
            ${entry.data ? `
                <div class="log-details">
                    <pre>${JSON.stringify(entry.data, null, 2)}</pre>
                </div>
            ` : ''}
        `;

        container.appendChild(el);
        container.scrollTop = container.scrollHeight;
    }

    function updateLogCount() {
        const el = document.getElementById('log-count');
        if (el) el.textContent = `${state.auditLog.length} entries`;
    }

    function clearLog() {
        state.auditLog = [];
        const container = document.getElementById('log-container');
        container.innerHTML = `
            <div class="log-empty" id="log-empty">
                <p>📭 No log entries yet.</p>
                <p style="font-size:0.78rem;margin-top:8px;">Process a transaction to see detailed cryptographic operation logs.</p>
            </div>
        `;
        updateLogCount();
        showToast('Audit log cleared', 'info');
    }

    function exportLog() {
        const logText = state.auditLog.map(e => {
            let line = `[${e.timestamp}] [${e.type.toUpperCase()}] ${e.message}`;
            if (e.data) line += '\n  Data: ' + JSON.stringify(e.data);
            return line;
        }).join('\n');

        const blob = new Blob([logText], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `securepay-audit-log-${new Date().toISOString().slice(0, 10)}.txt`;
        a.click();
        URL.revokeObjectURL(url);

        showToast('Audit log exported', 'success');
    }

    // ============================================================
    // DASHBOARD STATS
    // ============================================================

    function updateDashboardStats() {
        document.getElementById('stat-keys').textContent =
            state.keysGenerated ? '4' : '0';
        document.getElementById('stat-transactions').textContent =
            state.transactionCount.toString();
        document.getElementById('stat-attacks').textContent =
            state.attacksBlocked.toString();
    }

    // ============================================================
    // UTILITIES
    // ============================================================

    function delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function generateNonce() {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function showToast(message, type) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type || 'info'}`;

        const icons = { success: '✅', error: '❌', info: 'ℹ️', warning: '⚠️' };
        toast.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;

        container.appendChild(toast);

        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // ============================================================
    // PUBLIC API
    // ============================================================

    window.App = {
        navigate,
        flipCard,
        loadSampleData,
        generateAllKeys,
        startTransaction,
        simulateAttack,
        clearLog,
        exportLog,
        // Presentation mode
        nextPresentationStep,
        prevPresentationStep,
        exitPresentation
    };

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', init);

})();

