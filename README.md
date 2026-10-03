# 🔐 SecurePay — Card Transaction Cryptography Simulator

An interactive, browser-based simulation that demonstrates how real-world payment card transactions are secured using modern cryptographic techniques.

**Built for:** Information & Network Security (INS) — Academic Project  
**Tech Stack:** HTML5 + CSS3 + Vanilla JavaScript + Web Crypto API  
**Dependencies:** None — zero external libraries required

---

## 🚀 Quick Start

1. **Open** `index.html` in any modern browser (Chrome, Firefox, Edge, Safari)
2. That's it — no installation, no server, no build step needed.

> All cryptographic operations run locally in your browser using the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). No data ever leaves your machine.

---

## 📋 How to Use

### Step 1: Dashboard
See an overview of the system and the cryptographic algorithms used.

### Step 2: Card Input
Enter card details (or click **Load Sample Data** for a demo). Watch the Luhn algorithm validate the card number in real time.

### Step 3: Key Generation
Generate all 4 cryptographic key sets:
- **RSA-PSS 2048** — Merchant digital signing keys
- **RSA-OAEP 2048** — Gateway encryption keys
- **AES-256** — Transaction session key
- **HMAC-SHA256** — Message authentication key

### Step 4: Process Transaction
Click **Process Secure Transaction** to watch the 11-step encryption pipeline:
1. Tokenization
2. AES-256-CBC Encryption
3. RSA Key Wrapping
4. SHA-256 Hashing
5. RSA-PSS Digital Signature
6. HMAC-SHA256 Authentication
7. HMAC Verification (gateway)
8. Signature Verification (gateway)
9. RSA Key Unwrapping (gateway)
10. AES Decryption (gateway)
11. Hash Integrity Check (gateway)

### Step 5: Attack Simulator
Try 5 different attacks and see how cryptography blocks each one:
- 🔨 **Data Tampering** — HMAC detects modification
- 🔄 **Replay Attack** — Nonce reuse detected
- 🔑 **Wrong Key** — AES decryption fails
- ✂️ **Signature Removal** — RSA verification fails
- 👁️ **Eavesdropping** — All data is encrypted

### Step 6: Audit Log
Review the complete timestamped log of every cryptographic operation.

---

## 📁 Project Structure

```
├── index.html              → Main page (single-page app)
├── css/
│   └── style.css           → Complete design system
├── js/
│   ├── app.js              → Main application controller
│   └── crypto/
│       ├── luhn.js          → Luhn algorithm (card validation)
│       ├── tokenizer.js     → PAN tokenization
│       ├── hash.js          → SHA-256 hashing
│       ├── aes.js           → AES-256-CBC encryption
│       ├── rsa.js           → RSA-2048 (OAEP + PSS)
│       └── hmac.js          → HMAC-SHA256 authentication
├── guide.md                 → Comprehensive project guide
└── README.md                → This file
```

---

## 🔒 Cryptographic Algorithms Used

| Algorithm | Standard | Purpose |
|-----------|----------|---------|
| AES-256-CBC | FIPS 197 | Symmetric encryption of transaction payload |
| RSA-2048 OAEP | PKCS #1 | Asymmetric encryption for key wrapping |
| RSA-2048 PSS | PKCS #1 | Digital signatures for authentication |
| SHA-256 | FIPS 180-4 | Cryptographic hashing for integrity |
| HMAC-SHA256 | RFC 2104 | Message authentication codes |
| Luhn | ISO 7812-1 | Card number checksum validation |

---

## ⚠️ Disclaimer

This is an **educational simulation** for academic purposes. No real payment transactions are processed. All card numbers used are test numbers. Never enter real card information.

---

*Information & Network Security — Academic Project, October 2026*
