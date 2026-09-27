# Cipher Desk Web-Based Text Encryption Tool

A single-page web app for encrypting and decrypting text with a choice of
five algorithms, built with a Python (Flask) backend and a vanilla
HTML/CSS/JS frontend.

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in a browser.

## Project structure

```
encryption_tool/
├── app.py                 # Flask routes: /, /api/encrypt, /api/decrypt, /api/hash
├── crypto_utils.py        # All encryption / decryption / hashing logic
├── requirements.txt
├── templates/
│   └── index.html         # UI: text box, algorithm dropdown, buttons, output
└── static/
    ├── css/style.css
    └── js/script.js       # Calls the API and renders results/errors
```

## How it works

1. The user types plaintext into the text box and picks an algorithm from
   the dropdown.
2. If the algorithm needs a key or passphrase (Caesar, AES, DES), a second
   input appears.
3. Clicking **Encrypt** sends `{ algorithm, text, key }` as JSON to
   `POST /api/encrypt`. The Flask route validates the input, calls the
   matching function in `crypto_utils.py`, and returns `{ result }`.
4. The ciphertext is shown in the read-only output box, with a **Copy**
   button. **Decrypt** works the same way in reverse, and **Hash** calls
   `/api/hash` for a one-way SHA-256 digest.

Validation happens on both ends: the frontend blocks empty text/no
algorithm before it calls the API, and the backend independently checks
the same rules (and returns a clear error) since a UI check alone is never
trustworthy.

## Encryption techniques used (report)

Ten selectable algorithms are implemented, spanning four classical ciphers,
a simple stream cipher, a plain encoding, two modern symmetric ciphers, and
one asymmetric cipher — plus a one-way hash as a bonus feature.

| Algorithm | Type | Notes |
|---|---|---|
| **Caesar Cipher** | Classical substitution | Each letter is shifted by a fixed number of places in the alphabet (key = shift amount, 0–25). Trivial to break by brute force (only 26 possible shifts) or frequency analysis — the simplest "how ciphers work" example. |
| **Vigenère Cipher** | Classical polyalphabetic substitution | A repeating keyword sets a *different* shift for each letter instead of one fixed shift, which defeats simple frequency analysis. Historically called "le chiffre indéchiffrable" — still breakable today with key-length analysis (e.g. Kasiski examination), but a clear step up from Caesar. |
| **Atbash Cipher** | Classical substitution (no key) | A fixed mirror-alphabet swap (A↔Z, B↔Y, …). It needs no key and is its own inverse — encrypting twice returns the original text — which makes it a good example of why a fixed, keyless substitution offers no real security. |
| **Rail Fence Cipher** | Classical transposition | Instead of substituting letters, it *reorders* them: the text is written in a zigzag across a chosen number of rows ("rails") and read off row by row. Demonstrates that scrambling order, not just replacing letters, is another whole category of classical cipher. |
| **XOR Cipher** | Simple stream cipher | Each byte of the message is XORed with a repeating key. It's the simplest real "stream cipher" pattern (the same idea, done properly with a random keystream, underlies AES-CTR and ChaCha20) — but a short, reused key makes it easy to break, so it's for demonstration only. |
| **Base64** | Encoding, not encryption | Represents bytes as printable ASCII. It is fully reversible with no key, so it hides text from a casual glance but provides zero confidentiality. Included because the spec listed it alongside the ciphers. |
| **AES-256 (CBC mode)** | Symmetric block cipher | The industry-standard cipher for this kind of tool. The user's passphrase is stretched into a 256-bit key with **PBKDF2** (200,000 iterations) and a random 16-byte salt, then a random 16-byte IV is used for CBC mode so identical plaintexts never produce identical ciphertexts. Salt + IV + ciphertext are packaged together (base64-encoded) so decryption only needs the original passphrase. |
| **Triple DES (3DES)** | Symmetric block cipher (legacy) | Included so the report can compare a modern cipher against an older one. Single DES has a 56-bit effective key and is trivially brute-forced today, so modern crypto libraries (including the one this project uses) have dropped it entirely; 3DES — three DES passes with a longer key — is the standard drop-in used to demonstrate the same block-cipher family safely. Even so, it's kept here for comparison, not for anything that needs to stay secret; prefer AES. |
| **ChaCha20** | Symmetric stream cipher (modern) | A fast, modern stream cipher used in TLS 1.3 and WireGuard, included alongside AES/3DES as a second family of symmetric cipher (stream vs. block). Keyed the same way as AES here — PBKDF2 over the passphrase — with a random 16-byte nonce bundled into the payload. |
| **RSA (bonus)** | Asymmetric cipher | Generates a fresh 2048-bit key pair per message (no key management UI, so nothing is persisted server-side) and encrypts with **OAEP** padding via the public key. Because RSA can only encrypt data smaller than the key size, message length is capped — in practice RSA is normally used to encrypt a symmetric key rather than a whole message, which is noted in the UI. |
| **SHA-256 (bonus)** | Cryptographic hash | One-way — there is no "decrypt" for a hash. Used here to demonstrate the difference between *encryption* (reversible, needs a key) and *hashing* (irreversible, used for integrity checks and password storage). |

### Design decisions worth noting in a demo/report

- **Where keys are derived, not typed directly (AES/DES):** using PBKDF2
  with a per-message random salt means the same passphrase produces a
  different derived key (and different ciphertext) every time, which
  defeats rainbow-table attacks.
- **CBC mode + random IV:** without a random IV, encrypting the same
  plaintext twice with the same key would produce identical ciphertext,
  leaking a pattern to an observer.
- **RSA's private key is only ever shown once, client-side:** the backend
  never stores it, matching the "no auth/no persistence" scope of the
  base project.
- **Server-side validation mirrors the frontend:** even though the UI
  disables empty submissions, `app.py` re-validates independently, since
  the API could be called directly.

## What's implemented vs. optional (bonus) features

- ✅ Encrypt **and** decrypt (not just encrypt) for all ten algorithms
  (SHA-256 is intentionally hash-only).
- ✅ Hashing option (SHA-256).
- ✅ One-click **Copy** for the result.
- ⬜ User authentication / saved message history — out of scope for this
  build (no database wired up); the architecture (a JSON API) would
  support adding it behind a login route without changing the crypto
  logic.

## Demo video / GitHub

This README doubles as the short report requested in the submission
requirements. For the demo video, a natural walkthrough is: encrypt a
message with AES → show the ciphertext → decrypt it back → try Caesar
and Base64 for comparison → generate an RSA pair and decrypt with the
private key → hash a message with SHA-256 and note that there's no
decrypt button for it.
