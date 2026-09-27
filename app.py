"""
app.py
------
Flask backend for the Web-Based Text Encryption Tool.

Routes
    GET  /                -> serves the single-page frontend
    POST /api/encrypt      -> { algorithm, text, key } -> { result, ... }
    POST /api/decrypt      -> { algorithm, text, key } -> { result }
    POST /api/hash          -> { text } -> { result }

Run locally:
    pip install -r requirements.txt
    python app.py
    -> open http://127.0.0.1:5000
"""

from flask import Flask, jsonify, render_template, request

import crypto_utils as cu

app = Flask(__name__)

# Every encrypt function takes (text, key) -- algorithms that don't need a
# key (Atbash, Base64) simply ignore the second argument. RSA is handled
# separately below since it returns a key pair rather than a plain string.
ENCRYPT_FUNCS = {
    "caesar": cu.caesar_encrypt,
    "vigenere": cu.vigenere_encrypt,
    "atbash": cu.atbash_encrypt,
    "railfence": cu.rail_fence_encrypt,
    "xor": cu.xor_encrypt,
    "base64": cu.base64_encrypt,
    "aes": cu.aes_encrypt,
    "des": cu.des_encrypt,
    "chacha20": cu.chacha20_encrypt,
}

DECRYPT_FUNCS = {
    "caesar": cu.caesar_decrypt,
    "vigenere": cu.vigenere_decrypt,
    "atbash": cu.atbash_decrypt,
    "railfence": cu.rail_fence_decrypt,
    "xor": cu.xor_decrypt,
    "base64": cu.base64_decrypt,
    "aes": cu.aes_decrypt,
    "des": cu.des_decrypt,
    "chacha20": cu.chacha20_decrypt,
}

ALGORITHMS = set(ENCRYPT_FUNCS) | {"rsa"}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True) or {}
    algorithm = str(data.get("algorithm", "")).strip().lower()
    text = data.get("text", "")
    key = data.get("key", "")

    error = _validate(algorithm, text)
    if error:
        return jsonify({"error": error}), 400

    try:
        if algorithm == "rsa":
            rsa_out = cu.rsa_encrypt(text)
            return jsonify(
                {
                    "result": rsa_out["ciphertext"],
                    "public_key": rsa_out["public_key"],
                    "private_key": rsa_out["private_key"],
                    "note": "Save the private key now -- it is not stored on the server "
                    "and is required to decrypt this message.",
                }
            )
        result = ENCRYPT_FUNCS[algorithm](text, key)
        return jsonify({"result": result})
    except cu.CryptoError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(silent=True) or {}
    algorithm = str(data.get("algorithm", "")).strip().lower()
    text = data.get("text", "")
    key = data.get("key", "")

    error = _validate(algorithm, text)
    if error:
        return jsonify({"error": error}), 400

    try:
        if algorithm == "rsa":
            # For RSA, the frontend sends the PEM private key in "key"
            return jsonify({"result": cu.rsa_decrypt(text, key)})
        result = DECRYPT_FUNCS[algorithm](text, key)
        return jsonify({"result": result})
    except cu.CryptoError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/hash", methods=["POST"])
def api_hash():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    if not text or not str(text).strip():
        return jsonify({"error": "Enter some text to hash."}), 400
    return jsonify({"result": cu.sha256_hash(text)})


def _validate(algorithm, text):
    """Basic validation: non-empty input + a recognised algorithm selected."""
    if not algorithm or algorithm not in ALGORITHMS:
        return "Please select an encryption method."
    if text is None or str(text).strip() == "":
        return "Please enter some text first."
    return None


if __name__ == "__main__":
    app.run(debug=True, port=5001)
