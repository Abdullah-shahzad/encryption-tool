const plaintextEl = document.getElementById("plaintext");
const algorithmEl = document.getElementById("algorithm");
const keyFieldEl = document.getElementById("keyField");
const keyLabelEl = document.getElementById("keyLabel");
const secretKeyEl = document.getElementById("secretKey");
const algoHintEl = document.getElementById("algoHint");
const outputEl = document.getElementById("output");
const errorEl = document.getElementById("errorMsg");
const copyBtn = document.getElementById("copyBtn");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const hashBtn = document.getElementById("hashBtn");

const ALGO_INFO = {
  caesar: {
    key: true,
    label: "Shift",
    placeholder: "e.g. 3",
    hint: "Each letter shifts forward by this many places in the alphabet.",
  },
  vigenere: {
    key: true,
    label: "Keyword",
    placeholder: "e.g. LEMON",
    hint: "A repeating keyword sets a different shift for each letter -- stronger than a single fixed shift.",
  },
  atbash: {
    key: false,
    hint: "A fixed mirror-alphabet swap (A\u2194Z, B\u2194Y, \u2026). No key -- applying it twice returns the original text.",
  },
  railfence: {
    key: true,
    label: "Rails",
    placeholder: "e.g. 3",
    hint: "Writes the text in a zigzag across this many rows, then reads it off row by row.",
  },
  xor: {
    key: true,
    label: "Key",
    placeholder: "A passphrase to XOR the text with",
    hint: "Each character is combined with a repeating key using XOR -- simple, and only as strong as the key.",
  },
  base64: {
    key: false,
    hint: "Reversible text encoding, not real encryption -- anyone can decode it.",
  },
  aes: {
    key: true,
    label: "Passphrase",
    placeholder: "A passphrase to derive the AES-256 key from",
    hint: "AES-256 in CBC mode. The same passphrase is needed to decrypt.",
  },
  des: {
    key: true,
    label: "Passphrase",
    placeholder: "A passphrase to derive the 3DES key from",
    hint: "Triple DES, the modern safe successor to the broken single-DES cipher -- still prefer AES for real use.",
  },
  chacha20: {
    key: true,
    label: "Passphrase",
    placeholder: "A passphrase to derive the ChaCha20 key from",
    hint: "A fast modern stream cipher used in TLS 1.3 and WireGuard.",
  },
};

algorithmEl.addEventListener("change", () => {
  const info = ALGO_INFO[algorithmEl.value];
  clearError();
  if (!info) {
    keyFieldEl.hidden = true;
    algoHintEl.textContent = "";
    return;
  }
  algoHintEl.textContent = info.hint;
  keyFieldEl.hidden = !info.key;
  if (info.key) {
    keyLabelEl.textContent = info.label;
    secretKeyEl.placeholder = info.placeholder;
  }
});

encryptBtn.addEventListener("click", () => runAction("/api/encrypt"));
decryptBtn.addEventListener("click", () => runAction("/api/decrypt"));
hashBtn.addEventListener("click", runHash);

copyBtn.addEventListener("click", async () => {
  await navigator.clipboard.writeText(outputEl.value);
  const original = copyBtn.textContent;
  copyBtn.textContent = "Copied";
  setTimeout(() => (copyBtn.textContent = original), 1200);
});

async function runAction(endpoint) {
  clearError();
  copyBtn.hidden = true;

  const algorithm = algorithmEl.value;
  const text = plaintextEl.value;

  if (!text.trim()) {
    return showError("Please enter some text first.");
  }
  if (!algorithm) {
    return showError("Please select an encryption method.");
  }

  const key = secretKeyEl.value;

  setBusy(true);
  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ algorithm, text, key }),
    });
    const data = await res.json();

    if (!res.ok) {
      return showError(data.error || "Something went wrong.");
    }

    outputEl.value = data.result;
    copyBtn.hidden = false;
  } catch (err) {
    showError("Could not reach the server. Is it running?");
  } finally {
    setBusy(false);
  }
}

async function runHash() {
  clearError();
  copyBtn.hidden = true;

  const text = plaintextEl.value;
  if (!text.trim()) {
    return showError("Please enter some text first.");
  }

  setBusy(true);
  try {
    const res = await fetch("/api/hash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();
    if (!res.ok) {
      return showError(data.error || "Something went wrong.");
    }
    outputEl.value = data.result;
    copyBtn.hidden = false;
  } catch (err) {
    showError("Could not reach the server. Is it running?");
  } finally {
    setBusy(false);
  }
}

function showError(msg) {
  errorEl.textContent = msg;
  errorEl.hidden = false;
}

function clearError() {
  errorEl.hidden = true;
  errorEl.textContent = "";
}

function setBusy(isBusy) {
  [encryptBtn, decryptBtn, hashBtn].forEach((b) => (b.disabled = isBusy));
}
