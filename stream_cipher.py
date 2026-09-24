"""
A1. Stream Cipher - Simplified RC4-like algorithm
Course : Fundamental of Cryptography (NWC3373/NWC3193)

Components
  1. Key generation      -> generate_key()       (random key or password-derived key)
  2. Keystream generation-> ksa() + prga()       (RC4-style KSA and PRGA, with "drop-N")
  3. XOR encryption      -> xor_bytes()          (plaintext XOR keystream)
  4. Decryption          -> decrypt()            (same XOR with the same keystream)

Educational only: RC4 is considered broken and must not be used in production.
"""

import os
import hashlib

DROP_N = 768          # discard first N keystream bytes (mitigates RC4 initial-byte bias)
NONCE_LEN = 8         # per-message random nonce so the same key never reuses a keystream
KEY_LEN = 16          # 128-bit key


# ---------------------------------------------------------------- 1. KEY GENERATION
def generate_key(length: int = KEY_LEN) -> bytes:
    """Generate a cryptographically secure random key."""
    return os.urandom(length)


def key_from_password(password: str, salt: bytes, length: int = KEY_LEN) -> bytes:
    """Derive a key from a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, dklen=length)


# ---------------------------------------------------------------- 2. KEYSTREAM GENERATION
def ksa(key: bytes) -> list:
    """Key-Scheduling Algorithm: permute S = [0..255] using the key."""
    if not 1 <= len(key) <= 256:
        raise ValueError("Key length must be 1-256 bytes")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def prga(S: list, drop: int = DROP_N):
    """Pseudo-Random Generation Algorithm: yields one keystream byte at a time."""
    i = j = 0
    count = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        count += 1
        if count > drop:
            yield k


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Produce `length` keystream bytes for (key, nonce). Nonce is mixed into the key."""
    S = ksa(key + nonce)
    gen = prga(S)
    return bytes(next(gen) for _ in range(length))


# ---------------------------------------------------------------- 3. XOR ENCRYPTION
def xor_bytes(data: bytes, ks: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, ks))


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Output format: nonce (8 bytes) || ciphertext."""
    nonce = os.urandom(NONCE_LEN)
    ks = keystream(key, nonce, len(plaintext))
    return nonce + xor_bytes(plaintext, ks)


# ---------------------------------------------------------------- 4. DECRYPTION
def decrypt(blob: bytes, key: bytes) -> bytes:
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    ks = keystream(key, nonce, len(ct))
    return xor_bytes(ct, ks)


# ---------------------------------------------------------------- DEMO / SELF-TEST
if __name__ == "__main__":
    key = generate_key()
    print("Key (hex)      :", key.hex())

    msg = b"Confidential: Q3 salary report - do not distribute."
    blob = encrypt(msg, key)
    print("Plaintext      :", msg)
    print("Ciphertext(hex):", blob.hex())
    recovered = decrypt(blob, key)
    print("Decrypted      :", recovered)
    assert recovered == msg, "Decryption failed!"

    # Same plaintext twice -> different ciphertext (fresh nonce)
    assert encrypt(msg, key) != encrypt(msg, key)

    # Wrong key must not recover plaintext
    assert decrypt(blob, generate_key()) != msg

    # Known-answer check: RC4 test vector (Key="Key", Plain="Plaintext") without drop/nonce
    S = ksa(b"Key")
    g = prga(S, drop=0)
    ct = xor_bytes(b"Plaintext", bytes(next(g) for _ in range(9)))
    assert ct.hex().upper() == "BBF316E8D940AF0AD3", ct.hex()

    # File-size round trips (matches Part B test sizes)
    for size in (1024, 100 * 1024, 1024 * 1024):
        data = os.urandom(size)
        assert decrypt(encrypt(data, key), key) == data
        print(f"Round trip OK  : {size} bytes")

    print("All tests passed.")
