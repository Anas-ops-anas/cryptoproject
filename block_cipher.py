"""
A2. Block Cipher - Custom 8-round Feistel network
Course : Fundamental of Cryptography (NWC3373/NWC3193)

Parameters
  Block size : 64 bits (two 32-bit halves L, R)
  Key size   : 128 bits (16 bytes)
  Rounds     : 8
  Mode       : CBC with random IV + PKCS#7 padding (ECB also provided for demonstration only)

Round structure (encryption), for i = 1..8:
      L_i = R_{i-1}
      R_i = L_{i-1} XOR F(R_{i-1}, K_i)
Decryption is the same network with the subkeys used in reverse order (K_8 ... K_1),
so F does not have to be invertible.

Educational only: this is a custom design and has NOT been cryptanalysed.
"""

import os
import struct

ROUNDS = 8
BLOCK_SIZE = 8            # bytes
KEY_SIZE = 16             # bytes
MASK32 = 0xFFFFFFFF


# ---------------------------------------------------------------- helpers
def rotl32(x: int, n: int) -> int:
    n %= 32
    return ((x << n) | (x >> (32 - n))) & MASK32


def _build_sbox() -> list:
    """Build a non-linear 8-bit S-box: multiplicative inverse in GF(2^8) followed by an
    affine transform (the same construction principle used by AES)."""
    def gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x1B
            b >>= 1
        return p

    def inverse(a):
        if a == 0:
            return 0
        for c in range(1, 256):
            if gmul(a, c) == 1:
                return c

    sbox = []
    for x in range(256):
        b = inverse(x)
        s = b
        for shift in (1, 2, 3, 4):
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        sbox.append(s ^ 0x63)
    return sbox


SBOX = _build_sbox()


# ---------------------------------------------------------------- key schedule
def generate_key(length: int = KEY_SIZE) -> bytes:
    return os.urandom(length)


def key_schedule(key: bytes) -> list:
    """Expand a 128-bit key into 8 32-bit round subkeys.
    Four key words are repeatedly mixed with rotation, addition and a round constant,
    then one word is passed through the S-box so subkeys are not linear in the key."""
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be exactly 16 bytes")
    w = list(struct.unpack(">4I", key))
    subkeys = []
    for r in range(ROUNDS):
        rc = (0x9E3779B9 * (r + 1)) & MASK32           # round constant
        w[r % 4] = rotl32((w[r % 4] + w[(r + 1) % 4]) & MASK32, 7) ^ rc
        t = w[(r + 3) % 4]
        t = (SBOX[t & 0xFF] | (SBOX[(t >> 8) & 0xFF] << 8) |
             (SBOX[(t >> 16) & 0xFF] << 16) | (SBOX[(t >> 24) & 0xFF] << 24))
        subkeys.append(w[r % 4] ^ t)
    return subkeys


# ---------------------------------------------------------------- round function
def round_function(r: int, k: int) -> int:
    """F(R, K): key mixing -> byte-wise S-box (confusion) -> rotate/XOR mixing (diffusion)."""
    x = r ^ k
    x = (SBOX[x & 0xFF] | (SBOX[(x >> 8) & 0xFF] << 8) |
         (SBOX[(x >> 16) & 0xFF] << 16) | (SBOX[(x >> 24) & 0xFF] << 24))
    return x ^ rotl32(x, 9) ^ rotl32(x, 19)


# ---------------------------------------------------------------- single-block operations
def _process_block(block: bytes, subkeys: list) -> bytes:
    L, R = struct.unpack(">2I", block)
    for k in subkeys:
        L, R = R, L ^ round_function(R, k)
    return struct.pack(">2I", R, L)          # final swap so decryption = same network


def encrypt_block(block: bytes, subkeys: list) -> bytes:
    return _process_block(block, subkeys)


def decrypt_block(block: bytes, subkeys: list) -> bytes:
    return _process_block(block, subkeys[::-1])


# ---------------------------------------------------------------- padding
def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise ValueError("Invalid padded length")
    n = data[-1]
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError("Invalid padding")
    return data[:-n]


# ---------------------------------------------------------------- CBC mode (used by the project)
def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Output: IV (8 bytes) || ciphertext."""
    sk = key_schedule(key)
    iv = os.urandom(BLOCK_SIZE)
    data = pad(plaintext)
    prev = int.from_bytes(iv, "big")
    out = bytearray(iv)
    for i in range(0, len(data), BLOCK_SIZE):
        blk = int.from_bytes(data[i:i + BLOCK_SIZE], "big") ^ prev
        enc = encrypt_block(blk.to_bytes(BLOCK_SIZE, "big"), sk)
        out += enc
        prev = int.from_bytes(enc, "big")
    return bytes(out)


def decrypt(blob: bytes, key: bytes) -> bytes:
    sk = key_schedule(key)
    iv, ct = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    if len(ct) % BLOCK_SIZE:
        raise ValueError("Ciphertext length must be a multiple of 8")
    prev = int.from_bytes(iv, "big")
    out = bytearray()
    for i in range(0, len(ct), BLOCK_SIZE):
        c = ct[i:i + BLOCK_SIZE]
        dec = int.from_bytes(decrypt_block(c, sk), "big") ^ prev
        out += dec.to_bytes(BLOCK_SIZE, "big")
        prev = int.from_bytes(c, "big")
    return unpad(bytes(out))


# ---------------------------------------------------------------- ECB (demonstration ONLY)
def encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    sk = key_schedule(key)
    data = pad(plaintext)
    return b"".join(encrypt_block(data[i:i + 8], sk) for i in range(0, len(data), 8))


# ---------------------------------------------------------------- DEMO / SELF-TEST
if __name__ == "__main__":
    key = generate_key()
    print("Key (hex)       :", key.hex())
    print("Subkeys         :", [hex(k) for k in key_schedule(key)])

    # single block round trip
    sk = key_schedule(key)
    blk = b"ABCDEFGH"
    enc = encrypt_block(blk, sk)
    assert decrypt_block(enc, sk) == blk
    print("Block           :", blk, "->", enc.hex())

    msg = b"Confidential: Q3 salary report - do not distribute."
    blob = encrypt(msg, key)
    print("Ciphertext (hex):", blob.hex())
    assert decrypt(blob, key) == msg
    print("Decrypted       :", decrypt(blob, key))

    assert encrypt(msg, key) != encrypt(msg, key)           # random IV
    try:
        assert decrypt(blob, generate_key()) != msg          # wrong key
    except ValueError:
        pass                                                 # bad padding is also a failure

    for size in (0, 1, 7, 8, 9, 1024, 100 * 1024, 1024 * 1024):
        data = os.urandom(size)
        assert decrypt(encrypt(data, key), key) == data
        print(f"Round trip OK   : {size} bytes")
    print("All tests passed.")
