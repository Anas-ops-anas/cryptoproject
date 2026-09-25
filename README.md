# Cryptography Project
crypto group project sources code and guide how to run it

# Symmetric Cipher Project – NWC3373

## Team
- [Akmal Anas] – [Lead Developer & Stream Cipher Lead]
- [Ahmad Uzair] – [Security Analyst & Technical Writer Lead]
- [Muhammad Hafiz] – [Cryptographic Architect & Block Cipher Lead]
- [Danish Hakim] – [Performance Analyst & Data Engineer]



Implementation and evaluation of two symmetric ciphers for the Fundamental of Cryptography group project.

| File | Purpose |
|---|---|
| `stream_cipher.py` | A1 – RC4-like stream cipher (key generation, KSA, PRGA, XOR, nonce, drop-768) |
| `block_cipher.py` | A2 – custom 8-round Feistel block cipher (64-bit block, 128-bit key, CBC + PKCS#7) |
| `performance_test.py` | B1 – benchmarks 1 KB / 100 KB / 1 MB, writes CSV and charts to `results/` |
| `security_demos.py` | B2 – keystream reuse, bit-flipping, avalanche tests, ECB vs CBC |
| `tests/test_ciphers.py` | Unit tests for both ciphers |

## Requirements
Python 3.9+ and matplotlib (only for charts): `pip install -r requirements.txt`

## Run
```bash
python stream_cipher.py                 # self-test + demo
python block_cipher.py                  # self-test + demo
python -m unittest discover -s tests    # unit tests
python security_demos.py                # security demonstrations
python performance_test.py              # benchmark (creates results/)
```
