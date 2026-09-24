"""
B1. Performance testing - encryption/decryption time for 1 KB, 100 KB and 1 MB files.

Method
  * fresh random file per size (os.urandom) and a fresh 128-bit key per cipher
  * each measurement repeated REPEATS times, average reported in milliseconds
  * timing with time.perf_counter()
Outputs (written to ./results/): results.csv, chart_bar.png, chart_loglog.png
"""

import os
import csv
import time
import platform

import stream_cipher as sc
import block_cipher as bc

SIZES = {"1 KB": 1024, "100 KB": 100 * 1024, "1 MB": 1024 * 1024}
REPEATS = 10


def timed(fn, *args):
    t0 = time.perf_counter()
    out = fn(*args)
    return (time.perf_counter() - t0) * 1000.0, out


def bench(enc, dec, key, data):
    enc_t, dec_t = [], []
    for _ in range(REPEATS):
        t, blob = timed(enc, data, key)
        enc_t.append(t)
        t, plain = timed(dec, blob, key)
        dec_t.append(t)
        assert plain == data, "round trip failed during benchmark"
    return sum(enc_t) / REPEATS, sum(dec_t) / REPEATS


def main():
    os.makedirs("results", exist_ok=True)
    k_stream, k_block = sc.generate_key(), bc.generate_key()
    rows = []
    print(f"Python {platform.python_version()} on {platform.system()} | {REPEATS} runs per test\n")
    for label, size in SIZES.items():
        data = os.urandom(size)
        se, sd = bench(sc.encrypt, sc.decrypt, k_stream, data)
        be, bd = bench(bc.encrypt, bc.decrypt, k_block, data)
        rows.append([label, size, se, sd, be, bd])
        print(f"{label:>7} | stream enc {se:9.4f}  dec {sd:9.4f} | feistel enc {be:9.4f}  dec {bd:9.4f}  (ms)")

    with open("results/results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file_size", "bytes", "stream_enc_ms", "stream_dec_ms", "block_enc_ms", "block_dec_ms"])
        w.writerows(rows)

    print("\nSlowdown of block cipher vs stream cipher")
    for r in rows:
        print(f"{r[0]:>7} | enc {r[4] / r[2]:.2f}x | dec {r[5] / r[3]:.2f}x")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - skipping charts (pip install matplotlib)")
        return

    labels = [r[0] for r in rows]
    x = range(len(labels))
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))
    for ax, title, si, bi in ((axes[0], "Encryption time", 2, 4), (axes[1], "Decryption time", 3, 5)):
        ax.bar([i - 0.2 for i in x], [r[si] for r in rows], 0.4, label="RC4-like stream")
        ax.bar([i + 0.2 for i in x], [r[bi] for r in rows], 0.4, label="Feistel block (CBC)")
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_ylabel("Time (ms)")
        ax.set_xlabel("File size")
        ax.set_title(title)
        ax.legend()
    fig.tight_layout()
    fig.savefig("results/chart_bar.png", dpi=150)

    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    sizes = [r[1] for r in rows]
    ax.loglog(sizes, [r[2] for r in rows], "o-", label="Stream encrypt")
    ax.loglog(sizes, [r[3] for r in rows], "s--", label="Stream decrypt")
    ax.loglog(sizes, [r[4] for r in rows], "o-", label="Feistel encrypt")
    ax.loglog(sizes, [r[5] for r in rows], "s--", label="Feistel decrypt")
    ax.set_xticks(sizes)
    ax.set_xticklabels(labels)
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Scaling: time vs file size (log-log)")
    ax.legend()
    ax.grid(True, which="both", alpha=0.3)
    fig.tight_layout()
    fig.savefig("results/chart_loglog.png", dpi=150)
    print("\nSaved results/results.csv, chart_bar.png, chart_loglog.png")


if __name__ == "__main__":
    main()
