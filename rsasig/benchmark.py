"""Đo thời gian chạy theo kích thước dữ liệu và kích thước khoá.

Thư viện chuẩn (hashlib, cryptography) chỉ được gọi ở đây để ĐỐI CHIẾU tốc độ,
không dùng trong phần lõi.
"""

from __future__ import annotations

import hashlib
import os
import statistics
import time
from typing import Callable

from .core.keys import generate_keypair
from .core.pkcs1 import sign_digest, verify_digest
from .core.sha256 import sha256

try:  # tuỳ chọn
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    HAVE_CRYPTOGRAPHY = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False


def _time(fn: Callable[[], object], repeat: int = 3) -> float:
    samples = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def bench_hash(sizes=(1_024, 10_240, 102_400, 1_048_576)) -> list[dict]:
    rows = []
    for size in sizes:
        data = os.urandom(size)
        ours = _time(lambda: sha256(data).digest())
        ref = _time(lambda: hashlib.sha256(data).digest())
        rows.append({
            "size": size,
            "ours_s": ours,
            "ours_MBps": size / ours / 1e6,
            "hashlib_s": ref,
        })
    return rows


def bench_rsa(key_sizes=(1024, 2048, 3072), sign_repeat: int = 5) -> list[dict]:
    rows = []
    digest = sha256(b"benchmark").digest()
    for bits in key_sizes:
        t0 = time.perf_counter()
        key = generate_keypair(bits)
        keygen = time.perf_counter() - t0
        pub = key.public_key()
        sig = sign_digest(key, digest, "pss")
        row = {
            "bits": bits,
            "keygen_s": keygen,
            "sign_crt_ms": 1e3 * _time(lambda: sign_digest(key, digest, "pss", use_crt=True), sign_repeat),
            "sign_nocrt_ms": 1e3 * _time(lambda: sign_digest(key, digest, "pss", use_crt=False), sign_repeat),
            "verify_ms": 1e3 * _time(lambda: verify_digest(pub, digest, sig, "pss"), sign_repeat),
        }
        if HAVE_CRYPTOGRAPHY:
            ref_key = rsa.generate_private_key(65537, bits)
            pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
            row["ref_sign_ms"] = 1e3 * _time(lambda: ref_key.sign(b"benchmark", pss, hashes.SHA256()), sign_repeat)
        rows.append(row)
    return rows


def bench_sign_file_sizes(sizes=(1_024, 102_400, 1_048_576), bits: int = 2048) -> list[dict]:
    """Thời gian ký = băm (tỉ lệ với kích thước) + một phép lũy thừa RSA (hằng số)."""
    key = generate_keypair(bits)
    rows = []
    for size in sizes:
        data = os.urandom(size)
        t_hash = _time(lambda: sha256(data).digest(), 1)
        digest = sha256(data).digest()
        t_sign = _time(lambda: sign_digest(key, digest, "pss"), 3)
        rows.append({"size": size, "hash_ms": t_hash * 1e3, "rsa_ms": t_sign * 1e3})
    return rows


def _fmt_size(n: int) -> str:
    return f"{n // 1_048_576} MB" if n >= 1_048_576 else f"{n // 1024} KB"


def run_all(quick: bool = False) -> str:
    out = []
    out.append("== SHA-256 tự cài đặt so với hashlib (C) ==")
    out.append(f"{'kích thước':>10} | {'ours (s)':>9} | {'MB/s':>6} | {'hashlib (s)':>11}")
    sizes = (1_024, 10_240, 102_400) if quick else (1_024, 10_240, 102_400, 1_048_576)
    for r in bench_hash(sizes):
        out.append(f"{_fmt_size(r['size']):>10} | {r['ours_s']:>9.4f} | {r['ours_MBps']:>6.2f} | {r['hashlib_s']:>11.6f}")

    out.append("")
    out.append("== RSA-PSS theo kích thước khoá ==")
    header = f"{'bit':>5} | {'sinh khoá (s)':>13} | {'ký CRT (ms)':>11} | {'ký không CRT (ms)':>17} | {'kiểm tra (ms)':>13}"
    if HAVE_CRYPTOGRAPHY:
        header += f" | {'ký cryptography (ms)':>20}"
    out.append(header)
    for r in bench_rsa((1024, 2048) if quick else (1024, 2048, 3072)):
        line = (f"{r['bits']:>5} | {r['keygen_s']:>13.2f} | {r['sign_crt_ms']:>11.2f} | "
                f"{r['sign_nocrt_ms']:>17.2f} | {r['verify_ms']:>13.2f}")
        if "ref_sign_ms" in r:
            line += f" | {r['ref_sign_ms']:>20.3f}"
        out.append(line)

    out.append("")
    out.append("== Ký tệp theo kích thước (RSA-2048): băm chiếm phần lớn với tệp lớn ==")
    out.append(f"{'kích thước':>10} | {'băm (ms)':>9} | {'lũy thừa RSA (ms)':>17}")
    for r in bench_sign_file_sizes((1_024, 102_400) if quick else (1_024, 102_400, 1_048_576)):
        out.append(f"{_fmt_size(r['size']):>10} | {r['hash_ms']:>9.1f} | {r['rsa_ms']:>17.1f}")
    return "\n".join(out)
