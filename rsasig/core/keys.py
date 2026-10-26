"""Sinh, lưu và nạp cặp khoá RSA.

Sinh khoá:
    1. Chọn hai số nguyên tố lớn p ≠ q (Miller–Rabin).
    2. n = p*q,  φ(n) = (p-1)(q-1).
    3. Chọn e với gcd(e, φ(n)) = 1 (mặc định e = 65537).
    4. d = e^-1 mod φ(n)  (Euclid mở rộng).
    Khoá công khai (n, e) — khoá bí mật (n, d) kèm p, q, dP, dQ, qInv để ký nhanh bằng CRT.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .math_utils import gcd, is_probable_prime, mod_inverse, random_prime
from .sha256 import sha256

DEFAULT_E = 65537


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size_bytes(self) -> int:
        return (self.bits + 7) // 8

    def fingerprint(self) -> str:
        """Dấu vân tay khoá = SHA-256(n ‖ e) rút gọn — dùng để nhận diện khoá."""
        data = f"{self.n:x}:{self.e:x}".encode()
        digest = sha256(data).hexdigest()
        return ":".join(digest[i : i + 4] for i in range(0, 32, 4))

    def to_dict(self) -> dict:
        return {"type": "rsa-public", "n": hex(self.n), "e": self.e}

    @classmethod
    def from_dict(cls, d: dict) -> "PublicKey":
        return cls(n=int(d["n"], 16), e=int(d["e"]))


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int    # d mod (p-1)
    dq: int    # d mod (q-1)
    qinv: int  # q^-1 mod p

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)

    def to_dict(self) -> dict:
        return {"type": "rsa-private", **{k: hex(v) for k, v in asdict(self).items()}}

    @classmethod
    def from_dict(cls, d: dict) -> "PrivateKey":
        return cls(**{k: int(d[k], 16) for k in ("n", "e", "d", "p", "q", "dp", "dq", "qinv")})


def key_from_primes(p: int, q: int, e: int = DEFAULT_E, trace: dict | None = None) -> PrivateKey:
    """Dựng khoá từ p, q, e cho trước (dùng cho bản thu nhỏ và kiểm thử).

    trace (dict) nếu có sẽ nhận: phi, bảng Euclid mở rộng tính d.
    """
    if p == q:
        raise ValueError("p và q phải khác nhau")
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p và q phải là số nguyên tố")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi or gcd(e, phi) != 1:
        raise ValueError(f"e = {e} không hợp lệ: cần 1 < e < φ(n) = {phi} và gcd(e, φ(n)) = 1")
    egcd_rows: list | None = [] if trace is not None else None
    d = mod_inverse(e, phi, egcd_rows)
    if trace is not None:
        trace.update({"n": n, "phi": phi, "egcd": egcd_rows, "d": d})
    return PrivateKey(
        n=n, e=e, d=d, p=p, q=q, dp=d % (p - 1), dq=d % (q - 1), qinv=mod_inverse(q, p)
    )


def generate_keypair(bits: int = 2048, e: int = DEFAULT_E) -> PrivateKey:
    """Sinh cặp khoá RSA với modulus n đúng `bits` bit."""
    if bits < 512:
        raise ValueError("Bản đầy đủ yêu cầu ít nhất 512 bit (khuyến nghị ≥ 2048)")
    half = bits // 2
    while True:
        p = random_prime(bits - half)
        q = random_prime(half)
        if p == q:
            continue
        # Tránh p, q quá gần nhau (tấn công phân tích Fermat)
        if abs(p - q) >> (half - 100) == 0:
            continue
        if gcd(e, (p - 1) * (q - 1)) != 1:
            continue
        key = key_from_primes(p, q, e)
        if key.bits == bits:
            return key


# ---------------------------------------------------------------------------
# Lưu / nạp khoá dạng JSON
# ---------------------------------------------------------------------------


def save_key(key: PublicKey | PrivateKey, path: str | Path, owner: str | None = None) -> None:
    data = key.to_dict()
    if owner:
        data["owner"] = owner
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_key(path: str | Path) -> PublicKey | PrivateKey:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("type") == "rsa-private":
        return PrivateKey.from_dict(data)
    if data.get("type") == "rsa-public":
        return PublicKey.from_dict(data)
    raise ValueError(f"Tệp {path} không phải khoá RSA hợp lệ")


def load_owner(path: str | Path) -> str | None:
    return json.loads(Path(path).read_text(encoding="utf-8")).get("owner")
