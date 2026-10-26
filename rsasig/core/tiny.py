"""Phiên bản thu nhỏ (Tiny RSA signature) — dùng để dạy và tính tay.

Khác bản đầy đủ ở chỗ:
  * p, q là số nhỏ (mặc định p = 61, q = 53, e = 17 ⇒ n = 3233, d = 2753);
  * giá trị băm "thu gọn": h = SHA-256(M) mod n (vì n quá nhỏ để chứa 256 bit);
  * không có lược đồ đệm; mọi bước trung gian đều được ghi lại để in ra.

Chính vì h chỉ có n giá trị khả dĩ nên bản thu nhỏ KHÔNG an toàn — xem
tấn công va chạm trong rsasig/attacks/demos.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .keys import PrivateKey, PublicKey, key_from_primes
from .math_utils import extended_gcd, is_probable_prime, mod_pow
from .sha256 import sha256

DEFAULT_P, DEFAULT_Q, DEFAULT_E = 61, 53, 17


@dataclass
class TraceLog:
    """Bộ ghi các dòng giải thích để in ra màn hình / GUI."""

    lines: list[str] = field(default_factory=list)

    def title(self, text: str) -> None:
        self.lines.append("")
        self.lines.append(f"=== {text} ===")

    def add(self, text: str = "") -> None:
        self.lines.append(text)

    def text(self) -> str:
        return "\n".join(self.lines)


def tiny_hash(message: bytes, n: int, log: TraceLog | None = None) -> int:
    """Băm thu gọn: h = SHA-256(M) mod n."""
    digest = sha256(message).digest()
    full = int.from_bytes(digest, "big")
    h = full % n
    if log:
        log.title("Bước 1. Băm thông điệp")
        log.add(f"M            = {message!r}")
        log.add(f"SHA-256(M)   = {digest.hex()}")
        log.add(f"             = {full} (dạng số nguyên)")
        log.add(f"h = SHA-256(M) mod n = {full} mod {n} = {h}")
    return h


def _log_miller_rabin(n: int, log: TraceLog) -> bool:
    rows: list = []
    result = is_probable_prime(n, trace=rows)
    if not rows:
        log.add(f"  {n}: {'nguyên tố' if result else 'hợp số'}")
        return result
    head = rows[0]
    log.add(f"  Kiểm tra {n}: n-1 = {n - 1} = 2^{head['s']} * {head['d']}")
    for r in rows[1:]:
        seq = " → ".join(str(x) for x in r["sequence"])
        verdict = "qua" if r["passed"] else f"KHÔNG qua ⇒ {n} là hợp số"
        log.add(f"    a = {r['a']:>2}: a^d mod n, bình phương tiếp: {seq}   [{verdict}]")
    log.add(f"  ⇒ {n} {'là số nguyên tố' if result else 'là hợp số'}")
    return result


def _log_square_multiply(base: int, exp: int, mod: int, log: TraceLog, label: str) -> int:
    rows: list = []
    result = mod_pow(base, exp, mod, rows)
    log.add(f"{label} = {base}^{exp} mod {mod}, số mũ dạng nhị phân: {exp:b}")
    log.add(f"  {'bit':>3} | {'bình phương':>12} | {'nhân base':>10} | {'kết quả':>8}")
    log.add("  " + "-" * 44)
    for r in rows:
        mul = "-" if r["multiply"] is None else str(r["multiply"])
        log.add(f"  {r['bit']:>3} | {r['square']:>12} | {mul:>10} | {r['result']:>8}")
    log.add(f"  ⇒ {label} = {result}")
    return result


class TinyRSA:
    """Hệ chữ ký RSA thu nhỏ có in bước trung gian."""

    def __init__(self, p: int = DEFAULT_P, q: int = DEFAULT_Q, e: int = DEFAULT_E) -> None:
        self.p, self.q, self.e = p, q, e
        self._trace: dict = {}
        self.key: PrivateKey = key_from_primes(p, q, e, self._trace)

    @property
    def public_key(self) -> PublicKey:
        return self.key.public_key()

    @property
    def n(self) -> int:
        return self.key.n

    # -- sinh khoá -------------------------------------------------------

    def explain_keygen(self, log: TraceLog) -> None:
        k = self.key
        log.title("Sinh khoá")
        log.add("Kiểm tra p, q nguyên tố bằng Miller–Rabin:")
        _log_miller_rabin(self.p, log)
        _log_miller_rabin(self.q, log)
        log.add(f"n    = p*q = {self.p}*{self.q} = {k.n}")
        log.add(f"φ(n) = (p-1)(q-1) = {self.p - 1}*{self.q - 1} = {self._trace['phi']}")
        log.add(f"e    = {self.e}  (gcd(e, φ(n)) = 1)")
        phi = self._trace["phi"]
        rows: list = []
        _, _, t_final = extended_gcd(phi, self.e, rows)
        log.add("Tính d = e^-1 mod φ(n) bằng Euclid mở rộng (mỗi dòng: r = φ·s + e·t):")
        log.add(f"  {'q':>5} | {'r':>6} | {'s':>6} | {'t':>6}")
        log.add("  " + "-" * 32)
        for row in rows:
            q = "" if row["q"] is None else row["q"]
            log.add(f"  {q:>5} | {row['r']:>6} | {row['s']:>6} | {row['t']:>6}")
        log.add(f"  Dòng có r = 1 cho t = {t_final} ⇒ d = {t_final} mod {phi} = {k.d}")
        log.add(f"  Kiểm tra: e*d mod φ(n) = {self.e}*{k.d} mod {phi} = {self.e * k.d % phi}")
        log.add(f"Khoá công khai  (n, e) = ({k.n}, {k.e})")
        log.add(f"Khoá bí mật     (n, d) = ({k.n}, {k.d})")

    # -- ký / kiểm tra ---------------------------------------------------

    def sign_hash(self, h: int, log: TraceLog | None = None) -> int:
        if not 0 <= h < self.n:
            raise ValueError("h phải nằm trong [0, n-1]")
        if log:
            log.title("Bước 2. Ký: s = h^d mod n")
            return _log_square_multiply(h, self.key.d, self.n, log, "s")
        return mod_pow(h, self.key.d, self.n)

    def verify_hash(self, h: int, s: int, log: TraceLog | None = None) -> bool:
        if log:
            log.title("Bước 3. Kiểm tra: h' = s^e mod n, so sánh h' với h")
            h_prime = _log_square_multiply(s, self.e, self.n, log, "h'")
            ok = h_prime == h
            log.add(f"h' = {h_prime}, h = {h} ⇒ {'CHỮ KÝ HỢP LỆ' if ok else 'CHỮ KÝ KHÔNG HỢP LỆ'}")
            return ok
        return mod_pow(s, self.e, self.n) == h

    def sign(self, message: bytes, log: TraceLog | None = None) -> int:
        return self.sign_hash(tiny_hash(message, self.n, log), log)

    def verify(self, message: bytes, s: int, log: TraceLog | None = None) -> bool:
        if log:
            log.add("")
            log.add("Người nhận băm lại thông điệp nhận được:")
        return self.verify_hash(tiny_hash(message, self.n, log), s, log)


def full_walkthrough(
    message: bytes | None = None,
    hash_value: int | None = None,
    p: int = DEFAULT_P,
    q: int = DEFAULT_Q,
    e: int = DEFAULT_E,
    tampered: bytes | None = None,
) -> str:
    """Chạy trọn quy trình sinh khoá → ký → kiểm tra và trả về văn bản giải thích.

    Có thể truyền `hash_value` (số nguyên) thay cho `message` để khớp ví dụ trên lớp.
    """
    rsa = TinyRSA(p, q, e)
    log = TraceLog()
    rsa.explain_keygen(log)
    if hash_value is not None:
        log.title("Bước 1. Giá trị băm cho trước")
        log.add(f"h = {hash_value}")
        s = rsa.sign_hash(hash_value, log)
        rsa.verify_hash(hash_value, s, log)
    else:
        message = message if message is not None else b"HELLO"
        s = rsa.sign(message, log)
        rsa.verify(message, s, log)
        if tampered is not None:
            log.title("Thử sửa thông điệp")
            rsa.verify(tampered, s, log)
    return log.text()
