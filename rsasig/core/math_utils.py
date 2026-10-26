"""Các thuật toán số học nền tảng cho RSA — tự cài đặt, không dùng thư viện mật mã.

Gồm:
    * gcd / extended_gcd      — thuật toán Euclid và Euclid mở rộng
    * mod_inverse             — phần tử nghịch đảo theo modulo
    * mod_pow                 — thuật toán bình phương và nhân (square-and-multiply)
    * is_probable_prime       — kiểm tra nguyên tố Miller–Rabin
    * random_prime            — sinh số nguyên tố ngẫu nhiên k bit

Mỗi hàm có tham số ``trace`` (list hoặc None). Nếu truyền vào một list, hàm sẽ
ghi lại các bước trung gian để phiên bản thu nhỏ in ra khi thuyết trình.
"""

from __future__ import annotations

import secrets

# ---------------------------------------------------------------------------
# Euclid và Euclid mở rộng
# ---------------------------------------------------------------------------


def gcd(a: int, b: int) -> int:
    """Ước chung lớn nhất theo thuật toán Euclid."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    return abs(a // gcd(a, b) * b)


def extended_gcd(a: int, b: int, trace: list | None = None) -> tuple[int, int, int]:
    """Euclid mở rộng: trả về (g, x, y) sao cho a*x + b*y = g = gcd(a, b).

    Cài đặt dạng lặp, giữ bất biến  r_i = a*s_i + b*t_i.
    Khi trace != None, mỗi dòng của bảng tính được thêm vào dưới dạng dict
    {q, r, s, t} — đúng như bảng tính tay trên lớp.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    if trace is not None:
        trace.append({"q": None, "r": old_r, "s": old_s, "t": old_t})
        trace.append({"q": None, "r": r, "s": s, "t": t})
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
        if trace is not None:
            trace.append({"q": q, "r": r, "s": s, "t": t})
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int, trace: list | None = None) -> int:
    """Tìm x sao cho a*x ≡ 1 (mod m). Báo lỗi nếu gcd(a, m) ≠ 1."""
    g, x, _ = extended_gcd(a % m, m, trace)
    if g != 1:
        raise ValueError(f"{a} không khả nghịch modulo {m} (gcd = {g})")
    return x % m


# ---------------------------------------------------------------------------
# Lũy thừa modulo: bình phương và nhân
# ---------------------------------------------------------------------------


def mod_pow(base: int, exp: int, mod: int, trace: list | None = None) -> int:
    """Tính base^exp mod mod bằng thuật toán bình phương và nhân (trái → phải).

    Duyệt các bit của số mũ từ bit cao nhất: mỗi bit thì bình phương kết quả,
    nếu bit = 1 thì nhân thêm base. Độ phức tạp O(log exp) phép nhân modulo.

    trace (nếu có) nhận các dict {bit, square, multiply, result} cho từng bit.
    """
    if mod == 1:
        return 0
    if exp < 0:
        raise ValueError("Số mũ âm: hãy dùng mod_inverse trước")
    base %= mod
    result = 1
    for bit_char in bin(exp)[2:]:
        squared = (result * result) % mod
        if bit_char == "1":
            result = (squared * base) % mod
            multiplied = result
        else:
            result = squared
            multiplied = None
        if trace is not None:
            trace.append(
                {"bit": int(bit_char), "square": squared, "multiply": multiplied, "result": result}
            )
    return result


# ---------------------------------------------------------------------------
# Kiểm tra nguyên tố Miller–Rabin
# ---------------------------------------------------------------------------


def _small_primes(limit: int) -> list[int]:
    """Sàng Eratosthenes — dùng để chia thử nhanh trước khi chạy Miller–Rabin."""
    sieve = bytearray([1]) * (limit + 1)
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i, is_p in enumerate(sieve) if is_p]


SMALL_PRIMES = _small_primes(2000)

# Ngưỡng tất định: nếu n < ngưỡng thì chỉ cần thử các cơ sở tương ứng
# (Jaeschke 1993; Sorenson & Webster 2015). Ví dụ n < 2047 chỉ cần a = 2.
_DETERMINISTIC_TABLE = (
    (2_047, (2,)),
    (1_373_653, (2, 3)),
    (25_326_001, (2, 3, 5)),
    (3_215_031_751, (2, 3, 5, 7)),
    (2_152_302_898_747, (2, 3, 5, 7, 11)),
    (3_474_749_660_383, (2, 3, 5, 7, 11, 13)),
    (341_550_071_728_321, (2, 3, 5, 7, 11, 13, 17)),
    (3_825_123_056_546_413_051, (2, 3, 5, 7, 11, 13, 17, 19, 23)),
    (318_665_857_834_031_151_167_461, (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)),
    (3_317_044_064_679_887_385_961_981, (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)),
)


def miller_rabin_round(n: int, a: int, s: int, d: int, trace: list | None = None) -> bool:
    """Một vòng Miller–Rabin với cơ sở a, trong đó n - 1 = 2^s * d (d lẻ).

    Trả về True nếu n "có thể là nguyên tố" theo cơ sở a, False nếu a là
    nhân chứng (witness) chứng minh n là hợp số.
    """
    x = mod_pow(a, d, n)
    seq = [x]
    if x == 1 or x == n - 1:
        if trace is not None:
            trace.append({"a": a, "sequence": seq, "passed": True})
        return True
    for _ in range(s - 1):
        x = (x * x) % n
        seq.append(x)
        if x == n - 1:
            if trace is not None:
                trace.append({"a": a, "sequence": seq, "passed": True})
            return True
    if trace is not None:
        trace.append({"a": a, "sequence": seq, "passed": False})
    return False


def decompose(n_minus_1: int) -> tuple[int, int]:
    """Viết n - 1 = 2^s * d với d lẻ."""
    s, d = 0, n_minus_1
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def is_probable_prime(
    n: int, rounds: int = 40, trace: list | None = None, bases: list[int] | None = None
) -> bool:
    """Kiểm tra n có phải số nguyên tố (xác suất sai ≤ 4^-rounds với n lớn).

    * n nhỏ hơn 3.3e24: dùng bộ cơ sở cố định theo bảng ngưỡng → kết quả tất định.
    * n lớn: chia thử cho các số nguyên tố nhỏ rồi chọn ngẫu nhiên `rounds` cơ sở.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    # Chế độ trace (bản thu nhỏ) bỏ qua chia thử để luôn in được các vòng Miller–Rabin.
    if trace is None:
        for p in SMALL_PRIMES[:50]:
            if n == p:
                return True
            if n % p == 0:
                return False

    s, d = decompose(n - 1)
    if trace is not None:
        trace.append({"n": n, "s": s, "d": d})

    if bases is None:
        for limit, fixed in _DETERMINISTIC_TABLE:
            if n < limit:
                bases = [a for a in fixed if a < n - 1] or [2]
                break
        else:
            bases = [secrets.randbelow(n - 3) + 2 for _ in range(rounds)]

    for a in bases:
        if not miller_rabin_round(n, a, s, d, trace):
            return False
    return True


def random_prime(bits: int, rounds: int = 40) -> int:
    """Sinh số nguyên tố ngẫu nhiên đúng `bits` bit.

    Đặt bit cao nhất và bit kế cao nhất = 1 để tích p*q có đủ 2*bits bit,
    đặt bit thấp nhất = 1 để số là lẻ. Lọc nhanh bằng chia thử rồi Miller–Rabin.
    """
    if bits < 4:
        raise ValueError("bits phải ≥ 4")
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if any(candidate % p == 0 for p in SMALL_PRIMES if p < candidate):
            continue
        if is_probable_prime(candidate, rounds):
            return candidate


# ---------------------------------------------------------------------------
# Chuyển đổi số nguyên <-> chuỗi byte (I2OSP / OS2IP trong RFC 8017)
# ---------------------------------------------------------------------------


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String: số nguyên → chuỗi byte big-endian dài `length`."""
    if x < 0 or x >= 256**length:
        raise ValueError("Số nguyên quá lớn so với độ dài yêu cầu")
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    """Octet-String-to-Integer: chuỗi byte big-endian → số nguyên."""
    return int.from_bytes(data, "big")


def byte_length(n: int) -> int:
    return (n.bit_length() + 7) // 8
