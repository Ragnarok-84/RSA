"""Kiểm thử các thuật toán nền: Euclid mở rộng, nghịch đảo modulo, bình phương và nhân, Miller–Rabin.

Hàm có sẵn của Python (pow, math.gcd) chỉ được dùng làm chuẩn đối chiếu.
"""

import math
import secrets

import pytest

from rsasig.core.math_utils import (
    extended_gcd,
    gcd,
    i2osp,
    is_probable_prime,
    mod_inverse,
    mod_pow,
    os2ip,
    random_prime,
)


def test_extended_gcd_textbook():
    # Ví dụ trên lớp: φ = 3120, e = 17 ⇒ 3120*2 + 17*(-367) = 1
    g, x, y = extended_gcd(3120, 17)
    assert (g, x, y) == (1, 2, -367)
    assert 3120 * x + 17 * y == 1


def test_mod_inverse_textbook():
    assert mod_inverse(17, 3120) == 2753


def test_mod_inverse_not_invertible():
    with pytest.raises(ValueError):
        mod_inverse(6, 9)


def test_gcd_and_inverse_random_vs_builtin():
    for _ in range(200):
        a, m = secrets.randbits(256) + 1, secrets.randbits(256) + 2
        assert gcd(a, m) == math.gcd(a, m)
        g, x, y = extended_gcd(a, m)
        assert a * x + m * y == g
        if g == 1:
            assert mod_inverse(a, m) == pow(a, -1, m)


def test_mod_pow_small_trace():
    trace = []
    assert mod_pow(65, 2753, 3233, trace) == 588
    assert len(trace) == (2753).bit_length()
    assert trace[-1]["result"] == 588


def test_mod_pow_random_vs_builtin():
    for _ in range(100):
        b, e, m = secrets.randbits(1024), secrets.randbits(1024), secrets.randbits(1024) | 1
        assert mod_pow(b, e, m) == pow(b, e, m)
    assert mod_pow(5, 0, 7) == 1
    assert mod_pow(5, 3, 1) == 0


KNOWN_PRIMES = [2, 3, 5, 53, 61, 7919, 104729, 2**31 - 1, 2**61 - 1, 2**89 - 1, 2**127 - 1]
# Số Carmichael đánh lừa được phép thử Fermat nhưng không lừa được Miller–Rabin
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185]
COMPOSITES = [1, 4, 9, 3233, 2047, 1373653, (2**61 - 1) * (2**31 - 1)]


@pytest.mark.parametrize("p", KNOWN_PRIMES)
def test_miller_rabin_primes(p):
    assert is_probable_prime(p)


@pytest.mark.parametrize("n", CARMICHAEL + COMPOSITES)
def test_miller_rabin_composites(n):
    assert not is_probable_prime(n)


def test_miller_rabin_agrees_with_trial_division():
    def naive(n):
        return n >= 2 and all(n % d for d in range(2, math.isqrt(n) + 1))

    assert all(is_probable_prime(n) == naive(n) for n in range(0, 5000))


@pytest.mark.parametrize("bits", [16, 64, 512])
def test_random_prime_size(bits):
    p = random_prime(bits)
    assert p.bit_length() == bits and is_probable_prime(p)


def test_i2osp_os2ip_roundtrip():
    assert i2osp(258, 4) == b"\x00\x00\x01\x02"
    assert os2ip(b"\x00\x00\x01\x02") == 258
    with pytest.raises(ValueError):
        i2osp(256, 1)
