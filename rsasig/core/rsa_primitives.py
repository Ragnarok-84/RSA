"""Nguyên thuỷ RSA cho chữ ký (RFC 8017, mục 5.2).

    RSASP1 (ký):        s = m^d mod n
    RSAVP1 (kiểm tra):  m = s^e mod n

Ký bằng CRT (định lý số dư Trung Hoa) nhanh hơn ~3–4 lần:
    s1 = m^dP mod p,  s2 = m^dQ mod q,  h = qInv*(s1 - s2) mod p,  s = s2 + h*q
"""

from __future__ import annotations

from .keys import PrivateKey, PublicKey
from .math_utils import mod_pow


def rsasp1(key: PrivateKey, m: int, use_crt: bool = True) -> int:
    """Nguyên thuỷ ký: s = m^d mod n."""
    if not 0 <= m < key.n:
        raise ValueError("Biểu diễn thông điệp nằm ngoài khoảng [0, n-1]")
    if not use_crt:
        return mod_pow(m, key.d, key.n)
    s1 = mod_pow(m, key.dp, key.p)
    s2 = mod_pow(m, key.dq, key.q)
    h = (key.qinv * (s1 - s2)) % key.p
    return s2 + h * key.q


def rsavp1(key: PublicKey, s: int) -> int:
    """Nguyên thuỷ kiểm tra: m = s^e mod n."""
    if not 0 <= s < key.n:
        raise ValueError("Chữ ký nằm ngoài khoảng [0, n-1]")
    return mod_pow(s, key.e, key.n)
