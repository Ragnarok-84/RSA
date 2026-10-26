"""Lược đồ chữ ký RSA "ký trên giá trị băm" theo PKCS#1 (RFC 8017).

Hai lược đồ được cài đặt:

* RSASSA-PKCS1-v1_5 (mục 8.2) — tất định, dùng rộng rãi (chứng thư X.509, TLS):
      EM = 0x00 ‖ 0x01 ‖ FF…FF ‖ 0x00 ‖ DigestInfo(SHA-256) ‖ H(M)

* RSASSA-PSS (mục 8.1) — ngẫu nhiên hoá bằng salt, có chứng minh an toàn,
  được khuyến nghị cho ứng dụng mới.

Luôn ký trên H(M) chứ không ký trực tiếp M:
  - M dài tuỳ ý nhưng RSA chỉ ký được số < n;
  - phá vỡ tính chất nhân của RSA thô (xem rsasig/attacks).
"""

from __future__ import annotations

import secrets

from .hmac_sha256 import constant_time_equal
from .keys import PrivateKey, PublicKey
from .math_utils import i2osp, os2ip
from .rsa_primitives import rsasp1, rsavp1
from .sha256 import sha256

HASH_LEN = 32

# DER của DigestInfo { AlgorithmIdentifier(id-sha256, NULL), OCTET STRING(32) } — RFC 8017 mục 9.2
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

SCHEMES = ("pkcs1v15", "pss")


class SignatureError(Exception):
    pass


# ---------------------------------------------------------------------------
# EMSA-PKCS1-v1_5
# ---------------------------------------------------------------------------


def emsa_pkcs1_v15_encode(digest: bytes, em_len: int) -> bytes:
    """Mã hoá giá trị băm thành khối EM dài em_len byte."""
    t = SHA256_DIGEST_INFO_PREFIX + digest
    if em_len < len(t) + 11:
        raise SignatureError("Modulus quá ngắn để chứa DigestInfo")
    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def sign_digest_pkcs1_v15(key: PrivateKey, digest: bytes, use_crt: bool = True) -> bytes:
    k = (key.bits + 7) // 8
    em = emsa_pkcs1_v15_encode(digest, k)
    s = rsasp1(key, os2ip(em), use_crt)
    return i2osp(s, k)


def verify_digest_pkcs1_v15(key: PublicKey, digest: bytes, signature: bytes) -> bool:
    """Kiểm tra theo cách "mã hoá lại rồi so sánh" của RFC 8017.

    Không phân tích cú pháp EM — tránh lỗi kiểu tấn công Bleichenbacher 2006
    với e = 3 khi bộ kiểm tra chấp nhận phần rác sau DigestInfo.
    """
    k = key.size_bytes
    if len(signature) != k:
        return False
    s = os2ip(signature)
    if s >= key.n:
        return False
    em = i2osp(rsavp1(key, s), k)
    expected = emsa_pkcs1_v15_encode(digest, k)
    return constant_time_equal(em, expected)


# ---------------------------------------------------------------------------
# EMSA-PSS
# ---------------------------------------------------------------------------


def mgf1(seed: bytes, length: int) -> bytes:
    """Hàm sinh mặt nạ MGF1 dựa trên SHA-256 (RFC 8017 phụ lục B.2.1)."""
    out = b""
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def emsa_pss_encode(digest: bytes, em_bits: int, salt: bytes) -> bytes:
    em_len = (em_bits + 7) // 8
    s_len = len(salt)
    if em_len < HASH_LEN + s_len + 2:
        raise SignatureError("Modulus quá ngắn cho PSS")
    m_prime = b"\x00" * 8 + digest + salt
    h = sha256(m_prime).digest()
    ps = b"\x00" * (em_len - s_len - HASH_LEN - 2)
    db = ps + b"\x01" + salt
    masked_db = bytearray(_xor(db, mgf1(h, em_len - HASH_LEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def emsa_pss_verify(digest: bytes, em: bytes, em_bits: int, s_len: int = HASH_LEN) -> bool:
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < HASH_LEN + s_len + 2 or em[-1] != 0xBC:
        return False
    masked_db, h = em[: em_len - HASH_LEN - 1], em[em_len - HASH_LEN - 1 : -1]
    unused_bits = 8 * em_len - em_bits
    if masked_db[0] & (0xFF00 >> unused_bits) & 0xFF:  # các bit thừa bên trái phải = 0
        return False
    db = bytearray(_xor(masked_db, mgf1(h, em_len - HASH_LEN - 1)))
    db[0] &= 0xFF >> unused_bits
    pad_len = em_len - HASH_LEN - s_len - 2
    if any(db[:pad_len]) or db[pad_len] != 0x01:
        return False
    salt = bytes(db[-s_len:]) if s_len else b""
    h_prime = sha256(b"\x00" * 8 + digest + salt).digest()
    return constant_time_equal(h, h_prime)


def sign_digest_pss(
    key: PrivateKey, digest: bytes, salt: bytes | None = None, use_crt: bool = True
) -> bytes:
    if salt is None:
        salt = secrets.token_bytes(HASH_LEN)
    mod_bits = key.bits
    em = emsa_pss_encode(digest, mod_bits - 1, salt)
    s = rsasp1(key, os2ip(em), use_crt)
    return i2osp(s, (mod_bits + 7) // 8)


def verify_digest_pss(key: PublicKey, digest: bytes, signature: bytes, s_len: int = HASH_LEN) -> bool:
    if len(signature) != key.size_bytes:
        return False
    s = os2ip(signature)
    if s >= key.n:
        return False
    m = rsavp1(key, s)
    em_bits = key.bits - 1
    em_len = (em_bits + 7) // 8
    if m >= 256**em_len:
        return False
    return emsa_pss_verify(digest, i2osp(m, em_len), em_bits, s_len)


# ---------------------------------------------------------------------------
# API mức cao: ký / kiểm tra trên thông điệp hoặc trên giá trị băm có sẵn
# ---------------------------------------------------------------------------


def sign_digest(key: PrivateKey, digest: bytes, scheme: str = "pss", use_crt: bool = True) -> bytes:
    if len(digest) != HASH_LEN:
        raise SignatureError("Giá trị băm phải là SHA-256 (32 byte)")
    if scheme == "pkcs1v15":
        return sign_digest_pkcs1_v15(key, digest, use_crt)
    if scheme == "pss":
        return sign_digest_pss(key, digest, use_crt=use_crt)
    raise SignatureError(f"Lược đồ không hỗ trợ: {scheme}")


def verify_digest(key: PublicKey, digest: bytes, signature: bytes, scheme: str = "pss") -> bool:
    if scheme == "pkcs1v15":
        return verify_digest_pkcs1_v15(key, digest, signature)
    if scheme == "pss":
        return verify_digest_pss(key, digest, signature)
    raise SignatureError(f"Lược đồ không hỗ trợ: {scheme}")


def sign(key: PrivateKey, message: bytes, scheme: str = "pss", use_crt: bool = True) -> bytes:
    """Ký thông điệp: băm SHA-256 rồi ký trên giá trị băm."""
    return sign_digest(key, sha256(message).digest(), scheme, use_crt)


def verify(key: PublicKey, message: bytes, signature: bytes, scheme: str = "pss") -> bool:
    """Kiểm tra chữ ký trên thông điệp."""
    return verify_digest(key, sha256(message).digest(), signature, scheme)
