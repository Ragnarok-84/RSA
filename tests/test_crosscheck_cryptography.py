"""Đối chiếu chéo với thư viện chuẩn `cryptography` (lõi OpenSSL) theo cả hai chiều:

  * chữ ký do chương trình của nhóm tạo ra → `cryptography` kiểm tra;
  * chữ ký do `cryptography` tạo ra → chương trình của nhóm kiểm tra;
  * PKCS#1 v1.5 tất định ⇒ hai bên phải ra cùng một chuỗi byte.

Thư viện chỉ dùng ở đây để đối chiếu, không dùng trong phần lõi.
"""

import os

import pytest

pytest.importorskip("cryptography")

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from rsasig.core.keys import PrivateKey, key_from_primes
from rsasig.core.pkcs1 import sign, verify

SCHEMES = ["pkcs1v15", "pss"]
MSG = "Tôi, Alice, đồng ý thanh toán 1.200.000.000 VND cho Bob.".encode()


def _to_crypto(key: PrivateKey):
    pub = rsa.RSAPublicNumbers(key.e, key.n)
    return rsa.RSAPrivateNumbers(key.p, key.q, key.d, key.dp, key.dq, key.qinv, pub).private_key()


def _from_crypto(ref) -> PrivateKey:
    nums = ref.private_numbers()
    return key_from_primes(nums.p, nums.q, nums.public_numbers.e)


def _pad(scheme):
    if scheme == "pss":
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    return padding.PKCS1v15()


@pytest.mark.parametrize("scheme", SCHEMES)
def test_our_signature_verified_by_cryptography(key1024, scheme):
    sig = sign(key1024, MSG, scheme)
    _to_crypto(key1024).public_key().verify(sig, MSG, _pad(scheme), hashes.SHA256())  # ném lỗi nếu sai
    with pytest.raises(InvalidSignature):
        _to_crypto(key1024).public_key().verify(sig, MSG + b"!", _pad(scheme), hashes.SHA256())


@pytest.mark.parametrize("scheme", SCHEMES)
def test_cryptography_signature_verified_by_us(scheme):
    ref = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ours = _from_crypto(ref)
    assert ours.n == ref.private_numbers().public_numbers.n
    sig = ref.sign(MSG, _pad(scheme), hashes.SHA256())
    assert verify(ours.public_key(), MSG, sig, scheme)
    assert not verify(ours.public_key(), MSG + b"!", sig, scheme)


def test_pkcs1v15_signature_identical_to_cryptography(key1024):
    # PKCS#1 v1.5 tất định ⇒ hai bên phải cho ra cùng một chuỗi byte
    for _ in range(5):
        msg = os.urandom(50)
        assert sign(key1024, msg, "pkcs1v15") == _to_crypto(key1024).sign(msg, padding.PKCS1v15(), hashes.SHA256())
