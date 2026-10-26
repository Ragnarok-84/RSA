"""Bản đầy đủ: RSASSA-PKCS1-v1_5 và RSASSA-PSS với SHA-256.

Test tự viết: ký đúng / sửa thông điệp / sửa chữ ký / sai khoá / trường hợp biên.
Đối chiếu với thư viện chuẩn nằm ở test_crosscheck_cryptography.py.
"""

import os

import pytest

from rsasig.core.keys import generate_keypair
from rsasig.core.math_utils import i2osp, os2ip
from rsasig.core.pkcs1 import (
    SHA256_DIGEST_INFO_PREFIX,
    emsa_pkcs1_v15_encode,
    sign,
    verify,
)
from rsasig.core.rsa_primitives import rsasp1, rsavp1

SCHEMES = ["pkcs1v15", "pss"]
MSG = "Tôi, Alice, đồng ý thanh toán 1.200.000.000 VND cho Bob.".encode()


# ---------------------------------------------------------------- tự viết


def test_keypair_properties(key1024):
    k = key1024
    assert k.bits == 1024 and k.n == k.p * k.q
    assert (k.e * k.d) % ((k.p - 1) * (k.q - 1)) == 1
    assert k.dp == k.d % (k.p - 1) and k.dq == k.d % (k.q - 1)
    assert (k.q * k.qinv) % k.p == 1


def test_crt_equals_plain(key1024):
    m = os2ip(os.urandom(100))
    assert rsasp1(key1024, m, use_crt=True) == rsasp1(key1024, m, use_crt=False)
    assert rsavp1(key1024.public_key(), rsasp1(key1024, m)) == m


@pytest.mark.parametrize("scheme", SCHEMES)
def test_sign_verify_roundtrip(key1024, scheme):
    sig = sign(key1024, MSG, scheme)
    assert len(sig) == 128
    assert verify(key1024.public_key(), MSG, sig, scheme)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_tampered_message_rejected(key1024, scheme):
    sig = sign(key1024, MSG, scheme)
    assert not verify(key1024.public_key(), MSG.replace(b"1.200", b"9.200"), sig, scheme)


@pytest.mark.parametrize("scheme", SCHEMES)
def test_tampered_signature_rejected(key1024, scheme):
    sig = bytearray(sign(key1024, MSG, scheme))
    for pos in (0, 64, 127):
        bad = bytearray(sig)
        bad[pos] ^= 0x01
        assert not verify(key1024.public_key(), MSG, bytes(bad), scheme)
    assert not verify(key1024.public_key(), MSG, bytes(sig[:-1]), scheme)  # sai độ dài


@pytest.mark.parametrize("scheme", SCHEMES)
def test_wrong_public_key_rejected(key1024, other_key, scheme):
    sig = sign(key1024, MSG, scheme)
    assert not verify(other_key.public_key(), MSG, sig, scheme)


def test_pkcs1v15_is_deterministic_pss_is_randomized(key1024):
    assert sign(key1024, MSG, "pkcs1v15") == sign(key1024, MSG, "pkcs1v15")
    assert sign(key1024, MSG, "pss") != sign(key1024, MSG, "pss")


def test_pkcs1v15_encoding_layout():
    digest = bytes(range(32))
    em = emsa_pkcs1_v15_encode(digest, 256)
    assert em[:2] == b"\x00\x01"
    # |T| = 19 (DigestInfo) + 32 = 51 ⇒ |PS| = 256 - 51 - 3 = 202
    assert em[2:204] == b"\xff" * 202
    assert em[204:205] == b"\x00"
    assert em[205:] == SHA256_DIGEST_INFO_PREFIX + digest


def test_signature_value_out_of_range(key1024):
    pub = key1024.public_key()
    assert not verify(pub, MSG, i2osp(pub.n, 128), "pss")
    assert not verify(pub, MSG, i2osp(pub.n, 128), "pkcs1v15")


@pytest.mark.slow
@pytest.mark.parametrize("scheme", SCHEMES)
def test_rsa2048(key2048, scheme):
    sig = sign(key2048, MSG, scheme)
    assert len(sig) == 256 and verify(key2048.public_key(), MSG, sig, scheme)


@pytest.mark.parametrize("bits", [1023, 1025])
def test_odd_modulus_sizes(bits):
    # PSS có trường hợp biên khi (bit của n - 1) chia hết cho 8
    key = generate_keypair(bits)
    for scheme in SCHEMES:
        assert verify(key.public_key(), MSG, sign(key, MSG, scheme), scheme)
