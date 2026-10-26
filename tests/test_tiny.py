"""Bản thu nhỏ: phải tái hiện đúng ví dụ tính tay trong báo cáo (docs/vi-du-tinh-tay.md)."""

import pytest

from rsasig.core.tiny import TinyRSA, full_walkthrough, tiny_hash


def test_textbook_key():
    rsa = TinyRSA(61, 53, 17)
    assert rsa.n == 3233
    assert rsa.key.d == 2753


def test_textbook_sign_hash_65():
    # Ví dụ kinh điển: h = 65 ⇒ s = 65^2753 mod 3233 = 588, kiểm tra 588^17 mod 3233 = 65
    rsa = TinyRSA()
    s = rsa.sign_hash(65)
    assert s == 588
    assert rsa.verify_hash(65, s)
    assert not rsa.verify_hash(66, s)


def test_hand_example_hello():
    # Số liệu trong docs/vi-du-tinh-tay.md
    rsa = TinyRSA()
    assert tiny_hash(b"HELLO", rsa.n) == 820
    s = rsa.sign(b"HELLO")
    assert s == 1627
    assert rsa.verify(b"HELLO", s)
    assert not rsa.verify(b"HELLo", s)


def test_all_hash_values_roundtrip():
    rsa = TinyRSA(11, 17, 7)  # n = 187
    for h in range(rsa.n):
        assert rsa.verify_hash(h, rsa.sign_hash(h))


def test_invalid_parameters():
    with pytest.raises(ValueError):
        TinyRSA(61, 61, 17)        # p = q
    with pytest.raises(ValueError):
        TinyRSA(60, 53, 17)        # p không nguyên tố
    with pytest.raises(ValueError):
        TinyRSA(61, 53, 15)        # gcd(15, 3120) ≠ 1


def test_walkthrough_mentions_every_step():
    text = full_walkthrough(b"HELLO", tampered=b"HELLo")
    for needle in ("Miller–Rabin", "Euclid mở rộng", "d = -367 mod 3120 = 2753",
                   "s = 1627", "CHỮ KÝ HỢP LỆ", "CHỮ KÝ KHÔNG HỢP LỆ"):
        assert needle in text
