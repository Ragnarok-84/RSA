"""SHA-256 và HMAC-SHA256: test vector chuẩn (NIST FIPS 180-4 / CAVP, RFC 4231) + đối chiếu hashlib/hmac."""

import hashlib
import hmac
import os

import pytest

from rsasig.core.hmac_sha256 import hmac_sha256
from rsasig.core.sha256 import SHA256, sha256, sha256_file

# Ví dụ trong tài liệu NIST (FIPS 180-4, "SHA256.pdf" examples) và CAVP ShortMsg
NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
]


@pytest.mark.parametrize("msg,expected", NIST_VECTORS)
def test_sha256_nist_vectors(msg, expected):
    assert sha256(msg).hexdigest() == expected


@pytest.mark.slow
def test_sha256_million_a():
    h = SHA256()
    for _ in range(1000):
        h.update(b"a" * 1000)
    assert h.hexdigest() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


@pytest.mark.parametrize("length", [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 4097])
def test_sha256_padding_boundaries_vs_hashlib(length):
    data = os.urandom(length)
    assert sha256(data).digest() == hashlib.sha256(data).digest()


def test_sha256_streaming_equals_one_shot():
    data = os.urandom(5000)
    h = SHA256()
    for i in range(0, len(data), 37):  # nạp từng mẩu lẻ
        h.update(data[i : i + 37])
    assert h.digest() == sha256(data).digest()
    # digest() không làm hỏng trạng thái: vẫn update tiếp được
    h.update(b"more")
    assert h.digest() == hashlib.sha256(data + b"more").digest()


def test_sha256_file(tmp_path):
    p = tmp_path / "x.bin"
    data = os.urandom(200_000)
    p.write_bytes(data)
    assert sha256_file(p) == hashlib.sha256(data).digest()


def test_avalanche_effect():
    a = int.from_bytes(sha256(b"HELLO").digest(), "big")
    b = int.from_bytes(sha256(b"HELLo").digest(), "big")
    assert 90 < bin(a ^ b).count("1") < 166  # ~ một nửa số bit thay đổi


# RFC 4231 — test case 1, 2, 6 (khoá dài hơn khối)
RFC4231 = [
    (b"\x0b" * 20, b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
]


@pytest.mark.parametrize("key,msg,expected", RFC4231)
def test_hmac_rfc4231(key, msg, expected):
    assert hmac_sha256(key, msg).hex() == expected


def test_hmac_vs_stdlib():
    for klen in (0, 16, 64, 65, 200):
        key, msg = os.urandom(klen), os.urandom(300)
        assert hmac_sha256(key, msg) == hmac.new(key, msg, hashlib.sha256).digest()
