"""Hàm băm SHA-256 tự cài đặt theo chuẩn FIPS 180-4 (không dùng hashlib).

Cấu trúc Merkle–Damgård:
    1. Đệm (padding): thêm bit 1, các bit 0, rồi 64 bit độ dài thông điệp
       sao cho tổng độ dài là bội của 512 bit.
    2. Chia thành các khối 512 bit, mỗi khối qua hàm nén 64 vòng.
    3. Giá trị băm = 8 thanh ghi 32 bit (256 bit) sau khối cuối cùng.

API giống hashlib để dễ đối chiếu:
    h = SHA256(); h.update(b"abc"); h.hexdigest()
    sha256(b"abc").hexdigest()
"""

from __future__ import annotations

import struct

# Hằng số vòng K: 32 bit đầu phần thập phân của căn bậc ba 64 số nguyên tố đầu tiên
_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# Giá trị khởi tạo H0: 32 bit đầu phần thập phân của căn bậc hai 8 số nguyên tố đầu tiên
_H0 = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

_MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    """Quay phải x đi n bit trong thanh ghi 32 bit."""
    return ((x >> n) | (x << (32 - n))) & _MASK


def _compress(state: list[int], block: bytes) -> None:
    """Hàm nén: xử lý một khối 64 byte, cập nhật trực tiếp `state`."""
    # Lịch thông điệp W[0..63]
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        s0 = _rotr(w[t - 15], 7) ^ _rotr(w[t - 15], 18) ^ (w[t - 15] >> 3)
        s1 = _rotr(w[t - 2], 17) ^ _rotr(w[t - 2], 19) ^ (w[t - 2] >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _MASK)

    a, b, c, d, e, f, g, h = state
    for t in range(64):
        big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g)                    # Choose
        temp1 = (h + big_s1 + ch + _K[t] + w[t]) & _MASK
        big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)          # Majority
        temp2 = (big_s0 + maj) & _MASK
        h, g, f, e = g, f, e, (d + temp1) & _MASK
        d, c, b, a = c, b, a, (temp1 + temp2) & _MASK

    for i, v in enumerate((a, b, c, d, e, f, g, h)):
        state[i] = (state[i] + v) & _MASK


class SHA256:
    """Đối tượng băm hỗ trợ băm theo luồng (update nhiều lần) cho tệp lớn."""

    name = "sha256"
    digest_size = 32
    block_size = 64

    def __init__(self, data: bytes = b"") -> None:
        self._state = list(_H0)
        self._buffer = b""
        self._length = 0  # tổng số byte đã nạp
        if data:
            self.update(data)

    def update(self, data: bytes) -> "SHA256":
        data = bytes(data)
        self._length += len(data)
        buf = self._buffer + data
        full = len(buf) - len(buf) % 64
        for i in range(0, full, 64):
            _compress(self._state, buf[i : i + 64])
        self._buffer = buf[full:]
        return self

    def copy(self) -> "SHA256":
        clone = SHA256()
        clone._state = self._state[:]
        clone._buffer = self._buffer
        clone._length = self._length
        return clone

    def digest(self) -> bytes:
        # Đệm trên bản sao để đối tượng gốc vẫn có thể update tiếp
        state = self._state[:]
        bit_len = (self._length * 8) & 0xFFFFFFFFFFFFFFFF
        padding = b"\x80" + b"\x00" * ((55 - self._length) % 64) + struct.pack(">Q", bit_len)
        tail = self._buffer + padding
        for i in range(0, len(tail), 64):
            _compress(state, tail[i : i + 64])
        return struct.pack(">8I", *state)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes = b"") -> SHA256:
    return SHA256(data)


def sha256_file(path, chunk_size: int = 64 * 1024) -> bytes:
    """Băm một tệp theo từng khối để không phải nạp toàn bộ vào bộ nhớ."""
    h = SHA256()
    with open(path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            h.update(chunk)
    return h.digest()
