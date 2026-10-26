"""HMAC-SHA256 (RFC 2104) dựa trên SHA-256 tự cài đặt.

Chỉ dùng trong phần so sánh: HMAC cung cấp tính toàn vẹn và xác thực giữa hai
bên chia sẻ khoá bí mật, nhưng KHÔNG có tính không chối bỏ — vì người nhận cũng
có khoá nên cũng tạo được thẻ HMAC hợp lệ.
"""

from __future__ import annotations

from .sha256 import SHA256, sha256

_BLOCK = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC(K, m) = H((K' ⊕ opad) ‖ H((K' ⊕ ipad) ‖ m))."""
    if len(key) > _BLOCK:
        key = sha256(key).digest()
    key = key.ljust(_BLOCK, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    inner = SHA256(ipad).update(message).digest()
    return SHA256(opad).update(inner).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """So sánh hai chuỗi byte trong thời gian không phụ thuộc vị trí khác nhau."""
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
