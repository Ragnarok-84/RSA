"""Chứng thư số thu gọn (mini-certificate) — minh hoạ hạ tầng khoá công khai (PKI).

Chữ ký RSA chỉ chứng minh "người giữ khoá bí mật tương ứng với (n, e) đã ký".
Để biết (n, e) thực sự là của Alice, cần một bên thứ ba tin cậy (CA) ký lên
cặp (tên Alice, khoá công khai của Alice, thời hạn). Đây là ý tưởng của X.509,
ở đây lược giản thành JSON.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .envelope import canonical_json
from .keys import PrivateKey, PublicKey
from .pkcs1 import sign, verify


def issue_certificate(
    ca_key: PrivateKey,
    ca_name: str,
    subject: str,
    subject_key: PublicKey,
    valid_days: int = 365,
    serial: int = 1,
) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    tbs = {  # "to-be-signed" — phần nội dung được CA ký
        "serial": serial,
        "issuer": ca_name,
        "subject": subject,
        "subject_public_key": subject_key.to_dict(),
        "subject_key_fingerprint": subject_key.fingerprint(),
        "not_before": now.isoformat(),
        "not_after": (now + timedelta(days=valid_days)).isoformat(),
        "signature_algorithm": "RSASSA-PSS-SHA256",
    }
    signature = sign(ca_key, canonical_json(tbs), "pss")
    return {"tbs": tbs, "signature": signature.hex()}


def verify_certificate(
    ca_key: PublicKey, cert: dict, at: datetime | None = None, revoked_serials: set[int] | None = None
) -> tuple[bool, str]:
    """Kiểm tra chứng thư: chữ ký CA, thời hạn hiệu lực, danh sách thu hồi."""
    tbs = cert["tbs"]
    try:
        ok = verify(ca_key, canonical_json(tbs), bytes.fromhex(cert["signature"]), "pss")
    except ValueError:
        ok = False
    if not ok:
        return False, "Chữ ký của CA trên chứng thư không hợp lệ (chứng thư giả/bị sửa)"
    at = at or datetime.now(timezone.utc)
    if not (datetime.fromisoformat(tbs["not_before"]) <= at <= datetime.fromisoformat(tbs["not_after"])):
        return False, "Chứng thư đã hết hạn hoặc chưa có hiệu lực"
    if revoked_serials and tbs["serial"] in revoked_serials:
        return False, "Chứng thư đã bị thu hồi (CRL)"
    return True, f"Chứng thư hợp lệ: khoá {tbs['subject_key_fingerprint']} thuộc về '{tbs['subject']}'"


def subject_key(cert: dict) -> PublicKey:
    return PublicKey.from_dict(cert["tbs"]["subject_public_key"])
