"""Ký / kiểm tra tệp thật (văn bản, ảnh, PDF…) với "phong bì chữ ký" JSON.

Chữ ký không chỉ phủ lên giá trị băm của tệp mà phủ lên cả một bản kê khai
(manifest) gồm: SHA-256 của tệp, tên người ký, dấu vân tay khoá công khai,
thời điểm ký và lược đồ. Nhờ vậy:
  * sửa tệp            → băm thay đổi → kiểm tra thất bại (toàn vẹn);
  * sửa tên người ký / thời điểm → manifest thay đổi → chữ ký sai;
  * chữ ký gắn với một khoá cụ thể (fingerprint) — cơ sở của tính không chối bỏ.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .keys import PrivateKey, PublicKey
from .pkcs1 import SCHEMES, sign, verify
from .sha256 import sha256_file

FORMAT_VERSION = 1


def canonical_json(data: dict) -> bytes:
    """Mã hoá JSON chuẩn tắc (sắp xếp khoá, không khoảng trắng) để ký/kiểm tra nhất quán."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def build_manifest(path: str | Path, key: PublicKey, signer: str, scheme: str) -> dict:
    path = Path(path)
    return {
        "version": FORMAT_VERSION,
        "file_name": path.name,
        "file_size": path.stat().st_size,
        "file_sha256": sha256_file(path).hex(),
        "signer": signer,
        "key_fingerprint": key.fingerprint(),
        "key_bits": key.bits,
        "scheme": f"RSASSA-{'PSS' if scheme == 'pss' else 'PKCS1-v1_5'}-SHA256",
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def sign_file(key: PrivateKey, path: str | Path, signer: str, scheme: str = "pss") -> dict:
    if scheme not in SCHEMES:
        raise ValueError(f"scheme phải là một trong {SCHEMES}")
    manifest = build_manifest(path, key.public_key(), signer, scheme)
    signature = sign(key, canonical_json(manifest), scheme)
    return {"manifest": manifest, "signature": signature.hex()}


def _scheme_id(manifest: dict) -> str:
    return "pss" if "PSS" in manifest.get("scheme", "") else "pkcs1v15"


@dataclass
class VerifyResult:
    valid: bool
    checks: list[tuple[str, bool]] = field(default_factory=list)

    def report(self) -> str:
        lines = [f"  [{'OK' if ok else 'XX'}] {name}" for name, ok in self.checks]
        lines.append("=> CHỮ KÝ HỢP LỆ" if self.valid else "=> CHỮ KÝ KHÔNG HỢP LỆ")
        return "\n".join(lines)


def verify_file(key: PublicKey, path: str | Path, envelope: dict) -> VerifyResult:
    manifest = envelope["manifest"]
    checks: list[tuple[str, bool]] = []

    actual_hash = sha256_file(path).hex()
    checks.append(("Giá trị băm của tệp khớp với manifest (toàn vẹn)", actual_hash == manifest["file_sha256"]))
    checks.append(("Dấu vân tay khoá công khai khớp với khoá ghi trong manifest", key.fingerprint() == manifest["key_fingerprint"]))
    try:
        sig_ok = verify(key, canonical_json(manifest), bytes.fromhex(envelope["signature"]), _scheme_id(manifest))
    except ValueError:
        sig_ok = False
    checks.append(("Chữ ký RSA trên manifest đúng với khoá công khai (xác thực nguồn gốc)", sig_ok))

    return VerifyResult(valid=all(ok for _, ok in checks), checks=checks)


def save_envelope(envelope: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")


def load_envelope(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
