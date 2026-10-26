"""Giao diện dòng lệnh. Chỉ gọi API của rsasig.core / rsasig.attacks, không chứa thuật toán.

Ví dụ:
    python -m rsasig                       # menu tương tác
    python -m rsasig tiny --message "HELLO"
    python -m rsasig tiny --hash 65        # khớp ví dụ trên lớp
    python -m rsasig keygen --bits 2048 --name Alice --out keys/alice
    python -m rsasig sign   --key keys/alice.priv.json --file samples/hop_dong.txt --signer Alice
    python -m rsasig verify --pub keys/alice.pub.json  --file samples/hop_dong.txt
    python -m rsasig attack all
    python -m rsasig bench --quick
    python -m rsasig gui
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from ..attacks.demos import DEMOS
from ..core.envelope import load_envelope, save_envelope, sign_file, verify_file
from ..core.keys import PrivateKey, PublicKey, generate_keypair, load_key, load_owner, save_key
from ..core.sha256 import sha256_file
from ..core.tiny import full_walkthrough


def _enable_utf8() -> None:
    # Console Windows mặc định không phải UTF-8 → tiếng Việt bị lỗi
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass


# ---------------------------------------------------------------------------
# Các lệnh
# ---------------------------------------------------------------------------


def cmd_tiny(args: argparse.Namespace) -> int:
    print(full_walkthrough(
        message=args.message.encode() if args.message is not None else None,
        hash_value=args.hash,
        p=args.p, q=args.q, e=args.e,
        tampered=args.tamper.encode() if args.tamper else None,
    ))
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    print(f"Đang sinh khoá RSA {args.bits} bit (Miller–Rabin, e = 65537)…")
    t0 = time.perf_counter()
    key = generate_keypair(args.bits)
    dt = time.perf_counter() - t0
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = out.with_suffix(".priv.json"), out.with_suffix(".pub.json")
    save_key(key, priv_path, args.name)
    save_key(key.public_key(), pub_path, args.name)
    print(f"Xong sau {dt:.2f} s")
    print(f"  n (bit)        : {key.bits}")
    print(f"  dấu vân tay    : {key.public_key().fingerprint()}")
    print(f"  khoá bí mật    : {priv_path}   (GIỮ KÍN)")
    print(f"  khoá công khai : {pub_path}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    key = load_key(args.key)
    if not isinstance(key, PrivateKey):
        print("Lỗi: cần tệp khoá BÍ MẬT để ký", file=sys.stderr)
        return 2
    signer = args.signer or load_owner(args.key) or "unknown"
    t0 = time.perf_counter()
    env = sign_file(key, args.file, signer, args.scheme)
    dt = time.perf_counter() - t0
    out = args.out or f"{args.file}.sig.json"
    save_envelope(env, out)
    m = env["manifest"]
    print(f"Đã ký '{m['file_name']}' ({m['file_size']} byte) trong {dt * 1e3:.1f} ms")
    print(f"  SHA-256   : {m['file_sha256']}")
    print(f"  người ký  : {m['signer']}  — khoá {m['key_fingerprint']}")
    print(f"  lược đồ   : {m['scheme']}")
    print(f"  thời điểm : {m['signed_at']}")
    print(f"  chữ ký    : {env['signature'][:64]}…")
    print(f"  lưu tại   : {out}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    key = load_key(args.pub)
    if isinstance(key, PrivateKey):
        key = key.public_key()
    sig_path = args.sig or f"{args.file}.sig.json"
    env = load_envelope(sig_path)
    m = env["manifest"]
    print(f"Kiểm tra '{args.file}' với chữ ký '{sig_path}'")
    print(f"  người ký khai báo: {m['signer']} lúc {m['signed_at']} ({m['scheme']})")
    result = verify_file(key, args.file, env)
    print(result.report())
    return 0 if result.valid else 1


def cmd_hash(args: argparse.Namespace) -> int:
    import hashlib  # chỉ để đối chiếu

    ours = sha256_file(args.file).hex()
    ref = hashlib.sha256(Path(args.file).read_bytes()).hexdigest()
    print(f"SHA-256 (tự cài đặt): {ours}")
    print(f"SHA-256 (hashlib)   : {ref}")
    print("=> KHỚP" if ours == ref else "=> KHÔNG KHỚP")
    return 0 if ours == ref else 1


def cmd_attack(args: argparse.Namespace) -> int:
    names = list(DEMOS) if args.name == "all" else [args.name]
    for name in names:
        result = DEMOS[name]()
        print(result.text())
        print(f"[{'đúng như phân tích' if result.as_expected else 'KHÔNG như kỳ vọng'}]\n")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from ..benchmark import run_all

    print(run_all(quick=args.quick))
    return 0


def cmd_gui(_: argparse.Namespace) -> int:
    from .gui import main as gui_main

    gui_main()
    return 0


def cmd_menu(_: argparse.Namespace) -> int:
    from .menu import run_menu

    run_menu()
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="rsasig", description="Hệ chữ ký điện tử RSA trên giá trị băm SHA-256")
    sub = ap.add_subparsers(dest="command")

    p = sub.add_parser("tiny", help="Bản thu nhỏ: in từng bước sinh khoá / ký / kiểm tra")
    p.add_argument("--message", "-m", help="thông điệp cần ký (mặc định 'HELLO')")
    p.add_argument("--hash", type=int, help="ký trực tiếp giá trị băm h (số nguyên < n)")
    p.add_argument("--tamper", help="thông điệp bị sửa để thử kiểm tra")
    p.add_argument("-p", type=int, default=61)
    p.add_argument("-q", type=int, default=53)
    p.add_argument("-e", type=int, default=17)
    p.set_defaults(func=cmd_tiny)

    p = sub.add_parser("keygen", help="Sinh cặp khoá RSA đầy đủ")
    p.add_argument("--bits", type=int, default=2048)
    p.add_argument("--name", default=None, help="tên chủ khoá")
    p.add_argument("--out", required=True, help="tiền tố tệp, ví dụ keys/alice")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="Ký một tệp")
    p.add_argument("--key", required=True, help="tệp khoá bí mật .priv.json")
    p.add_argument("--file", required=True)
    p.add_argument("--signer", help="tên người ký (mặc định lấy từ tệp khoá)")
    p.add_argument("--scheme", choices=("pss", "pkcs1v15"), default="pss")
    p.add_argument("--out", help="tệp chữ ký (mặc định <file>.sig.json)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="Kiểm tra chữ ký của một tệp")
    p.add_argument("--pub", required=True, help="tệp khoá công khai .pub.json")
    p.add_argument("--file", required=True)
    p.add_argument("--sig", help="tệp chữ ký (mặc định <file>.sig.json)")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("hash", help="Băm SHA-256 một tệp và đối chiếu với hashlib")
    p.add_argument("file")
    p.set_defaults(func=cmd_hash)

    p = sub.add_parser("attack", help="Chạy kịch bản tấn công / phân tích an toàn")
    p.add_argument("name", choices=["all", *DEMOS])
    p.set_defaults(func=cmd_attack)

    p = sub.add_parser("bench", help="Đo thời gian theo kích thước dữ liệu / khoá")
    p.add_argument("--quick", action="store_true", help="bỏ các cấu hình chậm (3072 bit, 1 MB)")
    p.set_defaults(func=cmd_bench)

    sub.add_parser("gui", help="Mở giao diện đồ hoạ (Tkinter)").set_defaults(func=cmd_gui)
    sub.add_parser("menu", help="Menu tương tác").set_defaults(func=cmd_menu)
    return ap


def main(argv: list[str] | None = None) -> int:
    _enable_utf8()
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        return cmd_menu(args)
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Lỗi: {exc}", file=sys.stderr)
        return 2
