"""Menu tương tác trên terminal — tiện cho demo trực tiếp trên lớp."""

from __future__ import annotations

from argparse import Namespace

from ..attacks.demos import DEMOS
from . import cli

MENU = """
================ HỆ CHỮ KÝ ĐIỆN TỬ RSA ================
 1. Bản thu nhỏ: tính từng bước (sinh khoá, ký, kiểm tra)
 2. Sinh cặp khoá RSA đầy đủ
 3. Ký một tệp
 4. Kiểm tra chữ ký của một tệp
 5. Băm SHA-256 một tệp (đối chiếu hashlib)
 6. Kịch bản tấn công / phân tích an toàn
 7. Đo hiệu năng (nhanh)
 8. Mở giao diện đồ hoạ
 0. Thoát
========================================================"""


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def _ask_int(prompt: str, default: int | None = None) -> int | None:
    raw = _ask(prompt, None if default is None else str(default))
    return int(raw) if raw else None


def _tiny() -> None:
    p = _ask_int("p", 61)
    q = _ask_int("q", 53)
    e = _ask_int("e", 17)
    mode = _ask("Ký (1) thông điệp hay (2) giá trị băm cho trước", "1")
    if mode == "2":
        cli.cmd_tiny(Namespace(message=None, hash=_ask_int("h"), p=p, q=q, e=e, tamper=None))
    else:
        msg = _ask("Thông điệp", "HELLO")
        tamper = _ask("Thông điệp bị sửa để thử (bỏ trống nếu không)", "")
        cli.cmd_tiny(Namespace(message=msg, hash=None, p=p, q=q, e=e, tamper=tamper or None))


def _attacks() -> None:
    names = list(DEMOS)
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name}")
    print("  a. chạy tất cả")
    choice = _ask("Chọn", "a")
    name = "all" if choice == "a" else names[int(choice) - 1]
    cli.cmd_attack(Namespace(name=name))


def run_menu() -> None:
    actions = {
        "1": _tiny,
        "2": lambda: cli.cmd_keygen(Namespace(
            bits=int(_ask("Số bit", "2048")), name=_ask("Tên chủ khoá", "Alice"),
            out=_ask("Tiền tố tệp", "keys/alice"))),
        "3": lambda: cli.cmd_sign(Namespace(
            key=_ask("Khoá bí mật", "keys/alice.priv.json"), file=_ask("Tệp cần ký", "samples/hop_dong.txt"),
            signer=None, scheme=_ask("Lược đồ (pss/pkcs1v15)", "pss"), out=None)),
        "4": lambda: cli.cmd_verify(Namespace(
            pub=_ask("Khoá công khai", "keys/alice.pub.json"), file=_ask("Tệp", "samples/hop_dong.txt"), sig=None)),
        "5": lambda: cli.cmd_hash(Namespace(file=_ask("Tệp", "samples/hop_dong.txt"))),
        "6": _attacks,
        "7": lambda: cli.cmd_bench(Namespace(quick=True)),
        "8": lambda: cli.cmd_gui(Namespace()),
    }
    while True:
        print(MENU)
        try:
            choice = input("Chọn chức năng: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "0":
            return
        action = actions.get(choice)
        if not action:
            print("Lựa chọn không hợp lệ")
            continue
        try:
            action()
        except (FileNotFoundError, ValueError, IndexError) as exc:
            print(f"Lỗi: {exc}")
        except KeyboardInterrupt:
            print("\n(huỷ)")
