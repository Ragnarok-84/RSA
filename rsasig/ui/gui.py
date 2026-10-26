"""Giao diện đồ hoạ Tkinter. Chỉ gọi API của rsasig.core / rsasig.attacks.

Chạy:  python -m rsasig gui
"""

from __future__ import annotations

import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from ..attacks.demos import DEMOS
from ..core.envelope import load_envelope, save_envelope, sign_file, verify_file
from ..core.keys import PrivateKey, generate_keypair, load_key, load_owner, save_key
from ..core.tiny import full_walkthrough

MONO = ("Consolas", 10)


def _output(parent: tk.Widget) -> ScrolledText:
    box = ScrolledText(parent, font=MONO, wrap="none", height=24)
    box.tag_configure("ok", foreground="#1a7f37")
    box.tag_configure("bad", foreground="#cf222e")
    return box


def _write(box: ScrolledText, text: str, clear: bool = True) -> None:
    if clear:
        box.delete("1.0", "end")
    for line in text.splitlines():
        tag = ""
        if "KHÔNG HỢP LỆ" in line or "[XX]" in line:
            tag = "bad"
        elif "HỢP LỆ" in line or "[OK]" in line:
            tag = "ok"
        box.insert("end", line + "\n", tag)
    box.see("1.0" if clear else "end")


def _run_bg(root: tk.Tk, work, done) -> None:
    """Chạy `work` ở luồng phụ để giao diện không bị treo, rồi gọi `done(kết quả)`."""
    def runner():
        try:
            result = work()
        except Exception as exc:  # hiển thị mọi lỗi cho người dùng
            result = exc
        root.after(0, lambda: done(result))
    threading.Thread(target=runner, daemon=True).start()


class App(ttk.Frame):
    def __init__(self, root: tk.Tk) -> None:
        super().__init__(root, padding=8)
        self.root = root
        root.title("Hệ chữ ký điện tử RSA — ký trên giá trị băm")
        root.geometry("1050x700")
        self.pack(fill="both", expand=True)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        nb.add(self._tab_tiny(nb), text="Bản thu nhỏ")
        nb.add(self._tab_keys(nb), text="Sinh khoá")
        nb.add(self._tab_sign(nb), text="Ký / Kiểm tra tệp")
        nb.add(self._tab_attacks(nb), text="Tấn công & phân tích")
        nb.add(self._tab_bench(nb), text="Hiệu năng")

    # -- Bản thu nhỏ -------------------------------------------------------

    def _tab_tiny(self, nb: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(nb, padding=8)
        form = ttk.Frame(f)
        form.pack(fill="x")
        self.t_p, self.t_q, self.t_e = tk.StringVar(value="61"), tk.StringVar(value="53"), tk.StringVar(value="17")
        self.t_msg, self.t_hash, self.t_tamper = tk.StringVar(value="HELLO"), tk.StringVar(), tk.StringVar()
        fields = [("p", self.t_p, 6), ("q", self.t_q, 6), ("e", self.t_e, 6),
                  ("Thông điệp", self.t_msg, 22), ("hoặc h =", self.t_hash, 8), ("Bản bị sửa", self.t_tamper, 18)]
        for i, (label, var, w) in enumerate(fields):
            ttk.Label(form, text=label).grid(row=0, column=2 * i, padx=(6, 2))
            ttk.Entry(form, textvariable=var, width=w).grid(row=0, column=2 * i + 1)
        ttk.Button(form, text="Chạy từng bước", command=self._run_tiny).grid(row=0, column=12, padx=8)
        self.tiny_out = _output(f)
        self.tiny_out.pack(fill="both", expand=True, pady=(8, 0))
        return f

    def _run_tiny(self) -> None:
        try:
            text = full_walkthrough(
                message=self.t_msg.get().encode(),
                hash_value=int(self.t_hash.get()) if self.t_hash.get().strip() else None,
                p=int(self.t_p.get()), q=int(self.t_q.get()), e=int(self.t_e.get()),
                tampered=self.t_tamper.get().encode() or None,
            )
        except ValueError as exc:
            messagebox.showerror("Tham số không hợp lệ", str(exc))
            return
        _write(self.tiny_out, text)

    # -- Sinh khoá -----------------------------------------------------------

    def _tab_keys(self, nb: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(nb, padding=8)
        form = ttk.Frame(f)
        form.pack(fill="x")
        self.k_bits = tk.StringVar(value="2048")
        self.k_name = tk.StringVar(value="Alice")
        self.k_out = tk.StringVar(value="keys/alice")
        ttk.Label(form, text="Số bit").grid(row=0, column=0)
        ttk.Combobox(form, textvariable=self.k_bits, values=["1024", "2048", "3072", "4096"], width=8).grid(row=0, column=1)
        ttk.Label(form, text="Chủ khoá").grid(row=0, column=2, padx=(10, 2))
        ttk.Entry(form, textvariable=self.k_name, width=14).grid(row=0, column=3)
        ttk.Label(form, text="Lưu tại").grid(row=0, column=4, padx=(10, 2))
        ttk.Entry(form, textvariable=self.k_out, width=30).grid(row=0, column=5)
        self.k_btn = ttk.Button(form, text="Sinh khoá", command=self._run_keygen)
        self.k_btn.grid(row=0, column=6, padx=8)
        self.key_out = _output(f)
        self.key_out.pack(fill="both", expand=True, pady=(8, 0))
        return f

    def _run_keygen(self) -> None:
        bits, name, out = int(self.k_bits.get()), self.k_name.get(), Path(self.k_out.get())
        self.k_btn.state(["disabled"])
        _write(self.key_out, f"Đang sinh khoá {bits} bit…")
        t0 = time.perf_counter()

        def done(key):
            self.k_btn.state(["!disabled"])
            if isinstance(key, Exception):
                messagebox.showerror("Lỗi", str(key))
                return
            out.parent.mkdir(parents=True, exist_ok=True)
            save_key(key, out.with_suffix(".priv.json"), name)
            save_key(key.public_key(), out.with_suffix(".pub.json"), name)
            _write(self.key_out, "\n".join([
                f"Sinh khoá xong sau {time.perf_counter() - t0:.2f} s",
                f"Chủ khoá     : {name}",
                f"Dấu vân tay  : {key.public_key().fingerprint()}",
                f"e            = {key.e}",
                f"n ({key.bits} bit) = {key.n:x}",
                f"p            = {key.p:x}",
                f"q            = {key.q:x}",
                "",
                f"Khoá bí mật    → {out.with_suffix('.priv.json')}  (GIỮ KÍN)",
                f"Khoá công khai → {out.with_suffix('.pub.json')}",
            ]))

        _run_bg(self.root, lambda: generate_keypair(bits), done)

    # -- Ký / kiểm tra tệp --------------------------------------------------------

    def _file_row(self, form, row, label, var, save=False):
        ttk.Label(form, text=label).grid(row=row, column=0, sticky="w")
        ttk.Entry(form, textvariable=var, width=70).grid(row=row, column=1, padx=4, pady=2)
        ask = filedialog.asksaveasfilename if save else filedialog.askopenfilename
        ttk.Button(form, text="…", width=3, command=lambda: var.set(ask() or var.get())).grid(row=row, column=2)

    def _tab_sign(self, nb: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(nb, padding=8)
        form = ttk.Frame(f)
        form.pack(fill="x")
        self.s_file = tk.StringVar(value="samples/hop_dong.txt")
        self.s_priv = tk.StringVar(value="keys/alice.priv.json")
        self.s_pub = tk.StringVar(value="keys/alice.pub.json")
        self.s_sig = tk.StringVar(value="")
        self.s_scheme = tk.StringVar(value="pss")
        self._file_row(form, 0, "Tệp dữ liệu", self.s_file)
        self._file_row(form, 1, "Khoá bí mật (ký)", self.s_priv)
        self._file_row(form, 2, "Khoá công khai (kiểm tra)", self.s_pub)
        self._file_row(form, 3, "Tệp chữ ký (để trống = <tệp>.sig.json)", self.s_sig)
        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=6)
        ttk.Radiobutton(bar, text="RSASSA-PSS", variable=self.s_scheme, value="pss").pack(side="left")
        ttk.Radiobutton(bar, text="RSASSA-PKCS1-v1_5", variable=self.s_scheme, value="pkcs1v15").pack(side="left", padx=8)
        ttk.Button(bar, text="Ký tệp", command=self._run_sign).pack(side="left", padx=12)
        ttk.Button(bar, text="Kiểm tra chữ ký", command=self._run_verify).pack(side="left")
        self.sign_out = _output(f)
        self.sign_out.pack(fill="both", expand=True)
        return f

    def _sig_path(self) -> str:
        return self.s_sig.get().strip() or f"{self.s_file.get()}.sig.json"

    def _run_sign(self) -> None:
        try:
            key = load_key(self.s_priv.get())
            if not isinstance(key, PrivateKey):
                raise ValueError("Cần khoá BÍ MẬT để ký")
            signer = load_owner(self.s_priv.get()) or "unknown"
            t0 = time.perf_counter()
            env = sign_file(key, self.s_file.get(), signer, self.s_scheme.get())
            dt = time.perf_counter() - t0
            save_envelope(env, self._sig_path())
        except (OSError, ValueError) as exc:
            messagebox.showerror("Không ký được", str(exc))
            return
        m = env["manifest"]
        _write(self.sign_out, "\n".join([
            f"Đã ký trong {dt * 1e3:.1f} ms → {self._sig_path()}",
            *(f"  {k:<16}: {v}" for k, v in m.items()),
            f"  {'signature':<16}: {env['signature']}",
        ]))

    def _run_verify(self) -> None:
        try:
            key = load_key(self.s_pub.get())
            if isinstance(key, PrivateKey):
                key = key.public_key()
            env = load_envelope(self._sig_path())
            result = verify_file(key, self.s_file.get(), env)
        except (OSError, ValueError, KeyError) as exc:
            messagebox.showerror("Không kiểm tra được", str(exc))
            return
        m = env["manifest"]
        _write(self.sign_out, "\n".join([
            f"Tệp      : {self.s_file.get()}",
            f"Người ký : {m['signer']}  lúc {m['signed_at']}  ({m['scheme']})",
            result.report(),
        ]))

    # -- Tấn công --------------------------------------------------------------

    def _tab_attacks(self, nb: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(nb, padding=8)
        bar = ttk.Frame(f)
        bar.pack(fill="x")
        for name in DEMOS:
            ttk.Button(bar, text=name, command=lambda n=name: self._run_attack(n)).pack(side="left", padx=2)
        self.att_out = _output(f)
        self.att_out.pack(fill="both", expand=True, pady=(8, 0))
        return f

    def _run_attack(self, name: str) -> None:
        _write(self.att_out, f"Đang chạy {name}…")

        def done(r):
            if isinstance(r, Exception):
                _write(self.att_out, f"Lỗi: {r}")
                return
            verdict = "đúng như phân tích" if r.as_expected else "KHÔNG như kỳ vọng"
            _write(self.att_out, f"{r.text()}\n\n[{verdict}]")

        _run_bg(self.root, DEMOS[name], done)

    # -- Hiệu năng ---------------------------------------------------------------

    def _tab_bench(self, nb: ttk.Notebook) -> ttk.Frame:
        f = ttk.Frame(nb, padding=8)
        ttk.Button(f, text="Đo nhanh (vài chục giây)", command=self._run_bench).pack(anchor="w")
        self.bench_out = _output(f)
        self.bench_out.pack(fill="both", expand=True, pady=(8, 0))
        return f

    def _run_bench(self) -> None:
        from ..benchmark import run_all

        _write(self.bench_out, "Đang đo…")
        _run_bg(self.root, lambda: run_all(quick=True), lambda text: _write(self.bench_out, str(text)))


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
