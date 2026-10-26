"""Các kịch bản tấn công / phân tích an toàn cho hệ chữ ký RSA.

Mỗi hàm demo_* trả về DemoResult gồm tiêu đề, các dòng giải thích và cờ
`as_expected` (kết quả khớp với phân tích lý thuyết) — để kiểm thử tự động và để
giao diện in ra khi thuyết trình.

    1. tamper            — sửa thông điệp sau khi ký bị phát hiện (toàn vẹn)
    2. existential       — giả mạo tồn tại với RSA "thô" không băm
    3. multiplicative    — giả mạo nhờ tính chất nhân của RSA thô
    4. tiny_collision    — va chạm băm trên bản thu nhỏ ⇒ chuyển chữ ký
    5. key_substitution  — kẻ đứng giữa thay khoá công khai; CA/chứng thư ngăn chặn
    6. repudiation       — HMAC không có tính không chối bỏ, chữ ký RSA thì có
    7. factoring         — n nhỏ bị phân tích bằng Pollard rho ⇒ lộ khoá bí mật
    8. crt_fault         — tấn công lỗi (Bellcore) lên ký CRT ⇒ phân tích được n
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

from ..core.certificate import issue_certificate, subject_key, verify_certificate
from ..core.hmac_sha256 import hmac_sha256
from ..core.keys import PrivateKey, generate_keypair, key_from_primes
from ..core.math_utils import gcd, i2osp, mod_inverse, mod_pow, os2ip, random_prime
from ..core.pkcs1 import emsa_pkcs1_v15_encode, sign, verify
from ..core.rsa_primitives import rsasp1, rsavp1
from ..core.sha256 import sha256
from ..core.tiny import TinyRSA, tiny_hash

DEMO_KEY_BITS = 1024  # đủ an toàn cho minh hoạ, sinh khoá nhanh


@dataclass
class DemoResult:
    title: str
    as_expected: bool
    lines: list[str] = field(default_factory=list)

    def add(self, text: str = "") -> None:
        self.lines.append(text)

    def text(self) -> str:
        return "\n".join([f"### {self.title}", *self.lines])


def _short(x: int | bytes, width: int = 24) -> str:
    s = x.hex() if isinstance(x, bytes) else str(x)
    return s if len(s) <= width else f"{s[:width // 2]}…{s[-width // 2:]} ({len(s)} ký tự)"


# ---------------------------------------------------------------------------
# 1. Phát hiện sửa đổi
# ---------------------------------------------------------------------------


def demo_tamper(key: PrivateKey | None = None) -> DemoResult:
    key = key or generate_keypair(DEMO_KEY_BITS)
    pub = key.public_key()
    r = DemoResult("Sửa nội dung sau khi ký", as_expected=False)
    original = "Hợp đồng: Alice bán cho Bob 100 cổ phiếu giá 50.000 VND.".encode()
    forged = "Hợp đồng: Alice bán cho Bob 100 cổ phiếu giá 5.000 VND.".encode()
    sig = sign(key, original)
    r.add(f"Alice ký: {original.decode()}")
    r.add(f"  SHA-256 = {sha256(original).hexdigest()}")
    r.add(f"Kẻ tấn công sửa thành: {forged.decode()}")
    r.add(f"  SHA-256 = {sha256(forged).hexdigest()}")
    ok_orig = verify(pub, original, sig)
    ok_forged = verify(pub, forged, sig)
    r.add(f"Kiểm tra bản gốc     : {'HỢP LỆ' if ok_orig else 'SAI'}")
    r.add(f"Kiểm tra bản bị sửa  : {'HỢP LỆ' if ok_forged else 'SAI'}")
    r.as_expected = ok_orig and not ok_forged
    r.add("Kết luận: chỉ đổi 1 ký tự, giá trị băm thay đổi hoàn toàn (hiệu ứng thác lũ)")
    r.add("⇒ chữ ký cũ không còn khớp. Chữ ký bảo đảm TÍNH TOÀN VẸN.")
    return r


# ---------------------------------------------------------------------------
# 2 & 3. RSA "thô" (ký trực tiếp, không băm, không đệm)
# ---------------------------------------------------------------------------


def demo_existential_forgery(key: PrivateKey | None = None) -> DemoResult:
    key = key or generate_keypair(DEMO_KEY_BITS)
    pub = key.public_key()
    r = DemoResult("Giả mạo tồn tại với RSA thô (không băm)", as_expected=False)
    r.add("Nếu chữ ký là s = m^d mod n trên chính thông điệp m (không băm):")
    s = secrets.randbelow(pub.n - 2) + 2
    m = rsavp1(pub, s)
    r.add(f"  Kẻ tấn công chọn ngẫu nhiên s = {_short(s)}")
    r.add(f"  rồi tính m = s^e mod n      = {_short(m)}")
    ok_raw = rsavp1(pub, s) == m
    r.add(f"  Bộ kiểm tra RSA thô: s^e mod n == m ? {'ĐÚNG ⇒ (m, s) là cặp hợp lệ!' if ok_raw else 'sai'}")
    r.add("  Kẻ tấn công không có d nhưng vẫn tạo được một cặp (thông điệp, chữ ký) hợp lệ.")
    r.add("  (m là chuỗi vô nghĩa, nhưng với thông điệp ngắn/có cấu trúc thì rất nguy hiểm.)")
    r.add("Với lược đồ ký trên giá trị băm (PSS / PKCS#1 v1.5):")
    sig = i2osp(s, pub.size_bytes)
    ok_hashed = verify(pub, i2osp(m, pub.size_bytes), sig)
    r.add(f"  Kiểm tra chữ ký s trên thông điệp m: {'HỢP LỆ' if ok_hashed else 'SAI'}")
    r.add("  Muốn giả mạo, kẻ tấn công phải tìm M sao cho Encode(H(M)) = s^e mod n")
    r.add("  ⇒ phải tìm tiền ảnh của SHA-256 — bất khả thi (2^256 phép thử).")
    r.as_expected = ok_raw and not ok_hashed
    return r


def demo_multiplicative(key: PrivateKey | None = None) -> DemoResult:
    key = key or generate_keypair(DEMO_KEY_BITS)
    pub = key.public_key()
    r = DemoResult("Giả mạo nhờ tính chất nhân của RSA thô", as_expected=False)
    m1, m2 = 1_000, 1_000_000
    s1, s2 = rsasp1(key, m1), rsasp1(key, m2)
    r.add(f"Alice (ký thô) đồng ý ký hai thông điệp vô hại: m1 = {m1}, m2 = {m2}")
    r.add(f"  s1 = {_short(s1)}")
    r.add(f"  s2 = {_short(s2)}")
    m_forged = m1 * m2 % pub.n
    s_forged = s1 * s2 % pub.n
    r.add(f"Kẻ tấn công nhân lại: m = m1*m2 = {m_forged}, s = s1*s2 mod n")
    ok = rsavp1(pub, s_forged) == m_forged
    r.add(f"  s^e mod n == m1*m2 ? {'ĐÚNG ⇒ có chữ ký trên số tiền ' + str(m_forged) + ' mà Alice chưa từng ký!' if ok else 'sai'}")
    r.add("  Vì (s1*s2)^e = s1^e * s2^e = m1*m2 (mod n).")
    msg1, msg2 = str(m1).encode(), str(m2).encode()
    sig1 = sign(key, msg1, "pkcs1v15")
    sig2 = sign(key, msg2, "pkcs1v15")
    forged = i2osp(os2ip(sig1) * os2ip(sig2) % pub.n, pub.size_bytes)
    ok_hashed = verify(pub, str(m_forged).encode(), forged, "pkcs1v15")
    r.add(f"Lặp lại với chữ ký trên giá trị băm (PKCS#1 v1.5): {'HỢP LỆ' if ok_hashed else 'SAI'}")
    r.add("  H(m1)·H(m2) ≠ H(m1·m2) và khối đệm không còn đúng cấu trúc ⇒ tính chất nhân bị phá vỡ.")
    r.as_expected = ok and not ok_hashed
    return r


# ---------------------------------------------------------------------------
# 4. Va chạm băm trên bản thu nhỏ
# ---------------------------------------------------------------------------


def demo_tiny_collision(max_tries: int = 5000) -> DemoResult:
    tiny = TinyRSA()
    n = tiny.n
    r = DemoResult(f"Va chạm giá trị băm trên bản thu nhỏ (n = {n})", as_expected=False)
    r.add(f"Bản thu nhỏ dùng h = SHA-256(M) mod {n} ⇒ chỉ có {n} giá trị băm khả dĩ.")
    r.add("Kẻ tấn công sinh nhiều biến thể của một hợp đồng vô hại và một hợp đồng gian lận")
    r.add("(chỉ đổi mã giao dịch ở cuối) cho đến khi hai bản có cùng h.")
    benign: dict[int, bytes] = {}
    found = None
    for i in range(max_tries):
        good = f"Alice dong y chuyen cho Bob 100.000 VND. Ma GD #{i}".encode()
        benign.setdefault(tiny_hash(good, n), good)
        evil = f"Alice dong y chuyen cho Bob 900.000.000 VND. Ma GD #{i}".encode()
        h_evil = tiny_hash(evil, n)
        if h_evil in benign:
            found = (benign[h_evil], evil, h_evil, i + 1)
            break
    if not found:
        r.add("Không tìm được va chạm trong giới hạn thử.")
        return r
    good, evil, h, tries = found
    r.add(f"Sau {tries} lượt (~√n = {int(n ** 0.5)} theo nghịch lý ngày sinh) tìm được:")
    r.add(f"  M1 = {good.decode()}")
    r.add(f"  M2 = {evil.decode()}")
    r.add(f"  h(M1) = h(M2) = {h}")
    s = tiny.sign(good)
    r.add(f"Alice ký M1 vô hại: s = {s}")
    ok = tiny.verify(evil, s)
    r.add(f"Kiểm tra (M2, s): {'HỢP LỆ ⇒ Alice bị gán chữ ký cho hợp đồng 900 triệu!' if ok else 'SAI'}")
    r.add("Bài học: hàm băm phải KHÁNG VA CHẠM và đầu ra đủ dài (SHA-256: ~2^128 phép thử).")
    r.add("Đây cũng là lý do MD5/SHA-1 bị loại khỏi chữ ký số (Flame 2012, SHAttered 2017).")
    r.as_expected = ok
    return r


# ---------------------------------------------------------------------------
# 5. Thay khoá công khai (kẻ đứng giữa) và vai trò của chứng thư số
# ---------------------------------------------------------------------------


def demo_key_substitution() -> DemoResult:
    r = DemoResult("Thay khoá công khai — tính chứng thực cần PKI", as_expected=False)
    alice = generate_keypair(DEMO_KEY_BITS)
    mallory = generate_keypair(DEMO_KEY_BITS)
    ca = generate_keypair(DEMO_KEY_BITS)
    r.add(f"Khoá thật của Alice   : {alice.public_key().fingerprint()}")
    r.add(f"Khoá của Mallory      : {mallory.public_key().fingerprint()}")

    r.add("")
    r.add("Kịch bản A — Bob nhận khoá công khai 'của Alice' qua kênh không tin cậy:")
    fake_msg = "Alice: hãy chuyển 50 triệu vào tài khoản 999-MALLORY".encode()
    fake_sig = sign(mallory, fake_msg)
    r.add("  Mallory chặn kênh, gửi cho Bob khoá của Mallory nhưng ghi tên 'Alice'.")
    ok_a = verify(mallory.public_key(), fake_msg, fake_sig)
    r.add(f"  Bob kiểm tra thông điệp giả bằng 'khoá Alice' (thực ra của Mallory): {'HỢP LỆ' if ok_a else 'SAI'}")
    r.add("  ⇒ Chữ ký đúng về mặt toán học nhưng Bob bị lừa về DANH TÍNH người ký.")

    r.add("")
    r.add("Kịch bản B — dùng chứng thư số do CA tin cậy cấp:")
    cert_alice = issue_certificate(ca, "Demo-CA", "Alice", alice.public_key(), serial=1)
    r.add("  CA đã xác minh danh tính và ký chứng thư (Alice ↔ khoá thật của Alice).")
    forged_cert = {
        "tbs": {**cert_alice["tbs"], "subject_public_key": mallory.public_key().to_dict(),
                "subject_key_fingerprint": mallory.public_key().fingerprint()},
        "signature": cert_alice["signature"],
    }
    ok_forged_cert, msg_forged = verify_certificate(ca.public_key(), forged_cert)
    r.add(f"  Mallory sửa chứng thư để nhét khoá của mình: {msg_forged}")
    ok_real_cert, msg_real = verify_certificate(ca.public_key(), cert_alice)
    r.add(f"  Bob kiểm tra chứng thư thật: {msg_real}")
    ok_b = verify(subject_key(cert_alice), fake_msg, fake_sig)
    r.add(f"  Bob kiểm tra thông điệp giả bằng khoá trong chứng thư: {'HỢP LỆ' if ok_b else 'SAI ⇒ phát hiện giả mạo'}")
    r.add("Kết luận: chữ ký RSA chứng thực 'người giữ khoá bí mật', còn liên kết khoá ↔ danh tính")
    r.add("phải do PKI (CA, chứng thư X.509, thu hồi CRL/OCSP) bảo đảm.")
    r.as_expected = ok_a and not ok_forged_cert and ok_real_cert and not ok_b
    return r


# ---------------------------------------------------------------------------
# 6. Không chối bỏ: HMAC so với chữ ký RSA
# ---------------------------------------------------------------------------


def demo_repudiation() -> DemoResult:
    r = DemoResult("Tính không chối bỏ: HMAC (khoá đối xứng) so với chữ ký RSA", as_expected=False)
    msg = "Alice đặt mua 10 tấn cà phê của Bob, tổng 1,2 tỷ VND".encode()

    shared = secrets.token_bytes(32)
    tag_alice = hmac_sha256(shared, msg)
    tag_bob = hmac_sha256(shared, msg)  # Bob cũng có khoá ⇒ tự tạo được thẻ y hệt
    r.add("HMAC: Alice và Bob dùng chung khoá K.")
    r.add(f"  Thẻ do Alice tạo: {tag_alice.hex()[:32]}…")
    r.add(f"  Thẻ do Bob tự tạo: {tag_bob.hex()[:32]}…")
    r.add(f"  Hai thẻ giống nhau? {tag_alice == tag_bob}")
    r.add("  Ra toà, Alice chối: 'Bob tự tạo thẻ này'. Trọng tài KHÔNG phân biệt được ⇒ chối bỏ được.")

    alice = generate_keypair(DEMO_KEY_BITS)
    bob = generate_keypair(DEMO_KEY_BITS)
    sig = sign(alice, msg)
    r.add("")
    r.add("Chữ ký RSA: chỉ Alice giữ khoá bí mật d_A; ai cũng kiểm tra được bằng (n_A, e_A).")
    r.add(f"  Chữ ký của Alice hợp lệ với khoá công khai của Alice: {verify(alice.public_key(), msg, sig)}")
    bob_attempt = sign(bob, msg)
    r.add(f"  Bob thử 'ký thay' bằng khoá của mình → kiểm tra bằng khoá Alice: {verify(alice.public_key(), msg, bob_attempt)}")
    r.add("  Trọng tài (bên thứ ba) chỉ cần khoá công khai của Alice + chứng thư để kết luận Alice đã ký.")
    r.add("Điều kiện để không chối bỏ thực sự: khoá bí mật được bảo vệ (token/HSM), chứng thư còn hiệu lực")
    r.add("tại thời điểm ký (dấu thời gian RFC 3161), và có cơ chế thu hồi khi lộ khoá.")
    r.as_expected = tag_alice == tag_bob and not verify(alice.public_key(), msg, bob_attempt)
    return r


# ---------------------------------------------------------------------------
# 7. Phân tích n nhỏ bằng Pollard rho
# ---------------------------------------------------------------------------


def pollard_rho(n: int, time_limit: float = 30.0) -> int | None:
    """Tìm một ước không tầm thường của n (thuật toán rho của Pollard, biến thể Brent)."""
    if n % 2 == 0:
        return 2
    deadline = time.perf_counter() + time_limit
    while time.perf_counter() < deadline:
        y, c, m = secrets.randbelow(n - 1) + 1, secrets.randbelow(n - 1) + 1, 128
        g = r = q = 1
        x = ys = y
        while g == 1:
            x = y
            for _ in range(r):
                y = (y * y + c) % n
            k = 0
            while k < r and g == 1:
                ys = y
                for _ in range(min(m, r - k)):
                    y = (y * y + c) % n
                    q = q * abs(x - y) % n
                g = gcd(q, n)
                k += m
            r *= 2
            if time.perf_counter() > deadline:
                return None
        if g == n:
            g = 1
            while g == 1:
                ys = (ys * ys + c) % n
                g = gcd(abs(x - ys), n)
        if g != n:
            return g
    return None


def demo_factoring(bit_sizes: tuple[int, ...] = (32, 40, 48, 56, 64, 72, 80, 88)) -> DemoResult:
    r = DemoResult("Phân tích modulus nhỏ ⇒ lộ khoá bí mật", as_expected=False)
    r.add("Biết p, q ⇒ tính φ(n) ⇒ d = e^-1 mod φ(n) ⇒ giả mạo mọi chữ ký.")
    r.add(f"  {'bit n':>6} | {'thời gian (s)':>13} | khôi phục d?")
    timings = []
    all_ok = True
    for bits in bit_sizes:
        while True:
            p, q = random_prime(bits // 2), random_prime(bits // 2)
            if p != q and gcd(65537, (p - 1) * (q - 1)) == 1:
                break
        key = key_from_primes(p, q, 65537)
        t0 = time.perf_counter()
        f = pollard_rho(key.n)
        dt = time.perf_counter() - t0
        ok = f is not None and f not in (1, key.n)
        if ok:
            phi = (f - 1) * (key.n // f - 1)
            ok = mod_inverse(65537, phi) == key.d
        all_ok &= ok
        timings.append((bits, dt))
        r.add(f"  {bits:>6} | {dt:>13.4f} | {'có' if ok else 'không'}")
    r.add("Thời gian Pollard rho tăng theo ~√p = 2^(bit/4): thêm 8 bit ⇒ chậm ~4 lần.")
    r.add("RSA-2048 không thể phá bằng rho; thuật toán tốt nhất là sàng trường số (GNFS):")
    r.add("kỷ lục công khai là RSA-250 (829 bit, năm 2020) — 2048 bit vẫn ngoài tầm (~112 bit an toàn).")
    r.as_expected = all_ok
    return r


# ---------------------------------------------------------------------------
# 8. Tấn công lỗi lên ký CRT (Boneh–DeMillo–Lipton 1997)
# ---------------------------------------------------------------------------


def demo_crt_fault(key: PrivateKey | None = None) -> DemoResult:
    key = key or generate_keypair(DEMO_KEY_BITS)
    pub = key.public_key()
    r = DemoResult("Tấn công lỗi (fault) lên phép ký dùng CRT", as_expected=False)
    msg = b"Bao cao tai chinh quy 3"
    k = pub.size_bytes
    m = os2ip(emsa_pkcs1_v15_encode(sha256(msg).digest(), k))  # PKCS#1 v1.5 tất định ⇒ kẻ tấn công biết m

    s1 = mod_pow(m, key.dp, key.p)
    s2 = mod_pow(m, key.dq, key.q) ^ 1   # lỗi phần cứng: lật 1 bit ở nửa mod q
    h = key.qinv * (s1 - s2) % key.p
    s_faulty = s2 + h * key.q
    r.add("Thiết bị ký dùng CRT; một lỗi (điện áp/nhiệt/laser) làm hỏng phép tính mod q.")
    r.add(f"  Chữ ký lỗi s' = {_short(s_faulty)}")
    p_found = gcd((rsavp1(pub, s_faulty) - m) % pub.n, pub.n)
    ok = p_found == key.p
    r.add(f"  Kẻ tấn công tính gcd(s'^e − m, n) = {_short(p_found)}")
    r.add(f"  Trùng với p bí mật? {ok} ⇒ n bị phân tích chỉ từ MỘT chữ ký lỗi!")
    r.add("Phòng chống: kiểm tra lại s^e mod n trước khi phát hành chữ ký;")
    r.add("dùng PSS (salt ngẫu nhiên ⇒ kẻ tấn công không biết m).")
    r.as_expected = ok
    return r


DEMOS = {
    "tamper": demo_tamper,
    "existential": demo_existential_forgery,
    "multiplicative": demo_multiplicative,
    "tiny_collision": demo_tiny_collision,
    "key_substitution": demo_key_substitution,
    "repudiation": demo_repudiation,
    "factoring": demo_factoring,
    "crt_fault": demo_crt_fault,
}
