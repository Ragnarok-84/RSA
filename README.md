# rsasig — Hệ chữ ký điện tử RSA ký trên giá trị băm

Bài tập nhóm môn **An toàn và bảo mật thông tin** — Nhóm C: *Hệ chữ ký điện tử RSA — ký trên
giá trị băm của thông điệp, kiểm tra chữ ký, phân tích tính chứng thực và tính không chối bỏ.*

- **Tự cài đặt toàn bộ phần lõi** bằng Python thuần: Euclid mở rộng, nghịch đảo modulo,
  bình phương và nhân, Miller–Rabin, SHA-256, HMAC, RSA (CRT), RSASSA-PKCS1-v1_5, RSASSA-PSS.
  Không dùng `hashlib`, `pow(a, b, n)`, `cryptography`, `Crypto`, `openssl` trong `rsasig/core`.
- **Hai phiên bản**: bản thu nhỏ (p = 61, q = 53, e = 17, in mọi bước trung gian, khớp
  ví dụ tính tay) và bản đầy đủ (RSA-2048/3072, SHA-256, chuẩn RFC 8017, tương thích OpenSSL).
- **Ký/kiểm tra tệp thật** (văn bản, ảnh), CLI + menu tương tác + GUI Tkinter.
- **8 kịch bản tấn công/phân tích**: sửa nội dung, giả mạo RSA thô, tính chất nhân, va chạm băm,
  thay khoá công khai (vai trò CA), HMAC vs RSA (không chối bỏ), phân tích n nhỏ, tấn công lỗi CRT.
- **108 ca kiểm thử**, đối chiếu NIST FIPS 180-4, RFC 4231 và thư viện `cryptography`.

## Cài đặt

Yêu cầu Python ≥ 3.10 (Windows/macOS/Linux). Phần lõi không cần cài thêm gì; `pytest` và
`cryptography` chỉ dùng để kiểm thử đối chiếu.

```powershell
# Windows (PowerShell)
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
```

```bash
# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

## Cách chạy

```bash
python -m rsasig                 # menu tương tác
python -m rsasig gui             # giao diện đồ hoạ
```

### Bản thu nhỏ — in từng bước

```bash
python -m rsasig tiny -m HELLO --tamper HELLo     # sinh khoá, băm, ký, kiểm tra, thử sửa
python -m rsasig tiny --hash 65                   # ký giá trị băm cho trước (ví dụ giáo trình ⇒ s = 588)
python -m rsasig tiny -p 11 -q 17 -e 7 --hash 88  # bộ số tuỳ ý
```

### Bản đầy đủ — ký và kiểm tra tệp

```bash
python -m rsasig keygen --bits 2048 --name Alice --out keys/alice
python -m rsasig sign   --key keys/alice.priv.json --file samples/hop_dong.txt            # mặc định PSS
python -m rsasig sign   --key keys/alice.priv.json --file samples/anh_mau.png --scheme pkcs1v15
python -m rsasig verify --pub keys/alice.pub.json  --file samples/hop_dong.txt
python -m rsasig hash samples/anh_mau.png         # SHA-256 tự cài đặt so với hashlib
```

Chữ ký lưu ở `<tệp>.sig.json`, gồm *manifest* (SHA-256 của tệp, người ký, dấu vân tay khoá,
lược đồ, thời điểm) và chữ ký RSA trên manifest. `verify` trả mã thoát 0 nếu hợp lệ, 1 nếu không.

### Tấn công / phân tích an toàn

```bash
python -m rsasig attack all
python -m rsasig attack tiny_collision     # tamper | existential | multiplicative | tiny_collision
                                           # key_substitution | repudiation | factoring | crt_fault
```

### Kiểm thử và đo hiệu năng

```bash
python -m pytest                  # 108 ca kiểm thử
python -m pytest -m "not slow"    # bỏ RSA-2048 và băm 1 MB
python -m rsasig bench --quick    # đo nhanh; bỏ --quick để đo cả 3072 bit và tệp 1 MB
```

## Cấu trúc thư mục

```
rsasig/
  core/                  # THUẬT TOÁN — tự cài đặt, không phụ thuộc giao diện
    math_utils.py        #   gcd, Euclid mở rộng, mod_inverse, mod_pow, Miller–Rabin, random_prime
    sha256.py            #   SHA-256 (FIPS 180-4)
    hmac_sha256.py       #   HMAC-SHA256 (RFC 2104) — dùng để so sánh
    keys.py              #   sinh / lưu / nạp khoá, dấu vân tay
    rsa_primitives.py    #   RSASP1 / RSAVP1, ký CRT
    pkcs1.py             #   RSASSA-PKCS1-v1_5, RSASSA-PSS, MGF1 (RFC 8017)
    tiny.py              #   bản thu nhỏ có in bước trung gian
    envelope.py          #   ký / kiểm tra tệp với manifest
    certificate.py       #   chứng thư số thu gọn (CA, hết hạn, thu hồi)
  attacks/demos.py       # 8 kịch bản tấn công / phân tích
  ui/                    # GIAO DIỆN — chỉ gọi API của core
    cli.py  menu.py  gui.py
  benchmark.py           # đo thời gian (dùng hashlib/cryptography để đối chiếu)
tests/                   # pytest: test tự viết + vector NIST/RFC + đối chiếu cryptography
docs/
  bao-cao.md             # bản thảo báo cáo theo bố cục gợi ý
  vi-du-tinh-tay.md      # ví dụ tính tay khớp chương trình
  so-do.md               # sơ đồ khối (Mermaid)
  kich-ban-demo.md       # kịch bản demo 5–7 phút + câu hỏi bảo vệ
  slides-outline.md      # dàn ý slide
  phan-cong.md           # bảng phân công (mẫu)
samples/                 # tệp văn bản + ảnh PNG để demo
```

## Đối chiếu với yêu cầu của hướng dẫn

| Yêu cầu | Đáp ứng ở |
|---|---|
| Bối cảnh, mô tả thuật toán, sơ đồ khối tự vẽ | `docs/bao-cao.md` ch. 2–3, `docs/so-do.md` |
| Ví dụ tính tay trên bộ số nhỏ, khớp chương trình | `docs/vi-du-tinh-tay.md`, `tests/test_tiny.py` |
| Phân tích độ an toàn, so sánh hệ cùng loại | `docs/bao-cao.md` §3.5–3.8 |
| Tự cài đặt, không dùng thư viện mật mã cho lõi | `rsasig/core/` |
| Cả hai phiên bản (thu nhỏ + đầy đủ) | `core/tiny.py`, `core/pkcs1.py` |
| Hai chiều: ký và kiểm tra | `sign` / `verify` (CLI, GUI) |
| ≥ 3 ca kiểm thử tự viết + vector chuẩn / thư viện chuẩn | `tests/` (108 ca; NIST, RFC 4231, `cryptography`) |
| Mã chia module, có chú thích, tách thuật toán khỏi giao diện | `core/` ↔ `ui/` |
| Demo trực tiếp, in bước trung gian cho bản thu nhỏ | `python -m rsasig tiny` |
| Demo trên dữ liệu thật (tệp văn bản / ảnh) | `samples/`, lệnh `sign` / `verify` |
| Khuyến khích: giao diện, đo thời gian, minh hoạ tấn công | `gui`, `menu`, `bench`, `attack` |
| Bảng phân công, ghi rõ sử dụng AI | `docs/phan-cong.md`, mục dưới đây |

## Sử dụng công cụ AI

Theo yêu cầu của hướng dẫn, nhóm ghi rõ: `<điền — ví dụ: khung repo, mã nguồn ban đầu, kiểm thử
và bản thảo tài liệu được tạo với sự hỗ trợ của Claude (Anthropic); nhóm đã đọc hiểu, chạy kiểm
thử, chỉnh sửa và chịu trách nhiệm giải thích toàn bộ mã nguồn khi bảo vệ>`.

## Lưu ý bảo mật

Đây là mã phục vụ học tập: chưa chạy trong thời gian hằng (có thể lộ qua kênh kề thời gian),
khoá bí mật lưu JSON không mã hoá. Không dùng cho hệ thống thật.
