# BÁO CÁO BÀI TẬP NHÓM — AN TOÀN VÀ BẢO MẬT THÔNG TIN

## Đề tài: Hệ chữ ký điện tử RSA — ký trên giá trị băm, kiểm tra chữ ký, phân tích tính chứng thực và tính không chối bỏ

| | |
|---|---|
| Nhóm | `<số nhóm>` |
| Lớp | `<mã lớp>` |
| Giảng viên | `<tên giảng viên>` |
| Thành viên | `<Họ tên — MSSV>` (xem bảng phân công ở Phụ lục A) |
| Mã nguồn | `<link GitHub>` |

> Bản thảo này được dựng cùng mã nguồn. Nhóm cần chuyển sang mẫu khoá luận của khoa,
> bổ sung thông tin nhóm, chụp ảnh màn hình demo, và **đọc lại – viết lại theo hiểu biết
> của mình** (mọi thành viên phải giải thích được khi bảo vệ).

---

## Chương 1. Mở đầu

### 1.1. Đặt vấn đề

Trong giao dịch giấy, chữ ký tay và con dấu cho phép người nhận tin rằng văn bản do đúng
người đó ban hành, không bị sửa sau khi ký, và người ký không thể phủ nhận. Khi văn bản
chuyển sang dạng số, việc sao chép một "hình ảnh chữ ký" là vô nghĩa — cần một cơ chế toán
học gắn chữ ký với **nội dung** văn bản và với **một bí mật** mà chỉ người ký nắm giữ.
Đó là chữ ký điện tử (chữ ký số).

### 1.2. Mục tiêu

1. Tìm hiểu hệ chữ ký RSA: bối cảnh, thuật toán sinh khoá – ký – kiểm tra, các lược đồ
   đệm chuẩn (PKCS#1 v1.5, PSS).
2. Tự cài đặt từ đầu (không dùng thư viện mật mã cho phần lõi) cả hai phiên bản:
   bản thu nhỏ (số nhỏ, in bước trung gian) và bản đầy đủ (RSA-2048, SHA-256).
3. Phân tích **tính chứng thực** và **tính không chối bỏ**: chữ ký RSA đảm bảo được gì,
   dưới giả thiết nào, và khi nào các tính chất đó bị phá vỡ.
4. Minh hoạ các tấn công đã biết và so sánh với các hệ chữ ký khác.

### 1.3. Phạm vi

Đề tài thuộc Nhóm C — Hàm băm và chữ ký điện tử (Chương 4). Hàm băm sử dụng là SHA-256,
cũng được nhóm tự cài đặt theo FIPS 180-4.

---

## Chương 2. Cơ sở lý thuyết

### 2.1. Bối cảnh ra đời

- **1976** — Diffie và Hellman công bố *New Directions in Cryptography*, đưa ra khái niệm
  mật mã khoá công khai và **chữ ký số**, nhưng chưa có hệ cụ thể cho chữ ký.
- **1977** — Ron Rivest, Adi Shamir, Leonard Adleman (MIT) đề xuất RSA; bài báo
  *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems* đăng trên
  Communications of the ACM năm 1978. Ngay tiêu đề đã nhấn mạnh chữ ký số.
- 1973 — Clifford Cocks (GCHQ, Anh) đã tìm ra hệ tương đương nhưng được giữ bí mật đến 1997.
- **1993** — RSA Laboratories công bố PKCS#1 (v1.5), chuẩn hoá cách đệm khi ký/mã hoá.
- **1996** — Bellare & Rogaway đề xuất PSS (Probabilistic Signature Scheme) với chứng minh
  an toàn chặt; được đưa vào PKCS#1 v2.1 (RFC 3447, 2003) và v2.2 (RFC 8017, 2016).
- **2000** — bằng sáng chế RSA (US 4,405,829) hết hạn, RSA được dùng tự do.

**Vấn đề RSA giải quyết**: cho phép một người dùng bí mật riêng (khoá bí mật) tạo dấu xác
nhận mà **bất kỳ ai** cũng kiểm tra được bằng thông tin công khai — điều mà mật mã đối xứng
(MAC) không làm được vì bên kiểm tra cũng phải giữ bí mật.

**Ứng dụng thực tế**: chứng thư số X.509 trong HTTPS/TLS; ký mã nguồn/phần mềm (Windows
Authenticode, gói phần mềm Linux); ký văn bản PDF; DNSSEC; SSH; hoá đơn điện tử, kê khai thuế,
hải quan, ngân hàng trực tuyến tại Việt Nam qua token chữ ký số do các tổ chức cung cấp dịch vụ
chứng thực cấp (khung pháp lý: Luật Giao dịch điện tử số 20/2023/QH15, hiệu lực 01/7/2024).

### 2.2. Các khái niệm an toàn liên quan

| Tính chất | Ý nghĩa | Cơ chế bảo đảm |
|---|---|---|
| Toàn vẹn (integrity) | Dữ liệu không bị sửa sau khi ký | Hàm băm + chữ ký |
| Xác thực nguồn gốc (data origin authentication) | Dữ liệu do người giữ khoá bí mật tạo ra | Chữ ký (hoặc MAC) |
| **Tính chứng thực** (gắn với danh tính) | Người giữ khoá chính là "Alice" ngoài đời thực | Chữ ký + PKI (chứng thư CA) |
| **Không chối bỏ** (non-repudiation) | Người ký không phủ nhận được trước **bên thứ ba** | Chỉ chữ ký bất đối xứng (MAC không có) |

### 2.3. Nền tảng toán học

- **Định lý Euler**: nếu gcd(a, n) = 1 thì a^φ(n) ≡ 1 (mod n). Với n = pq, φ(n) = (p−1)(q−1).
  Nếu ed ≡ 1 (mod φ(n)) thì (m^d)^e ≡ m (mod n) với mọi m (kể cả khi gcd(m, n) ≠ 1, chứng minh
  qua CRT).
- **Thuật toán Euclid mở rộng**: tìm x, y với ax + by = gcd(a, b) ⇒ tìm nghịch đảo d = e⁻¹ mod φ(n).
- **Lũy thừa modulo — bình phương và nhân**: tính a^k mod n trong O(log k) phép nhân.
- **Kiểm tra nguyên tố Miller–Rabin**: viết n − 1 = 2^s·d; với cơ sở a, n "qua" nếu
  a^d ≡ 1 hoặc a^(2^r·d) ≡ −1 với r nào đó. Hợp số qua một cơ sở ngẫu nhiên với xác suất ≤ 1/4
  ⇒ 40 vòng cho xác suất sai ≤ 2⁻⁸⁰. Khác với phép thử Fermat, Miller–Rabin không bị số
  Carmichael (561, 1105, …) đánh lừa.
- **Định lý số dư Trung Hoa (CRT)**: tính m^d mod p và mod q riêng rồi ghép lại — nhanh ~3–4 lần.

### 2.4. Hàm băm SHA-256

Cấu trúc Merkle–Damgård: đệm thông điệp tới bội 512 bit (bit 1, các bit 0, 64 bit độ dài),
xử lý từng khối qua hàm nén 64 vòng trên 8 thanh ghi 32 bit (các hàm Ch, Maj, Σ0, Σ1, σ0, σ1),
đầu ra 256 bit. Ba tính chất cần cho chữ ký: kháng tiền ảnh, kháng tiền ảnh thứ hai,
**kháng va chạm** (~2¹²⁸ phép thử theo nghịch lý ngày sinh).

---

## Chương 3. Phân tích thuật toán

> Sơ đồ khối: xem `docs/so-do.md` (sinh khoá, ký, kiểm tra, trao đổi với CA, kiến trúc mã nguồn).

### 3.1. Sinh khoá

**Đầu vào**: độ dài k bit (2048), số mũ công khai e (65537 = 2¹⁶ + 1).

1. Sinh số nguyên tố ngẫu nhiên p, q mỗi số k/2 bit: chọn số lẻ ngẫu nhiên, đặt 2 bit cao = 1
   (để n đủ k bit), lọc nhanh bằng chia thử cho các số nguyên tố < 2000, rồi Miller–Rabin 40 vòng.
2. Loại trường hợp |p − q| quá nhỏ (chống phân tích Fermat) và gcd(e, φ(n)) ≠ 1.
3. n = pq; φ(n) = (p−1)(q−1); d = e⁻¹ mod φ(n) (Euclid mở rộng).
4. Tính thêm dP = d mod (p−1), dQ = d mod (q−1), qInv = q⁻¹ mod p để ký bằng CRT.

**Đầu ra**: khoá công khai (n, e); khoá bí mật (n, d, p, q, dP, dQ, qInv).

*Tại sao e = 65537?* Nhỏ và chỉ có 2 bit 1 ⇒ kiểm tra rất nhanh (17 phép nhân), nhưng đủ lớn
để tránh các tấn công liên quan e = 3.

### 3.2. Ký trên giá trị băm

**RSA "thô" (sách giáo khoa)**: s = m^d mod n — *không an toàn*, chỉ dùng để giảng dạy.

**Ký trên giá trị băm**: s = Encode(H(M))^d mod n. Lý do:

1. M có độ dài tuỳ ý, RSA chỉ ký được số < n ⇒ băm về 256 bit cố định, tệp 1 GB vẫn chỉ
   cần **một** phép lũy thừa RSA.
2. Phá vỡ **tính chất nhân** (s₁·s₂ là chữ ký của m₁·m₂) và **giả mạo tồn tại** (chọn s,
   tính m = s^e) của RSA thô — xem demo ở Chương 5.
3. Hàm mã hoá (Encode) cố định cấu trúc khối, ràng buộc thuật toán băm (DigestInfo) và
   — với PSS — thêm tính ngẫu nhiên.

**RSASSA-PKCS1-v1_5** (RFC 8017 §8.2, tất định):

```
EM = 0x00 ‖ 0x01 ‖ 0xFF…FF (≥ 8 byte) ‖ 0x00 ‖ DigestInfo(SHA-256) ‖ H(M)
s  = OS2IP(EM)^d mod n
```

**RSASSA-PSS** (RFC 8017 §8.1, ngẫu nhiên hoá):

```
salt ← ngẫu nhiên 32 byte
H'   = SHA-256(0x00⁸ ‖ H(M) ‖ salt)
DB   = 0x00…00 ‖ 0x01 ‖ salt
EM   = (DB ⊕ MGF1(H')) ‖ H' ‖ 0xBC
s    = OS2IP(EM)^d mod n
```

### 3.3. Kiểm tra chữ ký

1. Kiểm tra 0 ≤ s < n và độ dài chữ ký = độ dài n.
2. m = s^e mod n; EM = I2OSP(m).
3. PKCS#1 v1.5: **mã hoá lại** Encode(H(M)) và so sánh toàn khối (không "phân tích cú pháp"
   EM — tránh lỗi Bleichenbacher 2006). PSS: gỡ mặt nạ, lấy salt, tính lại H' và so sánh.
4. So sánh trong thời gian hằng (không dừng sớm ở byte khác đầu tiên).

### 3.4. Ví dụ tính tay (bản thu nhỏ)

Trình bày đầy đủ trong `docs/vi-du-tinh-tay.md`. Tóm tắt: p = 61, q = 53, e = 17 ⇒ n = 3233,
φ(n) = 3120, d = 2753. M = "HELLO", h = SHA-256(M) mod 3233 = 820, chữ ký
s = 820^2753 mod 3233 = **1627**; kiểm tra 1627^17 mod 3233 = 820 ✔. Đổi M thành "HELLo"
⇒ h = 3106 ≠ 820 ⇒ bị từ chối. Kết quả khớp chương trình (kiểm thử `test_tiny.py`).

### 3.5. Phân tích tính chứng thực

**Mệnh đề**: nếu Verify(pk_A, M, s) = đúng thì, với xác suất áp đảo, s được tạo bởi
một thực thể biết khoá bí mật d_A, trên đúng thông điệp M.

**Giả thiết cần có**:

1. *Bài toán RSA khó*: không tính được căn bậc e modulo n khi không biết phân tích n = pq.
   Hiện tốt nhất là phân tích n bằng sàng trường số tổng quát (GNFS), độ phức tạp
   L_n[1/3, 1.923] — dưới mũ nhưng vẫn quá lớn với n ≥ 2048 bit.
2. *Hàm băm kháng va chạm*: nếu tìm được M ≠ M' với H(M) = H(M') thì chữ ký trên M cũng
   là chữ ký trên M' (demo `tiny_collision` cho thấy điều này khi miền băm chỉ có 3233 giá trị).
3. *Lược đồ đệm đúng*: với PSS, Bellare–Rogaway chứng minh (trong mô hình tiên tri ngẫu nhiên)
   rằng giả mạo chữ ký dưới tấn công thông điệp chọn trước (EUF-CMA) khó tương đương bài toán RSA.

**Giới hạn — chứng thực "khoá" chứ không chứng thực "người"**: toán học chỉ chứng minh
"ai đó giữ d_A đã ký". Liên kết *d_A ↔ Alice* phải được bảo đảm bên ngoài:

- Nếu Bob nhận khoá công khai qua kênh không tin cậy, kẻ đứng giữa có thể thay khoá
  (demo `key_substitution`): chữ ký của Mallory kiểm tra "hợp lệ" với "khoá Alice" giả.
- Giải pháp: **hạ tầng khoá công khai (PKI)**. CA xác minh danh tính rồi ký chứng thư
  Cert = Sign_CA(Alice, pk_A, thời hạn). Bob chỉ cần tin trước khoá công khai của CA.
  Mallory không sửa được chứng thư vì không có khoá bí mật của CA.
- Chứng thư có thời hạn và có thể bị **thu hồi** (CRL/OCSP) khi lộ khoá.

### 3.6. Phân tích tính không chối bỏ

**Vì sao chữ ký RSA có, còn MAC thì không?** Với HMAC, Alice và Bob dùng chung khoá K: bất
kỳ thẻ nào Alice tạo được thì Bob cũng tạo được. Khi tranh chấp, trọng tài không phân biệt
được ai đã tạo thẻ (demo `repudiation`). Với RSA, chỉ Alice giữ d_A, còn trọng tài kiểm tra
bằng khoá công khai — **bằng chứng có thể chuyển giao cho bên thứ ba**. Đây là tính chất
mà chỉ mật mã bất đối xứng mang lại.

**Điều kiện để không chối bỏ thực sự** (và các luận điểm chối bỏ tương ứng):

| Luận điểm chối bỏ của người ký | Điều kiện / biện pháp chống |
|---|---|
| "Khoá công khai đó không phải của tôi" | Chứng thư số do CA cấp sau khi xác minh danh tính |
| "Khoá của tôi bị đánh cắp, người khác ký" | Khoá bí mật lưu trong token/HSM không xuất được, có PIN; quy định trách nhiệm bảo quản |
| "Tôi ký sau khi đã báo mất khoá / chứng thư hết hạn" | Dấu thời gian tin cậy (RFC 3161) + bằng chứng trạng thái thu hồi tại thời điểm ký |
| "Tôi ký văn bản khác, không phải văn bản này" | Hàm băm kháng va chạm (SHA-256, không dùng MD5/SHA-1); ký cả siêu dữ liệu |
| "Chữ ký có thể bị giả mạo bằng toán học" | Khoá đủ dài (≥ 2048 bit), lược đồ đệm chuẩn (PSS), sinh số ngẫu nhiên tốt |
| "Phần mềm hiển thị khác với cái tôi ký" (WYSIWYS) | Môi trường ký tin cậy, định dạng văn bản chuẩn (PDF/A, PAdES) |

**Trong chương trình của nhóm**: tệp chữ ký (`.sig.json`) ký lên một *manifest* gồm
SHA-256 của tệp, tên người ký, dấu vân tay khoá, lược đồ và thời điểm ký. Sửa bất kỳ trường
nào đều làm chữ ký sai (`test_manifest_signer_changed_detected`). Hạn chế: thời điểm ký do
người ký tự khai, chưa có dịch vụ dấu thời gian độc lập.

### 3.7. Phân tích độ an toàn

**Không gian khoá và mức an toàn tương đương** (NIST SP 800-57 Part 1 Rev. 5):

| Độ dài n | Mức an toàn đối xứng tương đương | Tình trạng |
|---|---|---|
| 512 bit | ~ 56 bit | Đã bị phân tích (RSA-155, 1999) |
| 1024 bit | ~ 80 bit | Không còn được chấp nhận |
| 2048 bit | 112 bit | Chấp nhận đến 2030 |
| 3072 bit | 128 bit | Khuyến nghị cho dài hạn |
| 7680 / 15360 bit | 192 / 256 bit | Hiếm dùng (khoá và chữ ký rất lớn) |

Kỷ lục phân tích công khai: RSA-250 (829 bit) năm 2020, ~2700 năm-lõi CPU.

**Các tấn công đã biết**:

| Tấn công | Điều kiện | Phòng chống | Demo |
|---|---|---|---|
| Giả mạo tồn tại / tính chất nhân | Ký thô, không băm | Ký trên giá trị băm + đệm | `existential`, `multiplicative` |
| Va chạm hàm băm | Hàm băm yếu (MD5: chứng thư CA giả 2008, mã độc Flame 2012; SHA-1: SHAttered 2017) | SHA-256 trở lên | `tiny_collision` |
| Phân tích n | n ngắn | n ≥ 2048 bit | `factoring` (Pollard rho) |
| Thay khoá công khai | Không có PKI | Chứng thư CA | `key_substitution` |
| Tấn công lỗi (Boneh–DeMillo–Lipton 1997) | Ký CRT bị lỗi phần cứng | Kiểm tra s^e trước khi phát hành; PSS | `crt_fault` |
| Bleichenbacher 2006 (e = 3) | Bộ kiểm tra phân tích lỏng lẻo khối PKCS#1 | Mã hoá lại rồi so sánh toàn khối | — (đã phòng trong mã) |
| Kênh kề thời gian (Kocher 1996) | Thời gian ký phụ thuộc bit của d | Thuật toán thời gian hằng, blinding | — (hạn chế của bản Python) |
| Khoá yếu do sinh ngẫu nhiên kém | Debian OpenSSL 2008; ROCA 2017; các khoá chung thừa số nguyên tố (Lenstra et al., Heninger et al. 2012) | Nguồn ngẫu nhiên an toàn (`secrets`), kiểm tra khoá | — |
| d nhỏ (Wiener 1990) | d < n^0.25 / 3 | e = 65537 ⇒ d luôn lớn | — |
| Máy tính lượng tử (Shor 1994) | Máy lượng tử đủ lớn | Chuyển sang chữ ký hậu lượng tử (ML-DSA — FIPS 204, SLH-DSA — FIPS 205, 2024) | — |

**Kết luận về khuyến nghị**: RSA vẫn được chấp thuận trong FIPS 186-5 (2023) và dùng rộng rãi;
nên dùng n ≥ 3072 bit cho dữ liệu cần bảo vệ dài hạn, ưu tiên RSASSA-PSS cho ứng dụng mới
(PKCS#1 v1.5 vẫn an toàn khi cài đặt đúng và còn phổ biến trong X.509). Về dài hạn, các hệ
dựa trên phân tích thừa số sẽ được thay bằng chữ ký hậu lượng tử (NIST dự kiến loại dần
RSA-2048 sau 2030).

### 3.8. So sánh với các hệ chữ ký khác

| Tiêu chí | RSA-PSS (3072) | DSA (3072, q 256) | ECDSA P-256 | Ed25519 | HMAC-SHA256 |
|---|---|---|---|---|---|
| Bài toán khó | Phân tích thừa số / RSA | Logarit rời rạc trên Z_p* | Logarit rời rạc trên đường cong elliptic | Logarit rời rạc (Edwards) | Tính chất của hàm băm |
| Mức an toàn | 128 bit | 128 bit | 128 bit | ~128 bit | 256 bit (khoá) |
| Khoá công khai | 384 byte | ~384 byte | 64 byte | 32 byte | (khoá chung bí mật) |
| Chữ ký | 384 byte | 64 byte | 64 byte | 64 byte | 32 byte |
| Ký | Chậm (lũy thừa d lớn) | Nhanh | Nhanh | Rất nhanh | Rất nhanh |
| Kiểm tra | **Rất nhanh** (e = 65537) | Chậm hơn ký | Chậm hơn ký | Nhanh | Rất nhanh |
| Số ngẫu nhiên khi ký | PSS: salt (lộ không sao) | k bí mật — **lộ/lặp k ⇒ lộ khoá** | như DSA (sự cố PS3 2010) | Tất định, không cần | Không |
| Không chối bỏ | Có | Có | Có | Có | **Không** |
| Tình trạng | FIPS 186-5 chấp thuận | FIPS 186-5: chỉ còn kiểm tra chữ ký cũ | Chấp thuận | Chấp thuận (FIPS 186-5) | Chuẩn cho MAC |

Nhận xét: RSA phù hợp khi chữ ký được **kiểm tra nhiều lần hơn ký** (chứng thư, phần mềm);
hệ đường cong elliptic thắng về kích thước khoá/chữ ký và tốc độ ký. HMAC nhanh nhất nhưng
không có tính không chối bỏ.

---

## Chương 4. Cài đặt và kiểm thử

### 4.1. Môi trường và nguyên tắc

- Ngôn ngữ: Python ≥ 3.10, chỉ dùng thư viện chuẩn cho phần lõi (`secrets` để lấy số
  ngẫu nhiên an toàn, `struct` để đóng gói byte).
- **Không** dùng `hashlib`, `pow(·,·,·)`, `pow(e, −1, φ)`, `cryptography`, `Crypto`, `openssl`
  trong phần lõi. Các thư viện này chỉ xuất hiện trong kiểm thử và đo hiệu năng để đối chiếu.
- Phần thuật toán (`rsasig/core`) tách khỏi giao diện (`rsasig/ui`).

### 4.2. Cấu trúc mã nguồn

| Module | Nội dung |
|---|---|
| `core/math_utils.py` | gcd, Euclid mở rộng, nghịch đảo modulo, bình phương và nhân, Miller–Rabin, sinh số nguyên tố, I2OSP/OS2IP |
| `core/sha256.py` | SHA-256 (FIPS 180-4), băm theo luồng cho tệp lớn |
| `core/hmac_sha256.py` | HMAC-SHA256 (RFC 2104) — để so sánh tính không chối bỏ |
| `core/keys.py` | Sinh/lưu/nạp khoá, dấu vân tay khoá |
| `core/rsa_primitives.py` | RSASP1 / RSAVP1, ký bằng CRT |
| `core/pkcs1.py` | RSASSA-PKCS1-v1_5 và RSASSA-PSS (RFC 8017), MGF1 |
| `core/tiny.py` | Bản thu nhỏ, in toàn bộ bước trung gian |
| `core/envelope.py` | Ký/kiểm tra tệp thật với manifest |
| `core/certificate.py` | Chứng thư số thu gọn, CA, thu hồi |
| `attacks/demos.py` | 8 kịch bản tấn công/phân tích |
| `ui/cli.py`, `ui/menu.py`, `ui/gui.py` | Dòng lệnh, menu tương tác, giao diện Tkinter |
| `benchmark.py` | Đo thời gian theo kích thước dữ liệu/khoá |

### 4.3. Kiểm thử

Chạy `python -m pytest`: **108 ca kiểm thử, tất cả đạt**.

| Nhóm | Nội dung | Nguồn đối chiếu |
|---|---|---|
| Số học | Euclid mở rộng (ví dụ lớp), nghịch đảo, bình phương và nhân với số 1024 bit, Miller–Rabin trên số nguyên tố Mersenne, 10 số Carmichael, so với chia thử cho 0…4999 | `pow`, `math.gcd` |
| SHA-256 | 4 vector NIST, "a" × 10⁶, biên đệm 55/56/63/64 byte, băm theo luồng, hiệu ứng thác lũ | NIST FIPS 180-4, `hashlib` |
| HMAC | RFC 4231 test case 1, 2, 6; so với `hmac` | RFC 4231 |
| Bản thu nhỏ | d = 2753; h = 65 ⇒ s = 588; ví dụ tính tay "HELLO" ⇒ 1627; mọi h ∈ [0, 186] với n = 187; tham số sai | Ví dụ giáo trình |
| Bản đầy đủ | ký–kiểm tra 2 lược đồ, sửa thông điệp, sửa 1 bit chữ ký, sai độ dài, sai khoá, s ≥ n, n 1023/1025/2048 bit, CRT = không CRT | — |
| Đối chiếu chéo | Chữ ký của nhóm được `cryptography` (OpenSSL) chấp nhận và ngược lại, cả PSS và v1.5; chữ ký v1.5 trùng từng byte | `cryptography` |
| Tệp, chứng thư | Ký văn bản & tệp nhị phân; sửa tệp; sửa tên người ký; chứng thư bị sửa/hết hạn/thu hồi | — |
| Tấn công | 8 kịch bản cho kết quả đúng như phân tích | — |

---

## Chương 5. Kết quả demo và đánh giá

### 5.1. Demo chức năng

- Bản thu nhỏ: `python -m rsasig tiny -m HELLO --tamper HELLo` (in từng bước).
- Bản đầy đủ: sinh khoá RSA-2048 (~1–3 s), ký `samples/hop_dong.txt` và `samples/anh_mau.png`,
  kiểm tra hợp lệ; sửa "120.000.000" thành "12.000.000" ⇒ phát hiện ngay.
- `<chèn ảnh chụp màn hình CLI/GUI>`

### 5.2. Kết quả các kịch bản tấn công

`python -m rsasig attack all` — tóm tắt:

| Kịch bản | Kết quả |
|---|---|
| Sửa nội dung | Đổi 1 ký tự ⇒ băm khác hoàn toàn ⇒ chữ ký sai |
| Giả mạo tồn tại (RSA thô) | Tạo được cặp (m, s) hợp lệ không cần d; với lược đồ băm ⇒ thất bại |
| Tính chất nhân | Từ chữ ký trên 1000 và 1000000 tạo được chữ ký trên 10⁹; với băm ⇒ thất bại |
| Va chạm băm (bản thu nhỏ) | ~100 lần thử (≈ √3233) tìm được hợp đồng 100 nghìn và 900 triệu cùng h ⇒ chữ ký chuyển được |
| Thay khoá công khai | Không có CA: Bob bị lừa; có chứng thư: phát hiện |
| HMAC vs RSA | HMAC: Bob tạo được thẻ giống hệt ⇒ Alice chối được; RSA: không |
| Phân tích n nhỏ | n 32→88 bit bị phân tích trong < 2 s, khôi phục d |
| Lỗi CRT | Một chữ ký lỗi ⇒ gcd(s'^e − m, n) = p |

### 5.3. Hiệu năng

`python -m rsasig bench` (máy của nhóm: `<CPU, RAM>`; số liệu dưới đây là một lần chạy mẫu):

| n (bit) | Sinh khoá | Ký CRT | Ký không CRT | Kiểm tra | Ký bằng `cryptography` |
|---|---|---|---|---|---|
| 1024 | 0.15 s | 2.4 ms | 5.2 ms | 0.9 ms | 0.10 ms |
| 2048 | 2.1 s | 10.5 ms | 31.5 ms | 1.5 ms | 0.53 ms |

| Kích thước tệp | Băm SHA-256 (Python) | Lũy thừa RSA-2048 |
|---|---|---|
| 1 KB | 2.6 ms | 12.3 ms |
| 100 KB | 260 ms | 9.2 ms |

Nhận xét:

- CRT nhanh hơn ~3 lần; kiểm tra nhanh hơn ký ~7 lần (e = 65537 so với d ~2048 bit).
- Thời gian lũy thừa RSA **không phụ thuộc** kích thước tệp; với tệp lớn, thời gian băm chiếm ưu thế.
- Bản Python thuần chậm hơn OpenSSL ~20 lần (RSA) và hàng nghìn lần (SHA-256) — chấp nhận được
  cho mục đích học tập; đây cũng là lý do thực tế dùng thư viện đã được tối ưu và kiểm định.

### 5.4. Hạn chế

- Không chạy trong thời gian hằng ⇒ có thể bị tấn công kênh kề thời gian.
- Tệp khoá bí mật lưu dạng JSON không mã hoá (thực tế cần PKCS#8 mã hoá hoặc token/HSM).
- Thời điểm ký do người ký tự khai; chứng thư là dạng JSON thu gọn, không phải X.509/ASN.1.

---

## Chương 6. Kết luận

Nhóm đã tìm hiểu và tự cài đặt đầy đủ hệ chữ ký RSA ký trên giá trị băm SHA-256, gồm bản thu nhỏ
khớp ví dụ tính tay và bản đầy đủ theo chuẩn RFC 8017 tương thích với OpenSSL. Qua phân tích và
demo, nhóm rút ra:

1. Chữ ký RSA bảo đảm **toàn vẹn** và **xác thực nguồn gốc** dưới giả thiết bài toán RSA khó
   và hàm băm kháng va chạm; phải ký trên giá trị băm có đệm chuẩn, không bao giờ dùng RSA thô.
2. **Tính chứng thực** gắn với danh tính đòi hỏi PKI (CA, chứng thư, thu hồi).
3. **Tính không chối bỏ** là ưu thế của chữ ký bất đối xứng so với MAC, nhưng chỉ có hiệu lực
   khi khoá bí mật được bảo vệ độc quyền và có dấu thời gian, trạng thái chứng thư tin cậy.

Hướng phát triển: blinding và thuật toán thời gian hằng; định dạng X.509/PKCS#8; dịch vụ dấu
thời gian RFC 3161; so sánh thực nghiệm với ECDSA/Ed25519 và chữ ký hậu lượng tử ML-DSA.

---

## Tài liệu tham khảo

1. R. Rivest, A. Shamir, L. Adleman. *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.* Communications of the ACM, 21(2), 1978.
2. W. Diffie, M. Hellman. *New Directions in Cryptography.* IEEE Transactions on Information Theory, 22(6), 1976.
3. K. Moriarty et al. *RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2.* IETF, 2016.
4. NIST. *FIPS 180-4 — Secure Hash Standard (SHS).* 2015.
5. NIST. *FIPS 186-5 — Digital Signature Standard (DSS).* 2023.
6. NIST. *SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management.* 2020.
7. M. Bellare, P. Rogaway. *The Exact Security of Digital Signatures — How to Sign with RSA and Rabin.* EUROCRYPT 1996.
8. H. Krawczyk, M. Bellare, R. Canetti. *RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.* 1997. M. Nystrom. *RFC 4231 — HMAC-SHA Test Vectors.* 2005.
9. D. Boneh, R. DeMillo, R. Lipton. *On the Importance of Checking Cryptographic Protocols for Faults.* EUROCRYPT 1997.
10. D. Boneh. *Twenty Years of Attacks on the RSA Cryptosystem.* Notices of the AMS, 1999.
11. P. Kocher. *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems.* CRYPTO 1996.
12. M. Stevens et al. *The First Collision for Full SHA-1 (SHAttered).* CRYPTO 2017.
13. A. Lenstra et al. *Ron was wrong, Whit is right.* 2012; N. Heninger et al. *Mining Your Ps and Qs.* USENIX Security 2012.
14. C. Adams et al. *RFC 3161 — Time-Stamp Protocol (TSP).* 2001.
15. Quốc hội. *Luật Giao dịch điện tử số 20/2023/QH15.* 2023.
16. A. Menezes, P. van Oorschot, S. Vanstone. *Handbook of Applied Cryptography*, ch. 4, 11. CRC Press, 1996.
17. `<Bài giảng An toàn và bảo mật thông tin — Chương 3, 4>`

**Mã nguồn tham khảo bên ngoài**: không sao chép mã nguồn bên ngoài. Hằng số SHA-256 lấy từ
FIPS 180-4; tiền tố DigestInfo lấy từ RFC 8017 §9.2; bảng ngưỡng Miller–Rabin tất định theo
Jaeschke (1993) và Sorenson–Webster (2015).

**Sử dụng công cụ AI**: `<nhóm ghi rõ — ví dụ: dùng Claude (Anthropic) để dựng khung repo,
gợi ý cấu trúc mã và bản thảo báo cáo; nhóm đã đọc lại, chạy kiểm thử, chỉnh sửa, và tự viết
phần …>`

---

## Phụ lục A. Bảng phân công công việc

Xem `docs/phan-cong.md`.

## Phụ lục B. Hướng dẫn chạy

Xem `README.md`.
