# Ví dụ tính tay — chữ ký RSA thu nhỏ

> Mọi số liệu dưới đây trùng khớp với đầu ra của `python -m rsasig tiny -m HELLO`
> và được kiểm thử tự động trong `tests/test_tiny.py` (`test_hand_example_hello`,
> `test_textbook_sign_hash_65`). Nếu giảng viên đưa bộ số khác, chạy
> `python -m rsasig tiny -p <p> -q <q> -e <e> --hash <h>` để có bảng tương ứng.

Tham số: **p = 61, q = 53, e = 17**, thông điệp **M = "HELLO"**.

## 1. Sinh khoá

### 1.1. Kiểm tra p, q nguyên tố (Miller–Rabin)

Với n < 2047, chỉ cần thử cơ sở a = 2 là kết luận chắc chắn.

| n  | n − 1 = 2^s · d | x = 2^d mod n | bình phương tiếp | kết luận |
|----|-----------------|---------------|------------------|----------|
| 61 | 60 = 2² · 15    | 2^15 mod 61 = 11 | 11² = 121 ≡ 60 = n − 1 | qua ⇒ nguyên tố |
| 53 | 52 = 2² · 13    | 2^13 mod 53 = 30 | 30² = 900 ≡ 52 = n − 1 | qua ⇒ nguyên tố |

### 1.2. Tính n và φ(n)

- n = p · q = 61 · 53 = **3233**
- φ(n) = (p − 1)(q − 1) = 60 · 52 = **3120**
- e = 17, gcd(17, 3120) = 1 ⇒ hợp lệ.

### 1.3. Tính d = e⁻¹ mod φ(n) bằng Euclid mở rộng

Mỗi dòng giữ bất biến r = 3120·s + 17·t.

| q   | r    | s   | t    |
|-----|------|-----|------|
|     | 3120 | 1   | 0    |
|     | 17   | 0   | 1    |
| 183 | 9    | 1   | −183 |
| 1   | 8    | −1  | 184  |
| 1   | **1**| 2   | **−367** |
| 8   | 0    | −17 | 3120 |

Dòng có r = 1: 3120·2 + 17·(−367) = 1 ⇒ d ≡ −367 ≡ **2753** (mod 3120).
Kiểm tra: 17 · 2753 = 46801 = 15 · 3120 + 1 ✔

- Khoá công khai: **(n, e) = (3233, 17)**
- Khoá bí mật: **(n, d) = (3233, 2753)**

## 2. Băm thông điệp

```
SHA-256("HELLO") = 3733cd977ff8eb18b987357e22ced99f46097f31ecb239e878ae63760e83e4d5
h = SHA-256("HELLO") mod 3233 = 820
```

(SHA-256 không tính tay được; ở bản thu nhỏ ta rút gọn giá trị băm về đoạn [0, n − 1].
Đây là điểm yếu cố ý của bản thu nhỏ — xem demo `tiny_collision`.)

## 3. Ký: s = h^d mod n = 820^2753 mod 3233

d = 2753 = **101011000001**₂. Thuật toán bình phương và nhân, duyệt bit từ trái sang phải:
mỗi bit thì bình phương; nếu bit = 1 thì nhân thêm 820.

| bit | bình phương (mod 3233) | × 820 (nếu bit = 1) | kết quả |
|-----|------------------------|---------------------|---------|
| 1 | 1² = 1        | 1 · 820 = 820     | 820  |
| 0 | 820² ≡ 3169   | –                 | 3169 |
| 1 | 3169² ≡ 863   | 863 · 820 ≡ 2866  | 2866 |
| 0 | 2866² ≡ 2136  | –                 | 2136 |
| 1 | 2136² ≡ 733   | 733 · 820 ≡ 2955  | 2955 |
| 1 | 2955² ≡ 2925  | 2925 · 820 ≡ 2847 | 2847 |
| 0 | 2847² ≡ 278   | –                 | 278  |
| 0 | 278² ≡ 2925   | –                 | 2925 |
| 0 | 2925² ≡ 1107  | –                 | 1107 |
| 0 | 1107² ≡ 142   | –                 | 142  |
| 0 | 142² ≡ 766    | –                 | 766  |
| 1 | 766² ≡ 1583   | 1583 · 820 ≡ 1627 | **1627** |

Chữ ký: **s = 1627**. Chỉ cần 12 phép bình phương + 5 phép nhân thay vì 2752 phép nhân.

### 3.1. Kiểm tra chéo bằng CRT (cách ký nhanh)

- dP = d mod (p − 1) = 2753 mod 60 = 53; dQ = d mod (q − 1) = 2753 mod 52 = 49
- qInv = 53⁻¹ mod 61 = 38
- s₁ = (820 mod 61)^53 mod 61 = 27^53 mod 61 = 41
- s₂ = (820 mod 53)^49 mod 53 = 25^49 mod 53 = 37
- h' = qInv · (s₁ − s₂) mod p = 38 · 4 mod 61 = 30
- s = s₂ + h' · q = 37 + 30 · 53 = **1627** ✔ (trùng kết quả trên)

## 4. Kiểm tra: h' = s^e mod n = 1627^17 mod 3233

e = 17 = **10001**₂.

| bit | bình phương | × 1627 | kết quả |
|-----|-------------|--------|---------|
| 1 | 1      | 1627 | 1627 |
| 0 | 2535   | –    | 2535 |
| 0 | 2254   | –    | 2254 |
| 0 | 1473   | –    | 1473 |
| 1 | 386    | 386 · 1627 ≡ 820 | **820** |

h' = 820 = h ⇒ **chữ ký hợp lệ**.

## 5. Thông điệp bị sửa

Người nhận nhận được "HELLo" (sửa 1 chữ): h = SHA-256("HELLo") mod 3233 = **3106**.
Vẫn tính được s^e mod n = 820 ≠ 3106 ⇒ **chữ ký không hợp lệ**.

## 6. Ví dụ giáo trình kinh điển (h cho trước)

Với h = 65: s = 65^2753 mod 3233 = **588**; kiểm tra 588^17 mod 3233 = 65 ✔
(`python -m rsasig tiny --hash 65`).
