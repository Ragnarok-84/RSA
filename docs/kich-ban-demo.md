# Kịch bản demo trên lớp (5–7 phút)

Chuẩn bị trước (không làm trên lớp):

```powershell
.venv\Scripts\activate
python -m rsasig keygen --bits 2048 --name Alice --out keys/alice   # sinh sẵn để không phải chờ
python -m rsasig keygen --bits 2048 --name Mallory --out keys/mallory
copy samples\hop_dong.txt samples\hop_dong_backup.txt
```

Mở terminal phông chữ lớn (≥ 16pt) hoặc dùng GUI: `python -m rsasig gui`.
Quay sẵn video dự phòng 3–5 phút theo đúng kịch bản này.

| Thời gian | Người trình bày | Nội dung | Lệnh / thao tác | Điều cần nói |
|---|---|---|---|---|
| 0:00–1:30 | `<TV1>` | Bản thu nhỏ — khớp ví dụ tính tay | `python -m rsasig tiny -m HELLO --tamper HELLo` | Chỉ vào bảng Euclid mở rộng (d = 2753), bảng bình phương và nhân (s = 1627), so với slide tính tay. Sửa 1 chữ ⇒ h = 3106 ≠ 820. |
| 1:30–3:00 | `<TV2>` | Bản đầy đủ — ký tệp thật | `python -m rsasig sign --key keys/alice.priv.json --file samples/hop_dong.txt` rồi `python -m rsasig verify --pub keys/alice.pub.json --file samples/hop_dong.txt` | Ký 1 lần lũy thừa dù tệp dài bao nhiêu; 3 dòng [OK]: toàn vẹn, đúng khoá, đúng chữ ký. |
| 3:00–3:45 | `<TV2>` | Sửa hợp đồng | Mở `samples/hop_dong.txt`, đổi `120.000.000` → `12.000.000`, chạy lại verify | [XX] băm không khớp ⇒ CHỮ KÝ KHÔNG HỢP LỆ. Khôi phục tệp gốc sau đó. |
| 3:45–4:30 | `<TV3>` | Ký ảnh + sai khoá | `python -m rsasig sign --key keys/alice.priv.json --file samples/anh_mau.png` rồi `python -m rsasig verify --pub keys/mallory.pub.json --file samples/anh_mau.png` | Tệp nhị phân cũng ký được; kiểm tra bằng khoá khác ⇒ sai. |
| 4:30–5:30 | `<TV3>` | Tính chứng thực | `python -m rsasig attack key_substitution` | Toán học đúng nhưng danh tính sai ⇒ cần CA/chứng thư. |
| 5:30–6:15 | `<TV4>` | Không chối bỏ | `python -m rsasig attack repudiation` | HMAC: Bob tạo được thẻ y hệt ⇒ Alice chối được. RSA: chỉ Alice có d. |
| 6:15–7:00 | `<TV4>` | Vì sao phải băm + băm phải mạnh | `python -m rsasig attack tiny_collision` (và nếu còn giờ: `multiplicative`) | ~100 lần thử đã tìm được va chạm vì chỉ có 3233 giá trị ⇒ SHA-256 đầy đủ cần ~2¹²⁸. |

Câu hỏi bảo vệ thường gặp — mỗi thành viên nên trả lời được:

1. Tại sao ký trên giá trị băm mà không ký trực tiếp thông điệp?
2. Vì sao e = 65537? Có thể chọn e = 3 không, rủi ro gì?
3. Miller–Rabin khác Fermat thế nào? Số Carmichael là gì?
4. CRT giúp ký nhanh hơn bao nhiêu, và tại sao nó tạo ra nguy cơ tấn công lỗi?
5. PKCS#1 v1.5 khác PSS ở đâu? Vì sao v1.5 tất định còn PSS thì không?
6. Chữ ký RSA chứng thực được "ai"? Tại sao vẫn cần CA?
7. HMAC có tính không chối bỏ không? Vì sao?
8. Nếu khoá bí mật bị lộ thì những chữ ký cũ còn giá trị không? (thu hồi, dấu thời gian)
9. RSA-2048 an toàn tương đương bao nhiêu bit? Máy tính lượng tử ảnh hưởng thế nào?
10. Giải thích một hàm bất kỳ trong `rsasig/core` (giảng viên có thể chỉ định).
