# Dàn ý slide thuyết trình (~15–18 slide)

1. **Tiêu đề** — Hệ chữ ký điện tử RSA: ký trên giá trị băm, tính chứng thực & không chối bỏ. Tên nhóm, thành viên.
2. **Vấn đề** — Chữ ký tay trong thế giới số? 3 yêu cầu: toàn vẹn, xác thực, không chối bỏ.
3. **Bối cảnh lịch sử** — Diffie–Hellman 1976 → RSA 1977/78 → PKCS#1 1993 → PSS 1996 → RFC 8017 (2016). Ứng dụng: HTTPS, ký phần mềm, hoá đơn điện tử, Luật GDĐT 2023.
4. **Nền toán học** — Euler, Euclid mở rộng, bình phương và nhân, Miller–Rabin (1 slide, có công thức).
5. **Sinh khoá** — sơ đồ khối (docs/so-do.md §1).
6. **Ký & kiểm tra trên giá trị băm** — sơ đồ khối §2, §3. Vì sao phải băm.
7. **PKCS#1 v1.5 và PSS** — cấu trúc khối EM (vẽ các ô byte).
8. **Ví dụ tính tay (1/2)** — p = 61, q = 53, e = 17; bảng Euclid mở rộng ⇒ d = 2753.
9. **Ví dụ tính tay (2/2)** — h = 820, bảng bình phương và nhân ⇒ s = 1627; kiểm tra ⇒ 820. "Khớp với chương trình."
10. **Kiến trúc cài đặt** — sơ đồ §6; nguyên tắc không dùng thư viện mật mã; kiểm thử 108 ca + đối chiếu NIST/RFC/OpenSSL.
11. **DEMO TRỰC TIẾP** (theo docs/kich-ban-demo.md).
12. **Tính chứng thực** — chữ ký chứng thực "khoá", PKI chứng thực "người"; sơ đồ tấn công thay khoá §5.
13. **Tính không chối bỏ** — RSA vs HMAC; bảng "luận điểm chối bỏ ↔ biện pháp" (báo cáo §3.6).
14. **Phân tích an toàn** — bảng độ dài khoá ↔ mức an toàn; bảng tấn công đã biết.
15. **Hiệu năng** — bảng benchmark: CRT vs không CRT, ký vs kiểm tra, băm vs lũy thừa theo kích thước tệp.
16. **So sánh** — RSA vs DSA vs ECDSA vs Ed25519 vs HMAC.
17. **Kết luận & hướng phát triển** — hậu lượng tử ML-DSA.
18. **Phân công & cảm ơn** — bảng phân công, ghi chú sử dụng AI.

Lưu ý từ hướng dẫn: sơ đồ phải do nhóm tự vẽ (xuất từ Mermaid trong docs/so-do.md hoặc vẽ lại), không chụp slide bài giảng.
