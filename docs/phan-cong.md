# Bảng phân công công việc

> Điền tên thật, cả nhóm xác nhận. Gợi ý: mỗi người tự commit phần mình phụ trách lên GitHub
> để lịch sử commit thể hiện đóng góp (hướng dẫn khuyến khích).

| STT | Họ tên — MSSV | Phần phụ trách (gợi ý) | File/thư mục chính | Tỉ lệ đóng góp | Xác nhận |
|---|---|---|---|---|---|
| 1 | `<TV1>` | Nền toán học: Euclid mở rộng, bình phương và nhân, Miller–Rabin; bản thu nhỏ; ví dụ tính tay | `core/math_utils.py`, `core/tiny.py`, `docs/vi-du-tinh-tay.md` | `<%>` | |
| 2 | `<TV2>` | SHA-256, HMAC; test vector NIST/RFC | `core/sha256.py`, `core/hmac_sha256.py`, `tests/test_sha256_hmac.py` | `<%>` | |
| 3 | `<TV3>` | Sinh khoá, PKCS#1 v1.5 / PSS, đối chiếu `cryptography`; ký tệp | `core/keys.py`, `core/rsa_primitives.py`, `core/pkcs1.py`, `core/envelope.py`, `tests/test_pkcs1.py`, `tests/test_crosscheck_cryptography.py` | `<%>` | |
| 4 | `<TV4>` | Chứng thư, kịch bản tấn công, phân tích chứng thực/không chối bỏ | `core/certificate.py`, `attacks/demos.py`, báo cáo §3.5–3.7 | `<%>` | |
| 5 | `<TV5>` | Giao diện CLI/GUI, benchmark, slide, video demo | `ui/`, `benchmark.py`, slide, video | `<%>` | |

Tiến độ gợi ý:

| Tuần | Mốc |
|---|---|
| 1 | Đọc tài liệu Chương 3–4, chốt phân công, chạy thử repo, mỗi người đọc hiểu module được giao |
| 2 | Hoàn thiện mã + kiểm thử, ví dụ tính tay trên giấy khớp chương trình |
| 3 | Viết báo cáo theo mẫu khoa, vẽ sơ đồ, chụp màn hình |
| 4 | Slide, tập demo theo kịch bản, quay video dự phòng, nộp bài |
