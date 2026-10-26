# Sơ đồ khối

Các sơ đồ viết bằng Mermaid (GitHub hiển thị trực tiếp). Để chèn vào báo cáo/slide:
dán vào <https://mermaid.live> → *Export PNG/SVG*, hoặc `npx @mermaid-js/mermaid-cli -i so-do.md`.

## 1. Sinh khoá

```mermaid
flowchart TD
    A([Bắt đầu: số bit k, e = 65537]) --> B[Sinh ngẫu nhiên số lẻ k/2 bit<br/>đặt 2 bit cao = 1]
    B --> C{Chia thử cho<br/>số nguyên tố nhỏ}
    C -- chia hết --> B
    C -- không --> D{Miller–Rabin<br/>40 vòng}
    D -- hợp số --> B
    D -- nguyên tố --> E[Được p; lặp lại để được q ≠ p]
    E --> F["n = p·q ; φ(n) = (p−1)(q−1)"]
    F --> G{"gcd(e, φ(n)) = 1 ?"}
    G -- không --> B
    G -- có --> H["d = e⁻¹ mod φ(n)<br/>(Euclid mở rộng)"]
    H --> I["dP = d mod (p−1), dQ = d mod (q−1)<br/>qInv = q⁻¹ mod p"]
    I --> J([Khoá công khai (n, e)<br/>Khoá bí mật (n, d, p, q, dP, dQ, qInv)])
```

## 2. Ký trên giá trị băm (RSASSA-PSS)

```mermaid
flowchart LR
    M[/Thông điệp M/] --> H["SHA-256<br/>mHash = H(M)"]
    H --> P["EMSA-PSS:<br/>salt ngẫu nhiên, M' = 0⁸‖mHash‖salt<br/>H' = H(M'), DB = PS‖01‖salt<br/>maskedDB = DB ⊕ MGF1(H')<br/>EM = maskedDB‖H'‖BC"]
    P --> I["m = OS2IP(EM)"]
    I --> S["s = m^d mod n<br/>(bình phương và nhân + CRT)"]
    K[(Khoá bí mật d)] --> S
    S --> O[/Chữ ký S = I2OSP(s, k)/]
```

## 3. Kiểm tra chữ ký

```mermaid
flowchart LR
    S[/Chữ ký S/] --> V["m = s^e mod n"]
    PK[(Khoá công khai n, e)] --> V
    V --> E["EM = I2OSP(m)"]
    M[/Thông điệp M nhận được/] --> H["mHash = SHA-256(M)"]
    E --> C{"EMSA-PSS-Verify<br/>(EM, mHash)"}
    H --> C
    C -- khớp --> OK([Hợp lệ: toàn vẹn + đúng người ký])
    C -- không khớp --> BAD([Không hợp lệ])
```

## 4. Tổng quan ký / kiểm tra giữa hai bên

```mermaid
sequenceDiagram
    participant A as Alice (người ký)
    participant CA as CA (bên thứ ba tin cậy)
    participant B as Bob (người kiểm tra)
    A->>CA: Gửi khoá công khai (n, e) + giấy tờ định danh
    CA-->>A: Chứng thư: Sign_CA(Alice, n, e, thời hạn)
    Note over A: h = SHA-256(M)<br/>s = Encode(h)^d mod n
    A->>B: M, chữ ký s, chứng thư
    Note over B: 1. Kiểm tra chứng thư bằng khoá CA<br/>2. Lấy (n, e) của Alice từ chứng thư<br/>3. So s^e mod n với Encode(SHA-256(M))
    B-->>A: Chấp nhận — Alice không thể chối bỏ
```

## 5. Tấn công thay khoá công khai (kẻ đứng giữa)

```mermaid
sequenceDiagram
    participant A as Alice
    participant M as Mallory
    participant B as Bob
    A->>M: Khoá công khai của Alice (bị chặn)
    M->>B: Khoá của Mallory, ghi tên "Alice"
    M->>B: M' giả + chữ ký bằng khoá Mallory
    Note over B: Kiểm tra bằng "khoá Alice" ⇒ HỢP LỆ<br/>Bob bị lừa về danh tính
    Note over B,M: Phòng chống: khoá phải đi kèm chứng thư CA.<br/>Mallory không sửa được chứng thư vì không có khoá CA.
```

## 6. Kiến trúc mã nguồn

```mermaid
flowchart TB
    subgraph UI["rsasig/ui — giao diện"]
        CLI[cli.py] --- MENU[menu.py] --- GUI[gui.py]
    end
    subgraph ATK["rsasig/attacks"]
        DEMO[demos.py]
    end
    subgraph CORE["rsasig/core — thuật toán tự cài đặt"]
        MATH[math_utils.py<br/>Euclid, mod_pow, Miller–Rabin]
        SHA[sha256.py]
        HM[hmac_sha256.py]
        KEYS[keys.py]
        PRIM[rsa_primitives.py<br/>RSASP1 / RSAVP1, CRT]
        PK[pkcs1.py<br/>PKCS#1 v1.5, PSS]
        TINY[tiny.py<br/>bản thu nhỏ]
        ENV[envelope.py<br/>ký tệp]
        CERT[certificate.py]
    end
    UI --> CORE
    UI --> ATK
    ATK --> CORE
    KEYS --> MATH
    PRIM --> MATH
    PK --> PRIM
    PK --> SHA
    HM --> SHA
    TINY --> KEYS
    ENV --> PK
    CERT --> PK
```
