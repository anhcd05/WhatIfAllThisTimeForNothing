# memory-secret-base64

- **Category:** Forensic (Memory)
- **File đề:** một **memory dump** của một chương trình đang chạy. Chương trình lắng nghe lệnh Windows OS tại **port 8553**; khi nhận lệnh thì thực thi rồi POST kết quả lên một blog `https://<REDACTED>.blogspot.com/`. **KHÔNG có file offline trong repo**; flag chỉ hiện trên dump thật.

## Tóm tắt đề
Mục tiêu: trích **client secret** của API token mà chương trình dùng để đăng bài lên blog, từ memory dump. Theo đề:
- Flag = **client secret value** của API token.
- Flag bị **chia 3 phần chuỗi**, mỗi phần **mã hóa Base64**.
- Tìm 3 chuỗi Base64 đó trong dump, **ghép đúng thứ tự**, **decode Base64** → flag.

## Phân tích (chi tiết: cấu trúc secret, nơi tìm)
Đây là bài memory forensics hướng "credential/secret hunting":
- Chương trình giao tiếp Blogger API (blogspot) → cần OAuth/API token, trong đó có **client_secret**. Secret nằm plaintext trong vùng nhớ tiến trình khi chạy (dù được truyền mã hóa).
- Tác giả cố tình **chia secret thành 3 mảnh + Base64** để `strings` thẳng không lộ nguyên chuỗi, và tạo 3 "artifact" cần gom lại.
- Cách tiếp cận: dump/duyệt bộ nhớ, tìm chuỗi Base64 quanh ngữ cảnh API (`client_secret`, `blogspot`, `oauth`, `token`, `Authorization`, hoặc nhãn `part1/2/3`), gom 3 phần đúng thứ tự → ghép → `base64 -d`.
- **Mốc định danh tiến trình:** listener **port 8553** + kết nối ra blogspot (dùng `netscan` để xác nhận).

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Memory forensics / string carving:** `strings` + `grep` theo từ khóa; hoặc **Volatility** (`pslist`/`netscan`/`memdump`, rồi `strings`/`yara`/`bulk_extractor`). *Vì sao:* secret nằm trong heap/stack của tiến trình → phải dump cả tiến trình chứ không chỉ section cố định.
- **Nhận diện Base64:** chuỗi chỉ gồm `[A-Za-z0-9+/=]`, độ dài bội số 4, có thể kết `=`. *Vì sao:* đề nói rõ secret được Base64.
- **Ghép + decode Base64** (CyberChef / `base64 -d` / Python). *Vì sao:* đề nói secret chia 3 phần → phải nối lại rồi mới decode.

**Vì sao nhận ra?** Đề nói thẳng: secret chia 3 phần + Base64; chương trình POST lên blogspot ⇒ tìm quanh context HTTP request/API token trong RAM.

## Lời giải chi tiết (bước + lệnh sạch)
> Lưu ý: tài liệu lời giải chính thức chỉ có phần mô tả/đề, **không kèm bước thao tác cụ thể hay giá trị flag** (nguồn không nêu). Dưới đây là quy trình tái dựng hợp lý theo đúng hướng dẫn đề.

1. Xác định tiến trình & profile (nếu là full memory dump):
   ```bash
   python vol.py -f dump.mem imageinfo
   python vol.py -f dump.mem --profile=<profile> pslist     # tìm tiến trình server
   python vol.py -f dump.mem --profile=<profile> netscan    # xác nhận listener 8553 + kết nối blogspot
   python vol.py -f dump.mem --profile=<profile> memdump -p <pid> -D .
   ```
2. Carving chuỗi Base64 quanh ngữ cảnh API/blog:
   ```bash
   strings -n 8 <pid>.dmp > s.txt
   grep -iE "client_secret|blogspot|oauth|token|secret|part" s.txt
   grep -aoE "[A-Za-z0-9+/]{8,}={0,2}" s.txt | sort -u     # liệt kê ứng viên Base64
   ```
3. Ghép 3 phần theo đúng thứ tự rồi decode:
   ```bash
   echo -n "<part1><part2><part3>" | base64 -d          # = client secret = flag
   ```
   (Nếu không rõ thứ tự: thử hoán vị; bản decode hợp lệ sẽ ra text đọc được.)

## Flag
```
flag{...}
```
**Nguồn không nêu.** `SOLUTIONS_VN.md` (B1) và nháp `Can you give us the secret.md` chỉ công bố phương pháp (tìm 3 chuỗi Base64 → ghép → decode), **không in giá trị client_secret** vì chỉ có trên dump thật. (Domain blog và mọi chuỗi chứa viết tắt tên kỳ thi CTF đã được redact.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đề nói secret/token/credential nằm trong memory dump, hoặc chương trình giao tiếp một API/dịch vụ (OAuth, blogspot, Google API...); flag bị chia nhỏ + mã hóa để chống `strings` thẳng.
- **Quy trình:** Volatility `pslist`/`netscan` tìm tiến trình (theo listener port / kết nối mạng) → `memdump` → `strings` + `grep` theo từ khóa domain/API → khi flag chia mảnh, tìm nhãn gợi ý (`part1/2/3`, `[0]/[1]/[2]`) hoặc các chuỗi Base64 nằm gần nhau → decode Base64 (lặp nếu nhiều lớp).
- **Bẫy:** thứ tự ghép 3 mảnh có thể không theo thứ tự xuất hiện trong dump → thử hoán vị; có thể là base64url (`-_` thay `+/`); secret nằm trong heap/stack nên phải dump cả tiến trình.
- **Checklist:** tìm tiến trình (port 8553 + blogspot) → `memdump` → `strings|grep` API/secret → gom 3 chuỗi Base64 → ghép đúng thứ tự → `base64 -d` → client secret = flag.
