# c2-request-forge

- **Category:** Reversing / phân tích hành vi C2 (trong PDF gốc gắn nhãn Web)
- **File đề:** Không có file tải riêng — dùng mã độc PHP đã deobfuscate ở bài `quarantine-vsbx` để **giả request đúng cách** tới C2 server sống và lấy flag.

## Tóm tắt đề
Tiếp nối `quarantine-vsbx`: đã có mã độc PHP. Malware này thuộc chiến dịch **"Japanese Keyword Hack" / Blackhat SEO**, biến website bị hack thành **redirector**. Nhiệm vụ: truy vấn C2 đúng cách (giả đúng "nạn nhân mục tiêu") để lấy flag, phục vụ lập blocklist.

**Cảnh báo đề:** KHÔNG khai thác lỗ hổng của C2 — đây **không** phải bài PWN. Chỉ mô phỏng client, tránh làm sập môi trường dùng chung.

## Phân tích (chi tiết: tham số/endpoint/logic cloaking)
Từ PHP đã giải (bài 1), trích đủ tham số giao thức C2:
- **C2 domain** `service.myshop.trend` — bị **mã hóa trong biến `$xmlname`** (phải giải từ PHP đã deobfuscate).
- Bộ tham số query mà malware gửi lên C2 (endpoint `/indexnew.php`):
  - `web` = FQDN site bị deface.
  - `zz` = `0`/`1` — truy cập có phải bot search engine hay không.
  - `uri` = URI đã URL-encode (vd `%2Fsitemap%2Exml` = `/sitemap.xml`).
  - `urlshang` = referrer (URL-encode).
  - `http` = `http`/`https`.
  - `lang` = `HTTP_ACCEPT_LANGUAGE` (URL-encode).

**Logic cloaking** (phục vụ nội dung khác nhau cho từng khách để né phát hiện):
- **Bot Google** (`zz=1`): nhận `sitemap.xml` khổng lồ + nội dung spam từ khóa Nhật → để Google index các URL giả.
- **Người Nhật đến từ search engine** (`zz=0`, `lang` chứa `ja`, referrer google/bing/yahoo): nhận trang **chuyển hướng** tới site EC giả — "nạn nhân mục tiêu".
- **Mọi trường hợp khác** (admin/researcher/truy cập trực tiếp): nhận **trang dummy/404** → tưởng site bình thường.

⇒ Để C2 "nhả" nội dung thật, phải **giả đúng cả 3 điều kiện** `zz`, `lang=ja*`, `urlshang=google|bing|yahoo`. Chỉ lọc theo IP/host sẽ trượt.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Reverse tham số giao thức từ PHP đã deobfuscate:** VÌ SAO: C2 chỉ trả sitemap + trang flag khi request khớp hành vi malware mong đợi; đoán sai tên biến (`$xmlname`...) → chỉ nhận dummy.
- **Mô phỏng cloaking của SEO poisoning:** gửi referrer search engine + `lang=ja` để C2 tưởng là nạn nhân Nhật đến từ kết quả tìm kiếm → mới trả trang độc chứa flag.
- **Viết client vòng lặp qua sitemap:** VÌ SAO: ~2000 URL, phần lớn dummy; cần script lọc tự động trang bất thường.

## Lời giải chi tiết (bước + code sạch)
1. **Lấy sitemap** (giả bot): gọi `/indexnew.php` với `zz=1`, `uri=%2Fsitemap%2Exml` → nhận `sitemap.xml` (~2000 URL).
2. **Duyệt từng URI** (giả nạn nhân Nhật): `zz=0`, `uri=<path URL-encode>`, `lang` chứa `ja`, `urlshang` chứa google/bing/yahoo.
3. Hầu hết response là HTML dummy chuyển hướng `bogusec.example.com` → kiên nhẫn bỏ qua.
4. Khi gọi tới **`/200095etidm62z.htm`** (một URI trong sitemap) với bộ tham số đúng ở bước 2 → **nhận flag**.
```python
import requests, urllib.parse
C2 = "http://service.myshop.trend"
base = {"zz":"0","http":"https","lang":"ja-JP,ja;q=0.9",
        "urlshang": urllib.parse.quote("https://www.google.com/","")}
r = requests.get(f"{C2}/indexnew.php", params={**base,"zz":"1","uri":"%2Fsitemap%2Exml"})
urls = extract_urls(r.text)                      # ~2000 URL
for u in urls + ["/200095etidm62z.htm"]:
    p = {**base, "uri": urllib.parse.quote(urllib.parse.urlparse(u).path, "")}
    if "flag" in requests.get(f"{C2}/indexnew.php", params=p).text:
        print("FLAG trang:", u)
```

## Flag
flag{H4ck3dCMS}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** bài tiếp nối sau deobfuscate malware; khái niệm "Japanese Keyword Hack"/SEO poisoning; malware phân biệt bot vs người dùng (cloaking) qua `zz`/`lang`/referrer.
- **Quy trình:** (1) trích đủ tên tham số + endpoint từ malware (đừng đoán); (2) lấy sitemap trước (`zz=1`, `uri=/sitemap.xml`); (3) duyệt từng URI với profile "nạn nhân Nhật từ Google" (`zz=0`, `lang=ja`, referrer google/bing/yahoo); (4) script hóa, lọc dummy, tìm trang lạ chứa flag.
- **Công cụ:** `curl`/Python requests, CyberChef (URL-encode).
- **Bẫy:** quên URL-encode `uri`/`urlshang`; thiếu `lang=ja` hoặc referrer → chỉ dummy; **KHÔNG** khai thác lỗ hổng C2 (vi phạm luật, dễ sập môi trường).
