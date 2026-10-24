# cdn-identify

- **Category:** OSINT / Network reconnaissance — nhận diện nhà cung cấp CDN qua phân giải DNS.
- **File đề:** Không có file. Đề cho host `jpn.nec.com`, cần xác định **nhà cung cấp CDN** nào đang phục vụ nó.

## Tóm tắt đề
Cho một tên miền, xác định CDN (Content Delivery Network) đứng sau. Flag chính là **tên nhà cung cấp** (viết thường).

## Phân tích (chi tiết)
**CDN là gì.** Mạng lưới nhiều máy chủ "biên" (edge) đặt rải rác toàn cầu, giữ bản sao nội dung để phục vụ người dùng từ điểm *gần nhất* → nhanh hơn, chịu tải tốt, chống DDoS. Nhà cung cấp lớn: Akamai, Cloudflare, Fastly, Amazon CloudFront, Google Cloud CDN, Azure CDN...

**DNS & bản ghi CNAME — chìa khoá nhận diện.** DNS dịch tên miền → IP. Một **CNAME** (Canonical Name) là *bí danh*: tên A trỏ sang tên B. Khi một site dùng CDN, tên miền của họ thường CNAME tới tên miền của CDN. Nhìn "đuôi" domain đích là đoán được CDN:

| Đuôi CNAME | CDN |
|------------|-----|
| akamaiedge.net, akamai.net, edgekey.net, edgesuite.net | **Akamai** |
| cloudfront.net | Amazon CloudFront |
| fastly.net, fastlylb.net | Fastly |
| cdn.cloudflare.net | Cloudflare |
| azureedge.net | Microsoft Azure CDN |
| cdngc.net, gccdn.net | CDNetworks |

**Phân giải host của đề.** Khi `ping` (hay `dig`), hệ thống phân giải DNS trước và in hostname đích:
```bash
ping jpn.nec.com
# PING e13694.b.akamaiedge.net (125.252.231.135) ...
```
`jpn.nec.com` CNAME tới `e13694.b.akamaiedge.net`, IP `125.252.231.135`. Đuôi `akamaiedge.net` ⇒ **Akamai**.

Xác nhận rõ chuỗi CNAME:
```bash
dig +short jpn.nec.com
# jpn.nec.com.edgekey.net.
# e13694.b.akamaiedge.net.
# 125.252.231.135
```
Cả `edgekey.net` lẫn `akamaiedge.net` đều là hạ tầng Akamai → kết luận chắc chắn.

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE.** Đây là bài OSINT/recon thuần, chỉ tra cứu DNS.
- **Nhận diện CDN qua CNAME/hostname khi phân giải DNS.**
  - VÌ SAO: khi phân giải tên miền, hostname trung gian lộ domain thuộc hạ tầng CDN (`akamaiedge.net` → Akamai). Đây là cách chắc nhất và nhất quán theo mọi vị trí địa lý (dù IP trả về có thể khác nhau do CDN trả IP gần bạn nhất).
- **Cách nhận diện bổ trợ (nên chéo nhiều cách):**
  1. **CNAME** (chắc nhất): `dig +short CNAME jpn.nec.com`.
  2. **Header HTTP:** `curl -sI https://jpn.nec.com` xem `Server:` (Akamai hay để `AkamaiGHost`), `X-Cache:` (`TCP_HIT from ...`), `X-Akamai-*`, `Via:`.
  3. **Dải IP / ASN:** `whois 125.252.231.135` → thuộc AS của Akamai.
  4. **Công cụ web:** builtwith.com, whatcdn, cdnplanet, extension Wappalyzer, securitytrails.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. Phân giải tên miền:
   ```bash
   ping jpn.nec.com
   # PING e13694.b.akamaiedge.net (125.252.231.135): 56 data bytes
   ```
   hoặc trực quan chuỗi CNAME:
   ```bash
   dig jpn.nec.com
   nslookup jpn.nec.com
   ```
2. Hostname `e13694.b.akamaiedge.net` chứa `akamaiedge.net` → đối chiếu bảng dấu vân tay → CDN là **Akamai**.
3. Flag là tên nhà cung cấp viết thường.

## Flag
flag{akamai}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** đề hỏi "CDN nào phục vụ domain X" → bài toán tra cứu DNS.
- **Quy trình:**
  1. `dig <domain> +short` / `nslookup <domain>` / `ping <domain>` để lấy CNAME/hostname đích.
  2. Đối chiếu hậu tố hostname với bảng dấu vân tay CDN.
  3. Nếu CNAME không lộ (vd Cloudflare hay ẩn): dùng header HTTP (`X-Cache`, `Server`, `Via`) hoặc tra ASN của IP.
- **Công cụ:** `dig`, `nslookup`, `ping`, `whois`, `curl -I`; dịch vụ web whatcdn/builtwith/securitytrails; Wappalyzer.
- **Bẫy:**
  - Chỉ nhìn IP có thể nhầm — ưu tiên tra **CNAME**.
  - Kết quả DNS khác theo vị trí địa lý (CDN trả IP gần bạn) nhưng đuôi CNAME thì nhất quán.
  - Flag thường là tên thương hiệu viết thường (`akamai`), không phải cả hostname; thử cả dạng thường/hoa khi nộp.
- **Checklist ngắn:** resolve DNS → đọc CNAME → map hậu tố → lấy tên hãng.
