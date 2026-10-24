# serialized-object

- **Category:** Reverse Engineering / Forensics — Java Deserialization (nhận dạng định dạng + đọc giá trị ẩn).
- **File đề:** `D1-serialized-object/dataFile_e3347688032cb381a44796d46232ab9d`
  - Kích thước: **82 byte**
  - MD5: `e3347688032cb381a44796d46232ab9d` (chính là tên file — tên file = MD5 nội dung)
  - SHA1: `4d161ab281fc047bc1b0f3b1f0bd7b67dc4dbe4c`

## Tóm tắt đề
Đề của giải chỉ đưa duy nhất một file dữ liệu nhị phân nhỏ, không kèm lời dẫn. Nhiệm vụ: tự nhận dạng định dạng, đọc/giải mã để lấy giá trị bí mật bên trong rồi ghép thành flag. Đây là kiểu bài "nhận một mẩu byte lạ, hiểu nó là gì, moi thông tin ra".

## Phân tích (chi tiết)
Toàn bộ phân tích là **tĩnh** (đọc byte, tra đặc tả). Không chạy gì.

**Nhận dạng định dạng.** Chạy `file` lên đề:
```
dataFile_e3347688032cb381a44796d46232ab9d: Java serialization data, version 5
```
`file` kết luận dựa vào **magic bytes** đầu file. Xem hexdump bằng `xxd` (chỉ 82 byte nên đọc tay được trọn):
```
00000000: aced 0005 7372 000e 6a61 7661 2e6c 616e  ....sr..java.lan
00000010: 672e 4c6f 6e67 3b8b e490 cc8f 23df 0200  g.Long;.....#...
00000020: 014a 0005 7661 6c75 6578 7200 106a 6176  .J..valuexr..jav
00000030: 612e 6c61 6e67 2e4e 756d 6265 7286 ac95  a.lang.Number...
00000040: 1d0b 94e0 8b02 0000 7870 0000 0000 5588  ........xp....U.
00000050: 0711                                     ..
```

**Mổ xẻ luồng Java Serialization theo từng byte.** Một luồng `ObjectOutputStream` luôn mở đầu bằng `AC ED` (`STREAM_MAGIC`) + `00 05` (`STREAM_VERSION` = 5). Sau đó là các *tag byte* mô tả nội dung:

| Offset | Byte | Ý nghĩa |
|--------|------|---------|
| 0x00 | `ac ed` | STREAM_MAGIC |
| 0x02 | `00 05` | STREAM_VERSION = 5 |
| 0x04 | `73` (`'s'`) | TC_OBJECT — bắt đầu một object |
| 0x05 | `72` (`'r'`) | TC_CLASSDESC — mô tả class |
| 0x06 | `00 0e` | độ dài tên class = 14 |
| 0x08 | `java.lang.Long` | tên class (14 ký tự ASCII) |
| 0x16 | `3b 8b e4 90 cc 8f 23 df` | serialVersionUID của `Long` |
| 0x1e | `02` | cờ SC_SERIALIZABLE |
| 0x1f | `00 01` | số trường = 1 |
| 0x21 | `4a` (`'J'`) | kiểu trường = `long` (64-bit) |
| 0x22 | `00 05 "value"` | tên trường = `value` |
| 0x29 | `78` (`'x'`) | TC_ENDBLOCKDATA |
| ... | `72 ... "java.lang.Number"` | class cha = `Number` |
| 0x46 | `70` (`'p'`) | TC_NULL — hết chuỗi class cha |
| 0x47 | `00 00 00 00 55 88 07 11` | **giá trị long = 8 byte** |

**Vì sao biết là `Long`?** Trong luồng có chuỗi ASCII `java.lang.Long` và một trường `value` kiểu `J`. Theo đặc tả JVM, mỗi kiểu nguyên thuỷ có một ký tự: `I`=int(4B), `J`=**long(8B)**, `S`=short(2B), `B`=byte(1B), `Z`=boolean, `D`=double, `F`=float, `C`=char. Vậy object là một `java.lang.Long` kế thừa `java.lang.Number`, trường `value` kiểu `long`, và 8 byte cuối chính là giá trị.

**Kiểm chứng chéo serialVersionUID.** 8 byte sau tên class là `serialVersionUID` — "số phiên bản" để JVM kiểm tra tương thích khi deserialize. Với `java.lang.Long` là `0x3b8be490cc8f23df` (offset 0x16), với `java.lang.Number` là `0x86ac951d0b94e08b` (offset 0x3c). Hai giá trị cố định này khớp đúng byte trong hexdump ⇒ ta đọc đúng cấu trúc.

**Đọc 8 byte giá trị.** Java luôn **big-endian** (byte cao trước). `00 00 00 00 55 88 07 11` = `0x0000000055880711`. Vì là `long` nên phải đọc đủ 8 byte: 32 bit cao là `0x00000000`, 32 bit thấp là `0x55880711`. Nếu nhầm đọc 4 byte như `int` sẽ lấy phải phần cao `00 00 00 00` → ra 0 (sai).

Chuyển `0x55880711` sang thập phân:
- `0x55000000` = 1 426 063 360
- `0x00880711` = 8 914 705
- Tổng = **1 434 978 065**

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE.** Đây là bài nhận dạng định dạng + đọc dữ liệu, không khai thác lỗ hổng.
- **Nhận diện qua magic bytes `ac ed 00 05`.** VÌ SAO: bất kỳ file nào mở đầu `AC ED` gần như chắc chắn là một luồng `ObjectOutputStream` ghi ra đĩa. Nhận ra magic là bước quyết định — mọi forensics/reverse đều bắt đầu bằng xác định định dạng.
- **Đọc theo đặc tả Java Object Serialization.** VÌ SAO: định dạng có cấu trúc cố định (magic → class descriptor → classdata), nên có thể dò tay từng tag mà không cần chạy.
- **(Liên hệ bảo mật) Insecure Deserialization — OWASP Top 10.** Cùng cơ chế `readObject()` là nguồn của lớp lỗ hổng RCE khi deserialize dữ liệu do kẻ tấn công kiểm soát (gadget chain Apache Commons Collections, công cụ `ysoserial`). Bài này lành tính (chỉ một `Long`) nhưng hiểu cơ chế giúp nhận ra vì sao "deserialize dữ liệu lạ" là nguy hiểm.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
**Cách 1 — đọc thẳng 8 byte cuối (tĩnh, khuyến nghị):**
```python
import struct
data = open("dataFile_e3347688032cb381a44796d46232ab9d", "rb").read()
value = struct.unpack(">q", data[-8:])[0]   # ">q" = big-endian signed 64-bit
print(value)                                 # 1434978065
```
`>` = big-endian, `q` = signed 64-bit. Vì `Long` chỉ bọc một con số nên đọc 8 byte cuối là xong.

**Cách 2 — deserialize đúng chuẩn Java:**
```java
import java.io.*;
public class Solve {
    public static void main(String[] args) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(
                new FileInputStream("dataFile_e3347688032cb381a44796d46232ab9d"))) {
            Object o = in.readObject();   // JVM dựng lại thành java.lang.Long
            System.out.println(o);        // 1434978065
        }
    }
}
```
Biên dịch & chạy: `javac Solve.java && java Solve` → in `1434978065`.
`readObject()` đọc magic, class descriptor, rồi 8 byte value để tạo `Long(1434978065L)`; `println` gọi `toString()`.

**Cách 3 — xem cấu trúc cây bằng `SerializationDumper` (NickstaDB)** nếu muốn trực quan luồng mà không viết code:
```
STREAM_MAGIC - 0xac ed
STREAM_VERSION - 5
Contents
  TC_OBJECT
    TC_CLASSDESC
      className: java.lang.Long
      serialVersionUID: 0x3b8be490cc8f23df
      classDescFlags: 0x02 (SC_SERIALIZABLE)
      fieldCount: 1 -> name: value, type: long (J)
      superClassDesc: java.lang.Number
    classdata: value = 1434978065  (0x0000000055880711)
```

## Flag
flag{1434978065}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** file lạ, `file` báo "Java serialization data"; hexdump mở đầu `ac ed 00 05`.
- **Quy trình:**
  1. `file <x>` và `xxd <x> | head` để xác nhận magic `ac ed`.
  2. Đọc phần đầu luồng (ASCII) để biết class được serialize (`java.lang.Long`, `java.util.HashMap`, class tự định nghĩa...).
  3. Class chuẩn của JDK → viết `ObjectInputStream.readObject()` để deserialize và in; hoặc với type bọc số, đọc thẳng byte cuối theo ký tự kiểu.
  4. Class tự định nghĩa → cần `.class`/`.jar` tương ứng trên classpath mới deserialize được; nếu không, đọc tay hoặc dùng `SerializationDumper`.
- **Công cụ:** `file`, `xxd`/`hexdump`, JDK (`javac`/`java`), `SerializationDumper`, Python `struct`.
- **Bẫy:**
  - Java luôn **big-endian** — đọc little-endian ra số sai.
  - Khớp số byte với ký tự kiểu: `I`=4, `J`=8, `S`=2, `B`=1, `D`=8, `F`=4, `C`=2, `Z`=1. Đọc `long` mà chỉ lấy 4 byte sẽ sai.
  - Đừng cố "chạy" file hay `strings` rồi bối rối — mấu chốt là magic `ac ed`.
  - Deserialize dữ liệu **không tin cậy** có rủi ro RCE (gadget chain) — ở đây chỉ `Long` nên vô hại.
- **Checklist ngắn:** magic `ac ed` → xác định class → deserialize (JDK) hoặc đọc 8 byte cuối big-endian → đổi hex → dec.
