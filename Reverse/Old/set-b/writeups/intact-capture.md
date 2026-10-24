# intact-capture

- **Category:** Network
- **File đề:** `intact-capture/8688e1a1263c414450b12985e0d5620b.pcapng` (12040 bytes, md5 `8688e1a1263c414450b12985e0d5620b` — **khớp tên**, file nguyên bản; sha1 `069549649cb3e41bcaba9a2c6f5a62cf4b6b2bb1`). (`README.md` rỗng, không có lời giải sẵn; file pcapng còn nguyên vẹn và mở được.)

## Tóm tắt đề

Bài Network 80đ. Repo **không có lời giải sẵn** nhưng file pcapng **còn nguyên vẹn** (md5 khớp tên) nên có thể phân tích. Tên "Intact" ("nguyên vẹn") có thể gợi kiểm tra **tính toàn vẹn** / ghép lại một file bị chia nhỏ trong luồng. Phần dưới là playbook phân tích pcap.

## Phân tích (chi tiết)

Đây là bài phân tích gói tin. Vì không có lời giải, suy luận từ tên + mức điểm:
- "Intact" có thể ám chỉ phải **ghép lại** (reassemble) một file/đối tượng truyền qua mạng sao cho còn nguyên vẹn, hoặc kiểm tra checksum.
- File pcapng nhỏ (12 KB) nên lượng gói ít, dễ soi thủ công.

Hướng chuẩn khi mở pcap:
1. `Statistics > Protocol Hierarchy` / `Conversations` để nắm giao thức chính (HTTP/FTP/SMB/DNS...).
2. `File > Export Objects` (HTTP/SMB/FTP/IMF) để rút file được truyền.
3. `Follow Stream` đọc payload thô.
4. `strings` toàn file pcapng để quét nhanh flag/chuỗi gợi ý.

Vì không có lời giải, không thể xác nhận flag — nhưng file còn tải được, có thể phân tích thêm nếu cần.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Protocol Hierarchy / Conversations** — VÌ cần biết giao thức nào mang dữ liệu trước khi đào sâu.
- **Export Objects / Follow Stream** — VÌ flag thường nằm trong file được truyền hoặc payload một stream cụ thể.
- **`strings` quét nhanh** — VÌ pcap nhỏ, flag text có thể lộ ngay mà không cần phân tích sâu.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```bash
# Quét nhanh:
strings intact-capture/8688e1a1263c414450b12985e0d5620b.pcapng | grep -iE 'flag\{'

# Trong Wireshark:
#   Statistics > Protocol Hierarchy   -> xác định giao thức chính
#   File > Export Objects > HTTP/SMB/FTP  -> rút file truyền (có thể là ảnh/zip chứa flag)
#   Chuột phải 1 gói > Follow > TCP/HTTP Stream  -> đọc payload

# Bằng tshark:
tshark -r <file>.pcapng -q -z io,phs        # protocol hierarchy
tshark -r <file>.pcapng --export-objects http,./out   # rút object HTTP
```

Nếu "Intact" là ghép file: tìm các gói mang mảnh dữ liệu (theo offset/sequence), ghép lại rồi kiểm tra magic bytes/`file` để xác định định dạng và trích flag.

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` rỗng; `SOLUTIONS_VN.md` chỉ ghi định hướng phân tích, không có flag xác định (dù file pcapng còn mở được để phân tích thêm).

## Gặp lại thì xử lý thế nào (playbook)

1. Mở pcap ⇒ Protocol Hierarchy + Conversations để định hình.
2. Export Objects rút mọi file truyền; `Follow Stream` đọc payload từng luồng.
3. `strings pcap | grep flag` như bước rà nhanh.
4. Tên "Intact"/"reassemble" ⇒ nghĩ tới ghép mảnh file: theo sequence number, kiểm tra checksum/magic sau khi ghép.
5. `tshark` tự động hóa khi cần lọc/trích hàng loạt.
