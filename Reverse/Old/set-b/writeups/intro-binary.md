# intro-binary

- **Category:** Binary
- **File đề:** `intro-binary/bdb5baaf4b4f961738e1d1528f2efd35.zip` (6908 bytes, git blob sha1 `48746993f143bed2cfd5311da83f05df7867679d`). Lưu ý: md5 thật của zip = `0e22e8be56bb87af3be9a21c04ac4f59`, **khác** hash trong tên (`bdb5baaf...`) — nghĩa là file trong repo đã bị đóng gói/nén lại so với bản phát gốc; hash trong tên chỉ là nhãn định danh.

## Tóm tắt đề

Bài Binary nhập môn ("ultra introduction", 50đ). Repo **không kèm lời giải** (`README.md` rỗng 0 byte) và SOLUTIONS cũng chỉ nêu định hướng phân tích tĩnh, không có flag. Phần dưới là quy trình chuẩn cho một bài binary nhập môn.

## Phân tích (chi tiết)

Vì không có lời giải sẵn, chỉ suy luận từ tên bài + mức điểm:
- "Ultra introduction" + 50đ ⇒ đây là bài khởi động, thường flag lộ ngay qua `strings` hoặc một phép so sánh chuỗi cứng rất đơn giản.
- File đề là ZIP, giải nén ra một binary nhỏ (thường ELF hoặc PE).

Quy trình phân tích tĩnh chuẩn cho binary nhập môn:
1. `unzip` → `file` xác định loại (ELF/PE), kiến trúc, có stripped không.
2. `strings -a` quét toàn bộ chuỗi — bài dễ thường để flag hoặc chuỗi so sánh ở dạng text.
3. Nếu không thấy flag thẳng, `objdump -d` / Ghidra tìm chỗ so sánh **input người dùng với chuỗi cứng** (`strcmp`, so sánh từng byte, hoặc XOR đơn giản).
4. Nếu có phép biến đổi (XOR/cộng hằng) thì mô phỏng lại bằng Python để dựng flag — không chạy binary.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **`strings` quét chuỗi** — VÌ bài 50đ nhập môn thường để flag/mật khẩu ở dạng plaintext trong `.rodata`.
- **`objdump -d`/Ghidra tìm so sánh chuỗi** — VÌ nếu flag không lộ qua `strings`, nó thường là hằng được so với input; đọc disassembly là đủ.
- **Phân tích tĩnh, không chạy** — VÌ nguyên tắc an toàn (file lạ) và vì bài nhập môn hiếm khi cần chạy thật.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```bash
unzip bdb5baaf4b4f961738e1d1528f2efd35.zip
file *                              # xác định ELF/PE, kiến trúc
strings -a * | grep -iE "flag\{|ctf|pass|key"   # tìm flag/chuỗi gợi ý ở dạng text
# nếu chưa ra:
objdump -d -M intel <binary> | less # tìm strcmp / so sánh byte với hằng
# nếu có biến đổi XOR/cộng hằng, mô phỏng bằng Python để dựng flag (không chạy file)
```

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` của bài rỗng và `SOLUTIONS_VN.md` chỉ ghi định hướng phân tích tĩnh, không có flag xác định cho bài này.

## Gặp lại thì xử lý thế nào (playbook)

1. Luôn bắt đầu bằng `file` + `strings` — bài dễ thường lộ ngay.
2. Không thấy flag text ⇒ tìm phép so sánh input với chuỗi cứng trong disassembly.
3. Gặp biến đổi đơn giản (XOR một byte, cộng hằng, đảo chuỗi) ⇒ mô phỏng bằng Python thay vì chạy.
4. Kiểm tra cả `.data`/`.rodata` bằng `objdump -s` phòng khi flag là mảng byte.
5. Chỉ chạy binary trong VM nếu thật sự cần xác nhận hành vi.
