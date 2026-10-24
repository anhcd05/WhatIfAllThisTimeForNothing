# calculator

- **Category:** OS
- **File đề:** không có trong repo (`README.md` rỗng, không kèm binary → không thể disassemble). Tên bài gốc "Calc".

## Tóm tắt đề

Bài OS 180đ (điểm cao ⇒ khó). Repo **không có lời giải và không có file đề**. Từ tên "Calc" (máy tính) và mức điểm, đây gần như chắc chắn là một bài pwn/reverse về máy tính biểu thức có lỗ hổng. Phần dưới là các giả thuyết + playbook phân tích tĩnh.

## Phân tích (chi tiết)

Điểm cao gợi một trong các dạng:
1. **Máy tính biểu thức có lỗ hổng** — phân tích/eval biểu thức người dùng dẫn tới:
   - **Format string** (`printf(user_input)` → đọc/ghi bộ nhớ qua `%x`/`%n`),
   - **Integer overflow** (số quá lớn tràn, đổi luồng),
   - **command/eval injection** nếu dùng `eval`/`system`.
2. **Buffer overflow** — nhập biểu thức dài ghi đè return address (pwn cổ điển: cần `checksec`, tìm gadget ROP hoặc ghi đè biến).
3. **Reverse một VM/bytecode nhỏ** — máy tính tự định nghĩa opcode; phải dịch ngược bộ thông dịch.

Vì không có file đề, không thể xác nhận flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **`checksec` trước tiên** — VÌ NX/PIE/canary/RELRO quyết định hướng khai thác (overflow kinh điển hay cần ROP/leak).
- **`objdump`/`strings` tìm hàm nguy hiểm** — VÌ `printf`/`gets`/`scanf("%s")`/`system` là dấu hiệu format-string/overflow/injection.
- **Thử input biên** — VÌ chuỗi dài, `%x%x%x`, số âm/tràn nhanh chóng bộc lộ lớp lỗ hổng.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

Khi có file đề (trong VM):

```bash
file <binary>
checksec --file=<binary>             # NX, PIE, Canary, RELRO
strings -a <binary> | grep -iE 'flag|%n|%x|eval|system'
objdump -d -M intel <binary> | grep -iE 'printf|gets|scanf|system|strcpy|memcpy'

# Thăm dò lớp lỗ hổng:
#   - Format string: nhập '%x %x %x %p' xem có leak stack không; '%n' để ghi.
#   - Overflow: nhập chuỗi dài (pattern cyclic) xem có crash/ghi đè EIP/RIP.
#   - Injection: nhập '1;id' hoặc '__import__(...)' nếu là eval ngôn ngữ cấp cao.
```

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` rỗng, không có file đề; `SOLUTIONS_VN.md` chỉ ghi định hướng, không có flag.

## Gặp lại thì xử lý thế nào (playbook)

1. `file` + `checksec` để định hình bài (pwn hay reverse).
2. Máy tính biểu thức ⇒ ưu tiên nghi format-string và eval/command injection.
3. Nhập dài gây crash ⇒ bài overflow: dựng pattern cyclic tìm offset, rồi ret2win/ROP tùy mitigations.
4. Thấy bảng opcode/switch lớn ⇒ bài VM: viết disassembler cho bytecode rồi suy luồng kiểm tra flag.
5. Luôn thao tác trong VM cách ly; dùng `pwntools` để tự động hóa tương tác.
