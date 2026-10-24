# path-lookup

- **Category:** OS
- **File đề:** không có trong repo (`README.md` rỗng, không kèm binary → không thể disassemble). Tên bài gốc "Which".

## Tóm tắt đề

Bài OS 60đ. Repo **không có lời giải và không có file đề**. Từ tên "Which" (lệnh `which` của Linux) và mức điểm, gần như chắc chắn đây là bài **PATH hijacking / relative-path exec**. Phần dưới là kiến thức nền + playbook xử lý khi có file.

## Phân tích (chi tiết)

Lệnh `which` tra *đường dẫn đầy đủ* của một chương trình bằng cách duyệt các thư mục trong biến môi trường `$PATH` theo thứ tự. Lớp bài liên quan: **PATH hijacking**.

Cơ chế lỗ hổng: một chương trình (thường SUID-root hoặc dịch vụ) gọi lệnh ngoài **không ghi đường dẫn tuyệt đối** — ví dụ `system("ls")` thay vì `/bin/ls`. Khi đó shell tìm `ls` theo `$PATH`; kẻ tấn công đặt một `ls` giả ở thư mục ghi được rồi **thêm thư mục đó lên đầu `$PATH`** (`export PATH=/tmp:$PATH`) → chương trình chạy mã của attacker (đọc flag / leo quyền).

Vì không có file đề, không thể xác nhận flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Tìm lời gọi lệnh ngoài không có đường dẫn tuyệt đối** — VÌ `system("ls")`/`execlp("ls",...)`/`popen` với tên lệnh trần là điều kiện cần của PATH hijacking.
- **Kiểm tra bit SUID** — VÌ chỉ khi binary chạy với quyền cao (SUID-root) thì PATH hijacking mới leo quyền/đọc được flag.
- **Chèn binary giả lên đầu `$PATH`** — VÌ `ld`/shell tìm lệnh theo thứ tự `$PATH`; đặt thư mục ghi được lên đầu là chiếm quyền thực thi.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

Khi có file đề (làm trong VM):

```bash
# 1) Tìm lời gọi lệnh ngoài bằng tên trần (không có '/'):
strings <binary> | grep -E '^(ls|cat|id|whoami|cp|date)$'
objdump -d <binary> | grep -iE 'system|execlp|execvp|popen'

# 2) Kiểm tra SUID:
ls -l <binary>
find . -perm -4000 2>/dev/null

# 3) Tạo lệnh giả cùng tên và chèn lên đầu PATH:
mkdir -p /tmp/evil
printf '#!/bin/sh\ncat /path/to/flag\n' > /tmp/evil/ls   # ví dụ chương trình gọi 'ls'
chmod +x /tmp/evil/ls
export PATH=/tmp/evil:$PATH
./<binary>    # chạy lại -> nó gọi 'ls' giả -> in flag
```

## Flag

```
flag{...}
```

**Nguồn không nêu** — `README.md` rỗng, không có file đề; `SOLUTIONS_VN.md` chỉ ghi định hướng, không có flag.

## Gặp lại thì xử lý thế nào (playbook)

1. Tên liên quan `which`/`PATH`/`env` ⇒ nghĩ ngay tới PATH hijacking.
2. Điều kiện khai thác: binary gọi lệnh ngoài bằng tên trần + chạy quyền cao (SUID/service).
3. Chèn thư mục ghi được lên đầu `$PATH`, đặt binary giả cùng tên lệnh bị gọi.
4. Phòng thủ (để hiểu đề): dùng đường dẫn tuyệt đối, `secure_getenv`, reset `PATH` trong code SUID.
5. Luôn thao tác trong VM cách ly.
