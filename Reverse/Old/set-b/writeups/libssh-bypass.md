# libssh-bypass

- **Category:** Network
- **File đề:** không có file; chỉ dịch vụ `10.3.204.203:2222`. Gợi ý: "lỗ hổng nổi tiếng, có exploit công khai".

## Tóm tắt đề

Một dịch vụ SSH chạy bằng thư viện **libssh** dính **CVE-2018-10993** — lỗi bypass xác thực: client tự gửi gói `SSH2_MSG_USERAUTH_SUCCESS` khiến server nhầm là đã đăng nhập thành công → vào thẳng không cần mật khẩu/khóa, rồi chạy lệnh đọc flag.

## Phân tích (chi tiết)

**Nền tảng.** libssh là thư viện SSH (khác OpenSSH). Trong luồng xác thực bình thường, **chỉ server** mới gửi `SSH2_MSG_USERAUTH_SUCCESS` để báo đăng nhập OK.

**CVE-2018-10993:** nếu **client** chủ động gửi gói `SSH2_MSG_USERAUTH_SUCCESS`, state machine của libssh server bị nhầm và coi như đã xác thực → **vào thẳng** không cần mật khẩu/khóa. Ảnh hưởng libssh trước 0.7.6 / 0.8.4.

Trinh sát:

```bash
nc 10.3.204.203 2222
# -> banner: SSH-2.0-libssh_0.8.1   (0.8.1 < 0.8.4 => dính CVE)
```

Tra banner → đúng CVE-2018-10993. Chọn PoC gửi `USERAUTH_SUCCESS` sớm rồi mở channel chạy lệnh.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Đọc banner để fingerprint phiên bản** — VÌ CVE chỉ áp dụng cho libssh < 0.7.6/0.8.4; banner `libssh_0.8.1` xác nhận dính.
- **Gửi `USERAUTH_SUCCESS` từ client (auth bypass)** — VÌ đây chính là bản chất CVE: server libssh tin trạng thái mà client tự khai.
- **Mở session channel + `exec`** — VÌ sau khi "được" xác thực, cần chạy lệnh để đọc flag.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```bash
# 1) Fingerprint:
nc 10.3.204.203 2222        # banner SSH-2.0-libssh_0.8.1

# 2) Chạy PoC CVE-2018-10993 (gửi USERAUTH_SUCCESS, bỏ qua auth, mở channel, exec):
python exploitssh.py 10.3.204.203 -p 2222 -c "cat flag.txt"
```

Logic PoC: bắt tay KEX → gửi `SSH2_MSG_USERAUTH_SUCCESS` (bỏ qua auth) → mở `session` channel → `exec cat flag.txt`.

## Flag

```
flag{...}
```

**Nguồn không nêu** — writeup gốc không ghi flag (flag xuất hiện khi chạy trên server live, nay đã gỡ). `SOLUTIONS_VN.md` chỉ nêu CVE và cách khai thác.

## Gặp lại thì xử lý thế nào (playbook)

1. Dịch vụ SSH lạ ⇒ đọc banner (`nc`/`ssh -v`); phân biệt libssh và OpenSSH.
2. Banner `libssh_<0.7.6` hoặc `libssh_0.8.x<0.8.4` ⇒ thử CVE-2018-10993 (auth bypass bằng `USERAUTH_SUCCESS`).
3. Dùng PoC đúng phiên bản; sau khi vào, mở session channel và `exec` lệnh đọc flag.
4. Nếu là OpenSSH thì CVE này **không** áp dụng — đổi hướng (brute/cred/CVE khác).
5. Bài học phòng thủ: cập nhật libssh ≥ 0.8.4/0.7.6.
