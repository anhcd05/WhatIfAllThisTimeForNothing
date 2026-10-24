# twin-files

- **Category:** MISC
- **File đề:** `twin-files/0ad3d2abf5ededb11275ce89417f314e.zip` (287347 bytes; git blob sha1 `dbb4d77c9654d7b93447ebec794f0d68d81b83bd`). Bên trong có `File` và `File001..File999`.

## Tóm tắt đề

> Among File001 to File999, find files with the same features with `File`. Identify the files and also provide evidence for the commonality.

Format flag: `flag{File<4 số>_<alnum thường>}`. Cần tìm file "cùng đặc điểm" với `File` và nêu **bằng chứng**.

## Phân tích (chi tiết)

Từ format flag (`File<4 số>_<hash>`) + yêu cầu "same features ... evidence for the commonality" → bài hướng về **so khớp hash**. Đặc điểm cần tìm là một file khác có **cùng md5** với `File`.

**Nền tảng — MD5 collision.** MD5 là hàm băm 128-bit. Về lý thuyết 2 file khác nhau rất khó cùng MD5, nhưng MD5 **đã bị phá va chạm** từ 2004 (Wang & Yu). Cặp thông điệp 128-byte nổi tiếng của Wang có **cùng MD5 = `79054025255fb1a26e4bc422aef54eb4`** nhưng nội dung khác nhau; giá trị này xuất hiện khắp các demo "MD5 is broken". Bài này chính là trò đó: trong 999 file có một file (`File0623`) khác nội dung với `File` nhưng **trùng md5**.

Lưu ý quan trọng: `79054025255fb1a26e4bc422aef54eb4` **không** phải md5 chuỗi rỗng (`d41d8cd98f00b204e9800998ecf8427e`), mà đúng là MD5 của cặp va chạm Wang. So sánh bằng **sha256** sẽ thấy `File` và `File0623` khác hẳn nhau → đó là bằng chứng "cùng MD5 nhưng file khác" (MD5 không an toàn).

## Kỹ thuật áp dụng (+ VÌ SAO)

1. **Băm md5 toàn bộ + gom trùng.** *Vì sao:* "đặc điểm chung" = cùng md5; gom nhóm md5 trùng để tìm cặp.
2. **Đối chiếu bằng sha256 + `cmp`.** *Vì sao:* chứng minh 2 file **khác nội dung** dù cùng md5 → đúng bản chất MD5 collision (bằng chứng cần nộp).
3. **Phân tích tĩnh (chỉ đọc bytes).** *Vì sao:* đây là file dữ liệu, chỉ cần hash; không thực thi gì.

## Lời giải chi tiết (bước + code/lệnh sạch)

```bash
unzip 0ad3d2abf5ededb11275ce89417f314e.zip

# Cách 1: gom md5 trùng
md5sum File File??? File???? 2>/dev/null | sort | uniq -w32 -D

# Cách 2: dò file có md5 trùng với 'File'
target=$(md5sum File | awk '{print $1}')        # 79054025255fb1a26e4bc422aef54eb4
for f in File[0-9][0-9][0-9]; do
    [ "$(md5sum "$f" | awk '{print $1}')" = "$target" ] && echo "KHỚP: $f"
done                                             # -> KHỚP: File0623

# Bằng chứng: cùng md5 nhưng khác nội dung
cmp File File0623            # báo khác tại byte nào đó
sha256sum File File0623      # 2 sha256 KHÁC nhau => MD5 collision
```

`target` = `79054025255fb1a26e4bc422aef54eb4`; file trùng là `File0623`. Ghép theo format: `flag{File0623_79054025255fb1a26e4bc422aef54eb4}`.

## Flag

flag{File0623_79054025255fb1a26e4bc422aef54eb4}

## Gặp lại thì xử lý thế nào (playbook)

1. Thấy nhiều file giống tên + yêu cầu "same feature/commonality" → nghĩ tới **so khớp hash**, đặc biệt **MD5 collision**.
2. Băm md5 tất cả, gom trùng (`md5sum ... | sort | uniq -w32 -D`).
3. **Dùng md5, KHÔNG dùng sha1/sha256 để tìm trùng** — collision chỉ xảy ra với md5; sha256 sẽ không ra cặp.
4. Chứng minh bằng chứng: `cmp`/`sha256sum` cho thấy nội dung khác → minh họa MD5 không an toàn.
5. Nhận diện giá trị quen thuộc `79054025255fb1a26e4bc422aef54eb4` (cặp va chạm Wang 2004) để biết ngay đây là bài MD5 collision.
