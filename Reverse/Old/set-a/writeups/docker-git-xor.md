# docker-git-xor

- **Category:** Forensic (Disk / Docker / Git)
- **File đề:** `challenge.tar` — bản backup/export của một Docker container (gồm các layer, file JSON config/log, và `flag.txt` đã bị mã hóa). **File KHÔNG có trong repo offline** (bài thao tác trên môi trường thi); dưới đây tái dựng đầy đủ phương pháp.

## Tóm tắt đề
Nhiệm vụ: khôi phục nội dung `flag.txt`. Trong `challenge.tar` có `flag.txt` nhưng đã bị một script `cryptor.py` mã hóa rồi xóa khỏi commit git. Phải tái dựng logic mã hóa, tìm đúng khóa, giải mã lấy flag.

## Phân tích (chi tiết: khóa thật, cấu trúc)
Chuỗi manh mối trong backup:
1. **Docker log JSON** (`b01f...b172.json`) ghi lại stdout/stderr container: thấy `cryptor.py` đã chạy (rồi bị xóa). Log chứa **tham số (argument)** truyền vào script và **thời điểm thực thi** — hai thông tin quyết định để tái tạo khóa.
2. Cùng thư mục với `flag.txt` có `.git`. `git status` cho thấy `cryptor.py` bị xóa khỏi working tree nhưng còn trong lịch sử → `git restore`/`git checkout` lấy lại được mã nguồn.
3. Đọc `cryptor.py`: khóa sinh từ **thời điểm chạy** (`datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")`) nối với **argument** (`sys.argv[1]`), rồi **XOR** lặp vào nội dung `flag.txt`.

**Khóa thật gồm 2 phần:**
- `key1` = timestamp chạy, định dạng `%Y%m%d%H%M%S` (UTC). Giá trị đầy đủ (đến giây): **`20241010033808`**.
- `key2` = argument. **[REDACTED — tên sự kiện]**: argument thật đọc được trong log là tên của kỳ thi CTF; theo quy ước redact, ký hiệu là `<EVENT>` (bản nháp dùng placeholder `EVENTNAME`/`SetA`). Khi giải lại thì dùng đúng chuỗi lấy từ log.
- `key = key1 + key2` (ghép đúng thứ tự như `cryptor.py`), XOR lặp theo `% len(key)`.

Vì XOR đối xứng (XOR hai lần cùng khóa trả lại plaintext), chỉ cần dựng đúng khóa là giải mã được.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Docker forensics:** đọc layer/metadata container export (`docker save`/`docker export`). *Vì sao:* file log JSON chứa command line + timestamp — chính là seed của khóa.
- **Git forensics:** `git status` / `git log --all` / `git restore` / `git show <commit>:<path>`. *Vì sao:* file xóa khỏi working tree vẫn còn trong object store `.git` → khôi phục được logic mã hóa.
- **Giải XOR đối xứng:** đọc source thấy toán tử `^` + khóa = time+arg → chỉ việc tái tạo khóa cố định. *Vì sao:* XOR thuận nghịch.
- **Xác nhận timestamp bằng image:** `docker load` rồi `ls --full-time flag.txt`. *Vì sao:* log có thể thiếu giây; metadata file trong image cho timestamp chính xác đến giây.
- **Công cụ:** `docker`, `git`, Python.

## Lời giải chi tiết (bước + lệnh/code sạch)
1. Giải nén backup:
   ```bash
   mkdir challenge && tar -xf challenge.tar -C challenge
   ```
2. Tìm & đọc Docker log để lấy argument + thời gian chạy:
   ```bash
   grep -ri "cryptor.py" challenge/
   cat challenge/.../b01f...b172.json        # log container
   ```
   → argument = `<EVENT>` (tên sự kiện, đã redact); thời điểm ≈ `202410100338`.
3. Phục hồi `cryptor.py` từ git:
   ```bash
   cd <thư mục chứa flag.txt và .git>
   git status                 # thấy cryptor.py đã bị xóa
   git restore cryptor.py     # hoặc: git checkout HEAD -- cryptor.py
   ```
4. Xác nhận timestamp đủ giây bằng cách load image:
   ```bash
   docker load < challenge.tar
   docker run -itd challenge && docker ps
   docker exec -it <cid> sh -c "ls --full-time flag.txt"
   # -rw-rw-r-- 1 1000 1000 37 2024-10-10 03:38:08 +0000 flag.txt
   ```
   → timestamp đầy đủ **`20241010033808`** (UTC).
5. `decryptor.py` — lấy nguyên logic `cryptor.py`, chỉ thay phần sinh khóa bằng giá trị đã biết:
   ```python
   key1 = "20241010033808".encode()        # datetime.now(utc).strftime("%Y%m%d%H%M%S")
   key2 = "<EVENT>".encode()                # sys.argv[1] = argument thật lấy từ log (redact)
   key  = key1 + key2                       # ghép đúng như cryptor.py
   data = open("flag.txt", "rb").read()
   out  = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))   # XOR lặp
   open("flag_dec.txt", "wb").write(out)
   ```
6. Chạy & đọc flag:
   ```bash
   python3 decryptor.py && cat flag_dec.txt
   ```

## Flag
```
flag{...}
```
**Nguồn:** `SOLUTIONS_VN.md` (mục B3) **không in flag** (ghi "chỉ có khi có file thật — nội dung flag.txt sau giải XOR"). Nháp `recovery.md` nêu giá trị `flag{Great_job_on_the_recovery!}` nhưng **không có file đề offline để xác minh tĩnh** ⇒ coi là tham khảo, chưa kiểm chứng. (Lưu ý: chuỗi argument thật = tên kỳ thi CTF đã được redact theo quy ước.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** `.tar` là backup/export Docker (layer + JSON config/log); một file bị mã hóa (`flag.txt`) + một script mã hóa "biến mất".
- **Quy trình:** giải nén tar, map cấu trúc → đọc Docker log JSON lấy **command line + argument + timestamp** → kiểm `.git` cạnh file (`git status`/`git log --all`/`git restore`) phục hồi script → đọc script xác định thuật toán (XOR/stream đối xứng → chỉ tái tạo khóa) → `docker load` + `ls --full-time` lấy timestamp chính xác đến giây.
- **Bẫy:** timestamp phải đúng giây **và đúng múi giờ UTC** như script; lệch 1 giây → sai toàn bộ. Cách nối `key1+key2` và index XOR phải khớp source gốc. Đừng chỉ tin format `strftime`; đối chiếu metadata file thật trong image.
- **Checklist:** unzip tar → log JSON (arg+time) → `git restore` cryptor.py → xác nhận timestamp (`ls --full-time`) → decryptor XOR key=time+arg → giải → flag.
