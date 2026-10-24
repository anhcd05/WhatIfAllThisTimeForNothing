# pwd-crackme

- **Category:** Reversing
- **File đề:** `pwd-crackme.zip` (không mật khẩu) → `crackme.exe` — PE 32-bit (`pei-i386`), **118.784 byte**, entry `0x00401b4c`, ImageBase `0x400000`. ZIP MD5 `ca263bd58ed8bd48832a4226f9bfbb17`.

## Tóm tắt đề
Một file thực thi được cho là "công cụ của nhóm hacker". Khi chạy nó hỏi mật khẩu; chỉ khi nhập đúng mới in flag ra màn hình. Đề cho biết định dạng mật khẩu: **7 chữ số nối bằng dấu `-`**, tổng cộng 8 ký tự (dạng `NNNN-NNN`). Mục tiêu: tìm mật khẩu ẩn trong binary rồi lấy flag.

Flag **không** nằm plaintext trong file — `grep -i flag crackme.exe` ra rỗng — nên flag được **dựng/giải mã lúc chạy (runtime)** sau khi mật khẩu đúng. Toàn bộ phân tích dưới đây là **tĩnh** (objdump + pefile), không thực thi binary.

## Phân tích (offset/khóa/hằng số thật)
`objdump -s -j .rdata crackme.exe` + `pefile` cho thấy khối chuỗi quanh `0x41c0c8`:
```
0x41c0c8: "6701-" "0618-" "5117-" "4568-" "4517-" "3889-" "7144-" "6348-" "2222-"   ; 9 tiền tố 4 chữ số
0x41c2b4: "023"                                                                        ; hậu tố 3 chữ số
0x41c000: "The password is 7 numbers combined by '-' (8 digits in total)"
0x41c2d8: "Enter the password: "
0x41c300: "You need to input the password."
0x41c324: "Correct!! The FLAG is: %s\n"
0x41c368: "Incorrect\n"
0x41c340: 43 00 6f 00 6e 00 ...  = L"Congrats!"   (chuỗi UTF-16 / WIDE)
```
→ Có **9 tiền tố 4 chữ số** và **1 hậu tố 3 chữ số**. Chỉ một tổ hợp là thật; 8 tiền tố còn lại là **mồi nhử (decoy)** để làm hỏng kiểu brute mù.

**Luồng dựng mật khẩu đích + đọc input + so sánh (disasm thật, objdump -d):**
```asm
; --- dựng chuỗi mật khẩu đích vào buffer -0x310(%ebp) ---
4014aa: lea  -0x10(%ebp),%eax      ; mảnh "5117-"
4014ae: lea  -0x310(%ebp),%ecx     ; buffer đích
4014b5: call 0x406610              ; strcpy(-0x310, "5117-")
4014bd: lea  -0x1c(%ebp),%edx      ; mảnh "023"
4014c1: lea  -0x310(%ebp),%eax
4014c8: call 0x406620              ; strcat(-0x310, "023")   => "5117-023"
; --- prompt + đọc input ---
4014dd: push $0x41c2d8             ; "Enter the password: "
4014e2: call 0x4016c0             ; printf-wrapper
4014f5: push $0x32                 ; 50 = giới hạn độ dài input
4014f7: lea  -0x1ac(%ebp),%edx     ; buffer input
4014fe: call 0x4048c5             ; fgets(input, 50, stdin)
; --- cắt '\n' (0x0A) cuối input ---
401545: cmp  $0xa,%edx
40156f: movb $0x0,-0x1ac(%ebp,%ecx,1)
; --- SO SÁNH input vs mật khẩu đích ---
4015a9: lea  -0x1ac(%ebp),%ecx     ; input
4015aa: call 0x406710             ; strcmp(input, "5117-023")   <-- HÀM SO SÁNH
4015b2: test %eax,%eax
4015b4: jne  0x401657             ; eax!=0 -> "Incorrect"
; eax==0 -> rơi xuống nhánh dựng/giải mã flag (0x4015ba..)
```

**Nhánh thành công — chứng minh flag là runtime:**
```asm
401607: push $0x41c324            ; "Correct!! The FLAG is: %s\n"
40160c: call 0x4016c0            ; in flag đã dựng ở -0x214(%ebp)
401616: push $0x41c340            ; L"Congrats!"
401624: call *0x415118           ; USER32!MessageBoxW (pefile: IAT 0x415118 -> MessageBoxW)
```
Buffer flag `-0x214(%ebp)` được dựng/giải mã tại chỗ bởi các hàm `0x401000/0x4069f2/0x4046e8/0x4048c5` phía trên → không tồn tại dưới dạng chuỗi tĩnh. `pefile` xác nhận binary **import `IsDebuggerPresent`** (KERNEL32) → có chống debug.

**Giá trị load-bearing đã xác minh tĩnh:** mật khẩu đích = ghép `"5117-"` (`0x41c0d8`) + `"023"` (`0x41c2b4`) = **`5117-023`**; hàm so sánh = `strcmp @ 0x406710`; giới hạn input 50 byte (`fgets ...,0x32`); `\n` bị cắt trước khi so sánh.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Static string analysis (objdump/pefile/PeStudio):** lộ format mật khẩu, 9 decoy, mảnh thật `5117-`/`023`, và chuỗi `Correct/Incorrect`. VÌ SAO: định vị nhanh khối code so sánh mà không cần dò mù.
- **Đọc disasm nhánh so sánh thay vì brute:** VÌ SAO: tác giả rải 8 decoy để brute mù trượt; đọc trực tiếp `strcpy/strcat` dựng buffer đích cho ngay đáp án.
- **(Phương án động) breakpoint tại `0x406710`:** VÌ SAO: ngay tại call so sánh, `-0x1ac`=input, `-0x310`="5117-023"; đọc thanh ghi là lộ đáp án tức thì — nhưng phải vượt `IsDebuggerPresent` (patch trả 0 / ScyllaHide).

## Lời giải chi tiết (bước + lệnh sạch)
1. Giải nén: `unzip pwd-crackme.zip` → `crackme.exe` (không cần mật khẩu).
2. Trinh sát chuỗi tĩnh:
   ```bash
   objdump -s -j .rdata crackme.exe | less     # thấy 9 tiền tố + "023" + "Correct!! The FLAG is: %s"
   ```
3. Nhảy tới xref của chuỗi `Correct!! The FLAG is: %s` (`0x41c324`) trong IDA/Ghidra → vào nhánh `0x401607`, lần ngược lên `strcpy/strcat` (`0x4014aa..0x4014c8`) ghép `"5117-"`+`"023"`.
4. Mật khẩu = **`5117-023`**.
5. Chạy `crackme.exe`, nhập `5117-023` → MessageBoxW "Congrats!" + printf in flag runtime.
6. (Không muốn dùng debugger) Đã biết tiền tố thật `5117-` → brute 3 chữ số còn lại `000`–`999` = 1000 khả năng.

## Flag
flag{criminal_evidence_brought_to_LIGHT}

> Ghi chú nguồn: bản nháp per-bài in `flag{criminal_evidence_brought_to_LIGHT }` (có **một dấu cách** ngay trước `}`). `SOLUTIONS_VN.md` (nguồn chuẩn của set) in **không có** dấu cách. Flag không nằm plaintext — là chuỗi runtime, nên không xác minh được bằng phân tích tĩnh thuần; lấy theo `SOLUTIONS_VN.md`.

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** binary hỏi "password" rồi mới in flag; strings lộ format + `Correct/Incorrect`; `grep flag` rỗng (flag runtime); nhiều chuỗi số "mồi".
- **Quy trình:** (1) `strings`/`objdump -s -j .rdata` lấy format + mảnh thật + decoy; (2) tìm hàm so sánh gần `Incorrect` (`strcmp/memcmp/lstrcmp`); (3) đọc `strcpy/strcat` dựng buffer đích để lấy đáp án, hoặc breakpoint tại call so sánh đọc 2 con trỏ; (4) brute nếu không gian nhỏ và đã biết prefix.
- **Công cụ:** objdump/pefile/PeStudio/DIE, IDA Free/Ghidra/x32dbg, ScyllaHide (vượt anti-debug).
- **Bẫy:** tin ngay chuỗi số đầu tiên (decoy); quên `IsDebuggerPresent`; nhầm 2 luồng xuất (UTF-16 "Congrats!" qua MessageBoxW vs flag ASCII qua printf); input bị cắt `\n` và giới hạn 50 byte.
