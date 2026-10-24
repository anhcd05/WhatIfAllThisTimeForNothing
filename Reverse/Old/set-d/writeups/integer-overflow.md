# integer-overflow

- **Category:** Reverse Engineering — Integer Overflow (chủ đề *modulo*/số âm).
- **File đề:**
  - `D6-integer-overflow/binary_e2b191e6b2bb80471d8c4cdb96002207.zip` → giải nén ra `binary_...e2b191e6....exe` (PE32 Windows console, Intel 80386, **19 456 byte**).
  - `D6-integer-overflow/source_b8848652bef5d195b8d98fe880057d73.cp` (**2 554 byte**, UTF-16LE) — mã nguồn C++ nhưng nhánh in flag trong `GetFlag` bị thay bằng `<<Deleted>>`.

## Tóm tắt đề
Chương trình hỏi một số rồi báo chẵn/lẻ. Flag nằm trong nhánh `<<Deleted>>` của hàm `GetFlag`, chỉ chạy khi input thoả điều kiện đặc biệt. Phải tìm input thoả điều kiện. **Toàn bộ phân tích là tĩnh** — đọc mã nguồn và disassemble, KHÔNG chạy `.exe`.

## Phân tích (chi tiết)
**Nền tảng cần nắm:**
- **`int` 32-bit có dấu, bù hai (two's complement):** dải từ **-2 147 483 648** (`0x80000000`) đến **+2 147 483 647** (`0x7FFFFFFF`). Bit 31 là bit dấu (0=dương, 1=âm).
- **Integer overflow:** kết quả vượt dải bị "cuộn vòng" theo modulo 2³². Ví dụ `0x7FFFFFFF + 1 = 0x80000000` = **-2 147 483 648**: dương lớn nhất +1 nhảy sang âm nhỏ nhất.
- **Phép `%` với số âm trong C/C++:** `%` **giữ dấu số bị chia**. Do đó `-3 % 2 == -1`, `-7 % 2 == -1` (số âm lẻ dư **-1**, KHÔNG phải 1). Đây là chìa khoá.

**Trinh sát tĩnh exe:**
```bash
file binary_...e2b191e6....exe     # PE32 executable (console) Intel 80386, for MS Windows
strings -n 5 binary_...e2b191e6....exe | grep -iE 'even|odd|Close|number|limit'
```
Kết quả `strings`:
```
Determine whether the number you entered is even or odd.
Input number, please
Input number only.
Close! Please enter close to the limit value to get a flag.
The number you input is even.
The number you input is odd.
```
**Quan trọng:** chuỗi flag **không** xuất hiện trong `strings` ⇒ flag không nằm cứng, mà được **dựng/tính ở runtime** trong nhánh `<<Deleted>>`. Vì vậy phải suy luận điều kiện, không thể chỉ `strings`.

**Mã nguồn `.cp` (phần cốt lõi, đã đọc từ UTF-16):**
```cpp
int InputNumber() {
    char innum[11] = "";               // buffer 11 byte -> tối đa 10 chữ số
    int num; bool f;
    while (true) {
        num = 0; f = false;
        cin >> innum;
        for (int i = 0; i < sizeof(innum); i++) {
            if (innum[i] > 0) {
                if (!(innum[i] >= '0' && innum[i] <= '9')) {   // chỉ nhận ký tự số
                    cout << "Input number only."; f = false; break;
                } else {
                    int j = innum[i] - '0';
                    num = num * 10 + j;    // dựng số: KHÔNG kiểm tra tràn!
                    f = true;
                }
            }
        }
        if (f == true) return num;     // trả về int (có thể đã tràn thành âm)
    }
}

std::string GetFlag(int key) {
    std::string val = "";
    if (key * 2 == 2) {       // điều kiện mở khoá
        <<Deleted>>           // <-- nhánh in flag, bị xoá khỏi đề
    } else {
        val = "Close! Please enter close to the limit value to get a flag.";
    }
    return val.c_str();
}

int main() {
    int num = InputNumber();
    std::string msg;
    if (num % 2 == 0)       msg = "The number you input is even.\n";
    else if (num % 2 == 1)  msg = "The number you input is odd.\n";
    else                    msg = GetFlag(num);   // CHỈ tới đây khi num%2 khác 0 VÀ khác 1
    printf("%s\n", msg.c_str());
}
```

**Suy luận 3 ràng buộc:**
1. **Chạm được `GetFlag`:** cần `num % 2` khác 0 *và* khác 1. Với số dương `%2` chỉ ra 0 hoặc 1 → không bao giờ rơi vào `else`. Khả năng duy nhất: `num % 2 == -1`, xảy ra khi **`num` âm và lẻ** (quy tắc `%` giữ dấu số bị chia).
2. **Không nhập trực tiếp số âm:** `InputNumber` loại dấu `-`. Để có `num` âm phải nhờ **integer overflow**: nhập số dương đủ lớn để khi dựng vào `int` 32-bit nó cuộn vòng thành âm.
3. **Qua `if (key*2 == 2)`:** sau khi nhân đôi (cũng là phép `int` 32-bit, có thể tràn), kết quả phải đúng bằng `2`.

**Tìm giá trị thoả cả 3.** Đặt `N` là số nhập (lưu vào `int`):
- Cần `N*2 ≡ 2 (mod 2³²)` ⇒ `N ≡ 1 (mod 2³¹)`. Ứng viên: `N = 1` (lẻ dương → nhánh "odd", loại) và `N = 2³¹ + 1 = 2147483649` (`0x80000001`).
- Với `N = 2147483649`: lưu vào `int` → `0x80000001` có bit dấu 1 ⇒ giá trị thực = **-2147483647** → âm & lẻ ✓ (ràng buộc 1 & 2).
- `key*2 = (-2147483647)*2`: theo unsigned `0x80000001 * 2 = 0x100000002`, cắt 32-bit = `0x00000002` = **2** ✓ (ràng buộc 3).

**Đối chiếu disassembly thật (`objdump -d`, tĩnh — KHÔNG chạy).** Ba hàm C++ ánh xạ rõ ra mã máy:
- `main` hiện thực `num % 2` cho int *có dấu* bằng mẹo `and $0x80000001` (giữ bit0 + bit dấu) rồi hiệu chỉnh nếu âm. Lần vết với `num = -2147483647 = 0x80000001`: `0x80000001 & 0x80000001 = 0x80000001` (âm) → fixup `dec`/`or 0xfffffffe`/`add 1` → `0xffffffff = -1`; `-1 ≠ 0` (không even), `cmp $1`: `-1 ≠ 1` → **nhảy gọi `GetFlag(num)`**. Khớp hoàn hảo suy luận "số âm lẻ có `%2 == -1`".
- `GetFlag` tại `0x401230`: `lea (%ecx,%ecx,1),%eax` = `key*2`; `cmp $0x2,%eax` + `jne` = đúng `if (key*2 == 2)`. Với `key = -2147483647`, `key*2` tràn về `2` → vào nhánh `<<Deleted>>`.
- Nhánh bí mật **không** chứa chuỗi flag sẵn — nó ghi **48 cặp số nguyên** (96 dword) lên stack rồi lặp, mỗi vòng gọi hàm số học 64-bit (kiểu `_alldiv`/`_allrem` của MSVC) để dựng từng ký tự → 48 ký tự = đúng độ dài `flag{Something_happens_when_exceeds_limit_value}`. Đây là lý do `strings` không thấy flag.

## Kỹ thuật áp dụng (CVE cụ thể nếu có + VÌ SAO)
- **Không có CVE.** Đây là bài reverse về **signed integer overflow** trên `int` 32-bit.
- **Integer overflow + hành vi của `%` với số âm.**
  - VÌ SAO nhận ra: tên bài "Mod" (modulo) + điều kiện `num % 2 != 0 && != 1` là bất khả thi với toán học thông thường → gợi ý mạnh rằng giá trị bị wrap-around. Buffer 11 byte cho phép nhập số lớn hơn `INT_MAX`.
  - Mấu chốt: chọn `2147483649` để sau khi wrap thành `-2147483647` (âm lẻ → `%2 == -1`, né cả hai nhánh even/odd), đồng thời `*2` wrap về đúng `2` (mở khoá `GetFlag`).
  - Hành vi wrap của signed overflow về mặt chuẩn C là UB, nhưng MSVC thực tế wrap theo bù hai như mô tả nên exploit hoạt động.

## Lời giải chi tiết (bước + code/lệnh/payload sạch)
1. Đọc mã nguồn, nhận ra ba nhánh dựa trên `num % 2` và điều kiện `key*2 == 2`.
2. Suy luận cần một giá trị làm `%2` cho ra `-1` (né even/odd) đồng thời `*2` wrap về `2`.
3. Chọn `num = 2147483649` (= 2³¹+1). Tác giả cũng suy ra qua `(0xffffffff + 3) / 2 = 2147483649`.
4. **Mô phỏng an toàn bằng Python (KHÔNG chạy exe):**
   ```python
   import ctypes
   def simulate(s):
       num = 0
       for ch in s:                       # tái hiện InputNumber, cho phép tràn
           if not ch.isdigit():
               return None
           num = ctypes.c_int32(num * 10 + (ord(ch) - ord('0'))).value
       return num

   n = simulate("2147483649")             # -> -2147483647
   print("num   =", n)                    # âm, lẻ
   print("key*2 =", ctypes.c_int32(n * 2).value)   # 2  -> mở khoá
   ```
   `num % 2` theo quy tắc C cho số âm lẻ = `-1` → né cả even (0) lẫn odd (1) → gọi `GetFlag` → `key*2 == 2` → in flag.
5. Khi làm thật: nhập `2147483649` vào chương trình. (Tài liệu này chỉ *suy luận tĩnh*, không execute.)

**Cách thay thế (không cần đoán):** patch điều kiện `jne 0x4017b0` trong `GetFlag`, hoặc đặt breakpoint trong Ghidra/x64dbg sửa `key = 1` ngay trước `GetFlag`; hoặc emulate riêng hàm dựng chuỗi trong Ghidra.

## Flag
flag{Something_happens_when_exceeds_limit_value}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** điều kiện số học "không thể thoả" (cần `x*2==2` nhưng `x==1` lại rơi nhánh khác); input cho phép số rất lớn; kiểu dữ liệu `int`/`short` có dấu; flag được dựng runtime (`strings` không thấy).
- **Quy trình:**
  1. Xác định kiểu và độ rộng (`int` 32-bit, `short` 16-bit, `char` 8-bit).
  2. Tìm giá trị vượt ngưỡng để wrap: `INT_MAX=2147483647`, `INT_MIN=-2147483648`.
  3. Tính ngược input sao cho sau wrap thoả mọi điều kiện (`ctypes.c_int32`/`c_int16` mô phỏng).
  4. Chú ý dấu của `%` trong C: toán hạng âm có thể cho `-1`, khác Python.
- **Công cụ:** `file`, `strings`, `objdump -d`/`-s`, Ghidra/IDA/x64dbg (đọc tĩnh/patch), Python `ctypes`.
- **Bẫy:**
  - Nhầm `-3 % 2 == 1`: SAI trong C/C++ (đúng là `-1`) — dùng Python `%` để suy luận điều kiện C sẽ bế tắc.
  - Nhập 11 chữ số có thể vượt buffer; chỉ cần `2147483649` (10 chữ số).
  - Signed overflow là UB theo chuẩn, nhưng thực tế x86/MSVC wrap theo bù hai — bài dựa vào hành vi đó.
- **Checklist ngắn:** kiểu có dấu + ngưỡng overflow → wrap qua bù hai → mô phỏng bằng `ctypes` → nhập input đã tính.
