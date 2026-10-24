# anagram-author

- **Category:** MISC (OSINT / Puzzle)
- **File đề:** không có file đính kèm; chỉ một đoạn text bị xáo trộn (anagram) trong phần Message của đề.

## Tóm tắt đề
Đề cho một đoạn text bị "anagram hóa" (mỗi *từ* bị đảo thứ tự chữ cái nhưng giữ nguyên tập chữ). Nhiệm vụ: giải mã rồi **tìm tác giả** của đoạn văn.

Đoạn gốc (anagram):
```
neco nopu a meti teher ewer fuor ltitle btribas nda rehti smena ewer fylspo ypmso otcotn-ital nda teper yhet lediv thiw rehti tohrem ni a nsad bnak rednehtaun eht root fo a vrey igb fir rete
```

## Phân tích (chi tiết: ánh xạ từng từ)
Mỗi "từ" là một **anagram** của một từ tiếng Anh (cùng multiset chữ cái, khác thứ tự). Giải từng từ (giữ nguyên vị trí từ):
- `neco→once`, `nopu→upon`, `a→a`, `meti→time`, `teher→there`, `ewer→were`, `fuor→four`, `ltitle→little`, `btribas→rabbits`, `nda→and`, `rehti→their`, `smena→names`, `ewer→were`, `fylspo→flopsy`, `ypmso→mopsy`, `otcotn-ital→cotton-tail`, `nda→and`, `teper→peter`, `yhet→they`, `lediv→lived`, `thiw→with`, `rehti→their`, `tohrem→mother`, `ni→in`, `nsad→sand`, `bnak→bank`, `rednehtaun→underneath`, `eht→the`, `root→root`, `fo→of`, `vrey→very`, `igb→big`, `fir→fir`, `rete→tree`.

Ghép lại:
> *"once upon a time there were four little rabbits and their names were flopsy mopsy cotton tail and peter they lived with their mother in a sand bank underneath the root of a very big fir tree"*

Đây là **đoạn mở đầu của "The Tale of Peter Rabbit" (1902)**. Tác giả: **Beatrix Potter**, tên đầy đủ **Helen Beatrix Potter**.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Giải anagram theo từng từ:** đọc hiểu + anagram solver, hoặc nhận ra cụm "once upon a time..." quen thuộc. *Vì sao:* tập chữ cái mỗi từ khớp một từ tiếng Anh ⇒ chắc chắn là anagram theo từng từ, không phải reverse/Caesar.
- **OSINT văn học:** nhận diện tác phẩm từ câu mở đầu ("four little rabbits... Flopsy, Mopsy, Cottontail and Peter") → tra tác giả. *Vì sao:* đề hỏi "author", đáp án là tên tác giả.

## Lời giải chi tiết (bước + code sạch)
1. Giải anagram từng từ (bắt đầu từ từ ngắn `a`, `nda→and`, `eht→the`, `fo→of` để định hướng), hoặc nhập cả câu vào anagram solver:
   > once upon a time there were four little rabbits and their names were flopsy mopsy cotton tail and peter they lived with their mother in a sand bank underneath the root of a very big fir tree
2. Tra cứu câu đã khôi phục → tác phẩm **"The Tale of Peter Rabbit"**.
3. Tác giả = **Helen Beatrix Potter** → đáp án bài.

Gợi ý tự động hóa (so khớp multiset chữ cái với từ điển):
```python
from collections import Counter
# với mỗi từ anagram, tìm từ tiếng Anh w sao cho Counter(w)==Counter(word)
# (bỏ qua dấu '-' trong 'cotton-tail'); giữ nguyên thứ tự từ trong câu
```

## Flag
```
flag{Helen Beatrix Potter}
```
(Nguồn: `SOLUTIONS_VN.md` (C1) nêu đáp án `Helen Beatrix Potter`; nháp `Author.md` ghi *"the author is 'Helen Beatrix Potter'"*. Đáp án là **tên tác giả**, không phải chuỗi `flag{...}` cố định — **định dạng nộp cụ thể nguồn không nêu**; nội dung cần nộp là tên tác giả, bọc `flag{...}` giữ nguyên nội dung. Khi nộp nên thử cả `Helen Beatrix Potter` và bút danh `Beatrix Potter`.)

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đoạn text "vô nghĩa" nhưng mỗi từ giữ đúng số lượng chữ cái → nghĩ tới anagram (đảo chữ trong từ); đề hỏi "author/tác phẩm" → bài OSINT văn học sau khi giải.
- **Quy trình:** giải anagram từng từ (từ ngắn trước để định hướng) → ra vài từ đầu ("once upon a time...") thì đoán phần còn lại theo ngữ cảnh → dùng câu khôi phục làm truy vấn tìm kiếm → xác định tác phẩm → tra tác giả.
- **Bẫy:** đừng nhầm anagram với phép khác (đảo thứ tự từ, reverse cả chuỗi, Caesar) — kiểm bằng multiset chữ cái; dấu nối/khoảng trắng (`otcotn-ital` = `cotton-tail`) xử lý riêng; tên tác giả có thể cần dạng đầy đủ thay vì bút danh.
- **Checklist:** nhận ra anagram theo từng từ → khôi phục câu → OSINT "The Tale of Peter Rabbit" → tác giả = Helen Beatrix Potter.
