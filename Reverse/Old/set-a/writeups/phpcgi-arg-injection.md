# phpcgi-arg-injection

- **Category:** Network (Traffic Analysis → CVE identification)
- **File đề:** `network_challenge.pcapng` — pcap chứa nhiều phiên port scan bằng nmap lẫn với lưu lượng HTTP request/response. *(Chú thích: writeup đề tham chiếu pcap này; bản repo set-a không kèm file — phân tích dựa trên nội dung được trích trong nguồn.)*

## Tóm tắt đề
Trong pcap có một loạt gói port scan do nmap tạo ra, lẫn với HTTP request/response. Nhiệm vụ **không** phải lấy chuỗi `flag{...}` thông thường mà là **xác định số hiệu CVE** của lỗ hổng bị khai thác. Môi trường mục tiêu là máy ảo huấn luyện **Metasploitable2** (chuỗi `"metasploitable2"` xuất hiện quanh frame 131325).

## Phân tích (chi tiết: hằng số/offset/payload/khóa thật)
Port scan không phải hành vi khai thác → lọc bỏ, tập trung HTTP. Gói quyết định nằm ở **frame 132445**, là HTTP POST có query string rất đặc trưng:
```
POST /?-d+allow_url_include%3dON+-%64+safe_mode%3doFf+--define+suhosin.simulation%3d1
   +--define+disable_functions%3d%22%22+-%64+open_basedir%3dnone
   +-d+auto_prepend_file%3dphp://input+-%64+cgi.force_redirect%3doFf
   +-%64+cgi.redirect_status_env%3d0+-%6e HTTP/1.1
Content-Type: application/x-www-form-urlencoded
```
URL-decode (lưu ý `%64`=`d`, `%6e`=`n`, chữ hoa/thường trộn `oFf` để né IDS):
```
-d allow_url_include=ON -d safe_mode=oFf --define suhosin.simulation=1
--define disable_functions="" -d open_basedir=none
-d auto_prepend_file=php://input -d cgi.force_redirect=oFf
-d cgi.redirect_status_env=0 -n
```

Đây là **chữ ký kinh điển của PHP-CGI query string parameter injection**: khi PHP chạy ở chế độ CGI, các tham số trên query string **không chứa dấu `=`** bị truyền thẳng làm **đối số dòng lệnh cho binary `php-cgi`**. Kẻ tấn công bật `auto_prepend_file=php://input` để ép PHP **nạp và thực thi nội dung body của request như mã PHP** → RCE. Các tham số `-d allow_url_include=ON`, `-d safe_mode=oFf`, `--define disable_functions=""`, `-d open_basedir=none`, `-d cgi.force_redirect=oFf` nhằm vô hiệu hóa các biện pháp hạn chế trước khi chạy payload trong body.

Khóa thật: tổ hợp đồng thời `auto_prepend_file=php://input` + `allow_url_include=ON` + `cgi.force_redirect=oFf` là dấu hiệu gần như duy nhất của **CVE-2012-1823** (biến thể vá chưa đủ: **CVE-2012-2311**). Nó chạy được trên Metasploitable2 vì PHP ở đó chạy dạng CGI và dính lỗi này.

## Kỹ thuật áp dụng (+ VÌ SAO nhận ra)
- **Wireshark / tshark** lọc và xem HTTP:
  - Bỏ scan, chỉ HTTP: `http`
  - Tìm POST: `http.request.method == "POST"`
  - Nhảy tới gói nghi vấn: `frame.number == 132445`
  - Gợi ý mục tiêu: `frame contains "metasploitable2"` (gần frame 131325)
- **URL decode** query string (Wireshark tự giải hoặc CyberChef "URL Decode").
- **VÌ SAO nhận ra:** sự có mặt đồng thời của `auto_prepend_file=php://input`, `allow_url_include=ON`, `cgi.force_redirect=oFf` trong một query string ⇒ không có khai thác PHP phổ biến nào khác dùng đúng tổ hợp này ngoài CVE-2012-1823.

## Lời giải chi tiết (bước + code/lệnh/payload sạch, chạy lại được)
1. Mở `network_challenge.pcapng` trong Wireshark.
2. Filter `http` để loại gói scan nmap.
3. Go → Go to Packet → **132445**, xem HTTP POST với query string đáng ngờ.
4. URL-decode query string, nhận ra tổ hợp tham số đẩy vào `php-cgi`.
5. (Tùy chọn) soi quanh frame 131325 thấy `metasploitable2`, xác nhận mục tiêu.
6. Tra cứu chữ ký → PHP-CGI query string injection → **CVE-2012-1823**.

Với tshark:
```bash
tshark -r network_challenge.pcapng -Y 'http.request.method=="POST"' -T fields -e frame.number -e http.request.uri
# Follow stream để thấy mã PHP trong body và output RCE:
tshark -r network_challenge.pcapng -q -z follow,tcp,ascii,<stream_index>
```

## Flag
flag{CVE-2012-1823}

*(Nguồn canonical `SOLUTIONS_VN.md` — bài #10: đáp án cốt lõi là **CVE-2012-1823**. Đề yêu cầu "tìm số CVE" và **nguồn không nêu rõ wrapper `flag{...}`** cho bài này; một số BTC chấp nhận thêm biến thể CVE-2012-2311.)*

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu nhận diện:** HTTP request tới PHP endpoint có query string chứa `-d`, `--define`, `auto_prepend_file`, `php://input`, `allow_url_include`, `safe_mode`, `cgi.force_redirect`. Thấy các từ khóa này gần như chắc chắn là CVE-2012-1823.
- **Quy trình:**
  1. Lọc bỏ nhiễu scan (`http` only, hoặc loại `tcp.flags.syn==1 && tcp.flags.ack==0`).
  2. Soi `http.request.method == "POST"` và query string bất thường.
  3. URL-decode để đọc đối số thật.
  4. Nếu có payload trong body (POST data) → đó là mã PHP được RCE; follow TCP stream để thấy lệnh và output.
- **Công cụ:** Wireshark/tshark, CyberChef (URL Decode), tra CVE theo chữ ký.
- **Bẫy:** đừng sa đà phân tích hàng vạn gói scan (chỉ là nhiễu). Query string trộn mã hóa hoa/thường (`oFf`, `%64`=`d`, `%6e`=`n`) để né IDS — luôn decode trước khi kết luận.
- **Checklist:** [ ] lọc HTTP [ ] tìm POST lạ [ ] URL-decode [ ] nhận chữ ký php-cgi [ ] map ra CVE-2012-1823.
