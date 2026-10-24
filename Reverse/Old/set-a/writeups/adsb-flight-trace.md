# adsb-flight-trace

- **Category:** OSINT (nguồn ghi MISC/OSINT)
- **File đề:** không có file — điều tra dữ liệu chuyến bay của Pavel Durov (đồng sáng lập Telegram) bị bắt tại Pháp ngày **24/08/2024**. Flag format: `flag{<Aircraft Registration>:<Country>}`.

## Tóm tắt đề
Ngày 24/08/2024, Pavel Durov bị bắt ngay sau khi máy bay hạ cánh ở Pháp. Dùng OSINT dữ liệu chuyến bay để tìm: (1) **Aircraft Registration** (gồm chữ/số và dấu `-`); (2) **tên quốc gia** máy bay đang bay qua **đúng 2 giờ trước khi hạ cánh** tại sân bay Paris.

## Phân tích (chi tiết: mốc giờ/registration/đường bay thật)
1. **Thời điểm hạ cánh.** Tin tức: máy bay tới sân bay **Le Bourget** lúc ~**19:30 giờ Paris**. Paris mùa hè = **CEST = UTC+2** ⇒ **17:30 UTC**.
2. **Tra lịch sử bay.** Vào **ADS-B Exchange** (`https://globe.adsbexchange.com/`) — dữ liệu lịch sử miễn phí, không che máy bay riêng tư. Lọc ngày/giờ 24/08/2024, chuyến hạ ở Paris quanh 17:30 UTC → máy bay **Registration `OE-IOI`** hạ cánh Le Bourget lúc **17:32 UTC**.
3. **Truy vết 2 giờ trước.** Dùng playback/history lùi về **15:32 UTC** (2 giờ trước giờ hạ thực tế 17:32) → máy bay đang bay **trên bầu trời Hungary**.
4. Ghép: Registration `OE-IOI`, quốc gia `Hungary`.

## Kỹ thuật áp dụng (+ VÌ SAO)
- **ADS-B Exchange (lịch sử/playback):** VÌ SAO: không lọc/giấu máy bay như một số dịch vụ khác và cho truy cập dữ liệu lịch sử miễn phí → xem lại đúng đường bay theo ngày/giờ.
- **Quy đổi múi giờ (Paris CEST = UTC+2):** VÌ SAO: dữ liệu ADS-B theo UTC; xác định đúng cửa sổ 17:30 UTC và mốc "2 giờ trước" = 15:32 UTC.
- **Phân biệt Registration vs ICAO address (hex):** VÌ SAO (hint đề): dễ nhầm mã hex ICAO 24-bit với registration; flag cần **registration** dạng `OE-IOI` (có dấu `-`).

## Lời giải chi tiết (bước)
1. Gắn mốc thời gian từ tin tức, đổi hết về UTC (19:30 Paris → 17:30 UTC).
2. Mở ADS-B Exchange, lọc ngày 24/08/2024 + khu vực Le Bourget/Paris, khoanh chuyến hạ quanh 17:30 UTC.
3. Đọc **Registration** `OE-IOI` (không lấy ICAO hex), ghi giờ hạ chính xác 17:32 UTC.
4. Playback lùi −2 giờ → 15:32 UTC → xác định quốc gia bên dưới đường bay = Hungary.

## Flag
flag{OE-IOI:Hungary}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đề gắn với sự kiện/máy bay/thời điểm cụ thể, yêu cầu registration + đường bay → bài flight-tracking OSINT.
- **Quy trình:** (1) gắn mốc thời gian từ tin tức, đổi hết về UTC; (2) mở ADS-B Exchange, lọc ngày + sân bay/khu vực, khoanh chuyến đúng khung giờ; (3) đọc Registration (không ICAO hex), ghi giờ hạ chính xác; (4) playback lùi đúng offset (−2 giờ) → xác định quốc gia dưới đường bay.
- **Công cụ:** ADS-B Exchange (ưu tiên lịch sử/không bị che), FlightRadar24/FlightAware để đối chiếu, bản đồ.
- **Bẫy:** quên quy đổi múi giờ (CEST=UTC+2); nhầm registration `OE-IOI` với ICAO hex; "2 giờ trước" tính từ giờ hạ **thực tế** (17:32 → 15:32 UTC); một số site giấu máy bay riêng tư → ưu tiên ADS-B Exchange.
