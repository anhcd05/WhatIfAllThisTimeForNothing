# reverse-image-ramen

- **Category:** OSINT (nguồn ghi Misc/OSINT)
- **File đề:** không có file — đề dẫn tới một trang hội nghị bảo mật Nhật + một ảnh món ăn. Flag format: `flag{<restaurant_code>}` lấy từ URL tabelog.com.

## Tóm tắt đề
Chuỗi pivot OSINT dựa trên ảnh: (1) vào trang danh sách diễn giả JSAC (hội nghị của JPCERT) 2023; (2) tìm diễn giả có **ảnh đại diện là món ăn Nhật** (cuối trang); (3) reverse image search để tìm nhà hàng phục vụ đúng món/đĩa đó trên **tabelog.com**; (4) lấy **mã nhà hàng** (restaurant_code) làm flag.

## Phân tích (chi tiết: cấu trúc URL/pivot thật)
- Trang diễn giả: `https://jsac.jpcert.or.jp/archive/2023/en/speakers.html`. Kéo xuống cuối trang → ảnh mục tiêu (avatar là một món ăn/ramen trên đĩa đặc trưng).
- **Cấu trúc URL tabelog:** `https://tabelog.com/en/{area_name}/{area_code}/{city_code}/{restaurant_code}`. Chỉ **dãy số cuối** là `restaurant_code`.
- Dùng Google Lens tìm ảnh có **cùng đĩa/cách bày** → tới trang nhà hàng:
```
https://tabelog.com/en/tokyo/A1302/A130201/13249397/
```
→ `restaurant_code = 13249397`. (Không nhầm với `A1302` = area_code hay `A130201` = city_code.)

## Kỹ thuật áp dụng (+ VÌ SAO)
- **Reverse image search (Google Lens/Yandex/TinEye):** VÌ SAO: đầu mối duy nhất là hình thức món ăn + chiếc đĩa; tìm ảnh tương tự dẫn tới trang nhà hàng cụ thể (Yandex thường mạnh với ảnh món/khuôn mặt).
- **Hiểu cấu trúc URL tabelog:** VÌ SAO: bóc đúng `restaurant_code` (dãy số cuối), tránh nhầm area/city code.
- **Điều hướng trang hội nghị:** VÌ SAO: thu hẹp mục tiêu về đúng diễn giả có avatar là đồ ăn.

## Lời giải chi tiết (bước)
1. Mở trang diễn giả JSAC 2023, kéo xuống cuối → lấy ảnh món ăn (độ phân giải cao nhất có thể).
2. Reverse image search (Google Lens; đối chiếu Yandex/TinEye nếu cần), lọc theo chi tiết đặc trưng (hoa văn đĩa, cách bày, nền).
3. Lần theo kết quả tới trang nhà hàng tabelog có cùng món/đĩa.
4. Bóc dãy số cuối URL: `https://tabelog.com/en/tokyo/A1302/A130201/13249397/` → `13249397`.

## Flag
flag{13249397}

## Gặp lại thì xử lý thế nào (playbook)
- **Dấu hiệu:** đề cho một ảnh (avatar/ảnh món) và yêu cầu định danh địa điểm/nhà hàng → bài reverse image + pivot.
- **Quy trình:** (1) lấy ảnh gốc độ phân giải cao nhất; (2) reverse search nhiều engine; (3) khớp chi tiết đặc trưng (đĩa/logo/nền); (4) tới tabelog, đọc đúng vị trí `restaurant_code`.
- **Công cụ:** Google Lens, Yandex Images, TinEye, trình duyệt.
- **Bẫy:** đừng lấy nhầm `area_code`/`city_code` làm flag; nhiều nhà hàng bán cùng món → phân biệt bằng **cùng chiếc đĩa/cách bày**.
