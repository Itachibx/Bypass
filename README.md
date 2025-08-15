""""" 
Tổng Quan:
Bypass là một công cụ dựa trên Python được thiết kế dành cho các bạn kiểm tra thâm nhập và nghiên cứu bảo mật để kiểm tra WAF. Nó sử dụng các payload được định nghĩa sẵn để quét qua các phương thức HTTP khác nhau (GET, POST, v.v.) và các vùng khác nhau (URL, ARGS, BODY, HEADER, v.v.). Công cụ hỗ trợ đa luồng, giới hạn tốc độ yêu cầu, heuristics để phát hiện các bước ngăn chặn như CAPTCHA, và tạo báo cáo dưới dạng CSV/HTML.

Mình viết tool này không nhằm mục đích thương mại hóa, hay là thể hiện bản thân mình, chỉ muốn tạo sản phẩm để học hỏi và nâng cao trình độ.

Tuyên Bố Từ Chối Trách Nhiệm: Công cụ này chỉ dành cho mục đích giáo dục và kiểm tra thâm nhập hợp pháp. Không sử dụng trên hệ thống mà không có sự cho phép rõ ràng. Mình không chịu trách nhiệm cho bất kỳ những hành vi phạm pháp nào đó khi sử dụng tool của mình

Các tính năng chính:
Quét Payload: Kiểm tra với các payload tùy chỉnh hoặc tích hợp sẵn cho các lỗ hổng phổ biến.bạn có thể làm giàu về tài nguyên này
Hỗ Trợ Phương Thức HTTP: Bao gồm GET, POST, PUT, DELETE, và nhiều hơn thế
Nhắm Đến Vùng: Chèn payload vào URL, body, header, v.v.
Tùy Chọn Nâng Cao: DNS callback cho phát hiện out-of-band, kiểm tra reflection để xác nhận bỏ qua thực sự
Báo Cáo: Báo cáo chi tiết với các chỉ số 
Tính Năng Nâng Cao: Giới hạn tốc độ để tránh bị phát hiện ghi log

Cài Đặt:

Python 3.8 hoặc cao hơn
Các thư viện cần thiết:
pip install -r requirements.txt

 
Các Tùy Chọn Payload:

--url <target_url>: URL mục tiêu để kiểm tra (bắt buộc).
--method <http_method>: Phương thức HTTP để sử dụng (ví dụ: GET, POST). Mặc định: GET.
--zone <zone>: Vùng để chèn payload (ví dụ: URL, ARGS, BODY, HEADER). Có thể chỉ định nhiều bằng dấu phẩy.
--payloads <file>: Đường dẫn đến file JSON payload. Mặc định: utils/payload/payloads.json.
--threads <num>: Số luồng cho quét song song. Mặc định: 10.
--rate-limit <requests_per_sec>: Giới hạn yêu cầu mỗi giây để tránh bị phát hiện/ ghi log. Mặc định: 5.
--heuristics: Bật phát hiện thử thách (ví dụ: CAPTCHA, trang 403).
--dns-callback <dns_server>: Bật DNS callback cho phát hiện OOB.
--check-reflection: Xác nhận nếu payload được phản ánh trong phản hồi.
--report <format>: Tạo báo cáo (CSV hoặc HTML)
Ví Dụ
Quét cơ bản trên URL GET:
bashpython main.py --url https://example.com/vuln --method GET --zone ARGS

Đa luồng POST với payload tùy chỉnh và giới hạn tốc độ:
bashpython main.py --url https://example.com/api --method POST --zone BODY --payloads custom_payloads.json --threads 20 --rate-limit 10 --report html

Nâng cao với heuristics và DNS callback:
bashpython main.py --url https://target.com --heuristics --dns-callback <yourdns.server> --check-reflection

Định Dạng Payload
Payload được lưu trữ dưới dạng JSON trong utils/payload/. Cấu trúc ví dụ:
json{
  "xss": [
    "<script>alert(1)</script>",
    "'\"><script>alert(1)</script>"
  ],
  "sqli": [
    "1' OR '1'='1",
    "1 UNION SELECT 1,2,3"
  ]
}
Bạn có thể thêm hoặc sửa đổi payload theo nhu cầu và mục đích của bạn, tôi chỉ sử dụng các payload nhằm đảm bảo không ảnh hưởng đến hệ thống và khá basic, không nhằm mục đích phá hoại

Báo Cáo

Báo Cáo CSV: Các cột bao gồm: Payload, Phương Thức, Vùng, Mã Trạng Thái, Thời Gian Phản Hồi, Thành Công/Thất Bại.
Báo Cáo HTML: Bảng tương tác với lọc. Được tạo trong thư mục reports/.

Tất cả mọi sự đóng góp được chào  và tiếp thu hãy mở issue trên GitHub hoặc liên hệ tôi tại [itachibx2@gmail.com].
""
