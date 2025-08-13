Công Cụ Bypass WAF
Đây là công cụ dựa trên Python để kiểm tra và bypass Web Application Firewall (WAF) sử dụng các payload định sẵn. Nó quét host target với nhiều method (GET, POST, v.v.) và zone (URL, ARGS, BODY, HEADER, COOKIE, USER-AGENT, REFERER) để xác định payload bị block, bypassed, hay passed. Hãy dùng nó làm điều hợp pháp và sẽ không chịu trách nhiệm cho bất kì hành động nào sử dụng tool làm điều phạm pháp

#Tính Năng

Hỗ trợ nhiều method HTTP (GET, POST, PUT, PATCH, DELETE).
Quét đa luồng để tăng hiệu quả.
Giới hạn rate (RPS) và retry để test đáng tin cậy.
DNS callback cho detection out-of-band.
Heuristics để detect challenge (e.g., CAPTCHA).
Tạo report CSV và HTML.
Check reflection cho true bypassed (kiểm tra payload có reflect trong body response).
Log chi tiết cho bypassed, blocked, và reflected payload.

#Cài Đặt
git clone https://github.com/Itachibx/Bypass/
Cài dependencies:
pip install -r requirements.txt
(Giả sử requirements.txt bao gồm requests, urllib3, prettytable, ast nếu cần).
Đảm bảo thư mục payload/ tồn tại với JSON payload (e.g., XSS, SQLi, v.v.).


#Sử Dụng
Chạy tool với lệnh sau:
textpython main.py --host "https://target.com/" [options]
Options nếu cần
--host: URL target (bắt buộc).
--methods: Method HTTP (e.g., "GET,POST") (default: "GET,POST").
--threads: Số luồng (default: 8).
--rps: Request per second (default: 6).
--retries: Số retry (default: 3).
--retry-backoff: Factor backoff retry (default: 0.5).
--dns-callback: URL DNS callback cho OOB (optional).
--discover: Bật discovery path (optional).
--discover-max: Max path discovery (default: 80).
--csv-out: File CSV output (e.g., results.csv).
--details: Bật log chi tiết.
--heuristics_mode: Mode heuristics (off, cautious, strict) (default: cautious).
--verify-challenge: Verify challenge.
--insecure: Tắt verify TLS.

Payload là file JSON trong utils/payload/.cấu trúc:
json{
  "payload": [
    {
      "METHOD": "GET,POST",
      "URL": "/test?param=<script>alert(1)</script>",
      "ARGS": {"param": "<script>alert(1)</script>"},
      "BODY": {"data": "<script>alert(1)</script>"},
      "HEADER": {"X-Test": "<script>alert(1)</script>"},
      "COOKIE": {"session": "<script>alert(1)</script>"},
      "USER-AGENT": "Mozilla/5.0 <script>alert(1)</script>",
      "REFERER": "http://evil.com <script>alert(1)</script>",
      "ENCODE": "Base64 UTF-16",
      "BLOCKED": true
    }
  ]
}
#Report

CSV: results.csv với cột: key, status, code, path, zone, json_path, category, payload.
HTML: waf_report.html – bảng visual với stats và entry.

Status:
BLOCKED: WAF chặn.
BYPASSED_REFLECTED: Bypass và payload reflect (tác động thật).
PASSED_NO_REFLECT: Passed nhưng không reflect (không tác động).
FALSED: Response invalid.
PASSED: Baseline hoặc no payload.
CHALLENGE: Detect CAPTCHA/challenge.

#Logging
Log hiển thị progress và info chi tiết bypass/block (e.g., "TRUE BYPASSED (REFLECTED): key with payload").
Check "BYPASSED_REFLECTED" để tìm vuln thực.
#Lưu Ý
Tool giả định payload trong utils/payload/. Adjust payload_dir trong bypass.py nếu cần.
Reflection check: Payload phải xuất hiện trong body response.
Nếu no BYPASSED_REFLECTED, site có thể không vuln hoặc WAF mạnh.
