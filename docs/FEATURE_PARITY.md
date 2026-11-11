# Kiểm chứng đặc trưng trước khi kết luận độ chính xác live

Chưa có phép đo parity trên PCAP thật trong phiên chuẩn bị này. Việc có cùng 12 tên cột hoặc replay bằng cùng `flows.py` không chứng minh tương đương với CICFlowMeter. Gói VM có thể kiểm thử ngay, nhưng chưa được dùng F1 offline làm F1 realtime.

## Một capture, hai extractor độc lập

1. Trên adapter Host-only, lưu một PCAP IPv4 TCP/UDP gồm các phiên đã biết. Tách benign và scan; không lấy lưu lượng ngoài lab. Ghi interface, capture filter, thời gian, checksum, timeout và phiên bản mỗi extractor.
2. Chạy **CICFlowMeter độc lập**, đúng phiên bản/cách cấu hình đã tạo dữ liệu huấn luyện nếu xác định được. Xuất full flow CSV có IP, cổng, protocol và thời điểm gói đầu, không chỉ MachineLearningCSV. Ghi command/commit thực tế; không thay bằng bản `pip install cicflowmeter` khác rồi mặc định tương đương bản Java gốc.
3. Chạy extractor triển khai trên chính PCAP đó:

```bash
.venv/bin/python src/extract.py --pcap captures/scan01.pcap \
  --out captures/scan01-scapy.csv --idle 10 --max-age 60
```

4. So sánh reference `scan01-cic.csv` với CSV Scapy. Ví dụ sau **chỉ đúng nếu timestamp reference có format này và được xuất theo UTC**; thay bằng cấu hình thật:

```bash
.venv/bin/python src/feature_parity.py \
  --reference captures/scan01-cic.csv --candidate captures/scan01-scapy.csv \
  --reference-format cicflowmeter \
  --timestamp-format '%d/%m/%Y %H:%M:%S.%f' --timezone UTC \
  --reference-extractor 'GHI_PHIEN_BAN_COMMIT_VA_COMMAND_CICFLOWMETER_THAT' \
  --pcap captures/scan01.pcap --out captures/parity-scan01.json
```

Tool chuẩn hóa alias tên cột, IP/cổng, protocol 6/17 sang TCP/UDP và timestamp theo timezone khai báo. Thiếu metadata, mơ hồ tên cột, timezone không rõ hoặc protocol ngoài phạm vi sẽ bị từ chối; không tự bỏ các flow khó so sánh. Định dạng normalized cũ vẫn dùng được khi cả hai CSV đã có đúng schema.

Kết quả lưu SHA-256 của PCAP và hai CSV, thông tin reference, số flow ghép/không ghép và sai khác từng feature. Exit code 1 nếu phép đối chiếu thất bại. Không truyền cùng một đường dẫn CSV vào cả hai phía. Tên extractor là thông tin người chạy phải cung cấp đúng, không phải chứng nhận tự động về nguồn CSV.

## Đọc kết quả

- `passed_this_capture=true` yêu cầu mọi flow khớp endpoint/hướng/thời điểm gói đầu và mọi feature nằm trong sai số mặc định 1e-6. Chỉ xác nhận capture đang kiểm tra.
- Timestamp cần độ chính xác microsecond. Nếu reference chỉ có giây/millisecond, không tùy tiện làm tròn candidate để ép khớp; cần export thời gian gốc đủ chính xác hoặc ghi nhận chưa đủ dữ liệu đối chiếu.
- Sai hướng, khác đóng flow khi FIN/RST, timeout, phiên bị cắt hoặc khác cách đếm byte/flag đều có thể làm fail. Kiểm tra nguyên nhân trước khi đổi ngưỡng.
- Thử benign, scan và phiên TCP/UDP dài; không chỉ chọn capture dễ để công bố pass. Nếu không biết phiên bản đã sinh CSV dataset, một phép so với bản CICFlowMeter khác chưa chứng minh tương đương với dataset gốc.

## Khi phép so sánh không đạt

Chọn cách tính feature thống nhất cho train và triển khai. Nếu dùng extractor Scapy hiện tại, thu thập nhiều phiên lab có nhãn từ kịch bản độc lập, trích cùng `flows.py`, chia train/validation/test **theo phiên/thời gian trước khi tune**. Test phải giữ riêng, không đưa vào huấn luyện sau khi xem lỗi. Không train từ nhãn dự đoán của model cũ.

Đây là phần kiểm chứng bổ sung ngoài thí nghiệm CIC/InSDN; không ghi đè các model hoặc kết quả đã có. Khi chưa có PCAP/reference thật, trạng thái đúng là **PoC đang kiểm thử**, không tạo kết quả parity giả từ fixture hoặc từ hai CSV cùng extractor.

## Hoàn thiện kết quả ES

ES hiện chưa vượt baseline trên InSDN và test gộp. Cải tiến tiếp theo phải chọn bằng train/validation: kiểm tra lỗi từng lớp, độ đa dạng/sai số tương quan giữa các base model, class weighting và ngân sách tham số công bằng. Cố định thiết kế trước test mới theo phiên/thời gian. Báo đủ seed và support của U2R/INFILTRATION; không chọn seed hoặc gộp nhãn theo điểm test để tạo kết luận ES thắng.

## Bằng chứng mới từ PCAP lab

LIVE_DIAGNOSIS.md ghi lại lỗi đếm padding đã xác nhận: `bytes(TCP.payload)` của Scapy có thể chứa Ethernet padding ngoài độ dài IP. Bản `scapy-ip-payload-v2` đã giới hạn phép đếm theo header lengths. Đây là sửa đúng định nghĩa payload, chưa chứng minh parity với dataset. CIC-IDS2017 gốc còn có bug flag chỉ tính packet đầu và chính sách đóng flow khác; không lấy phép OR của flags làm bản thay thế mà gọi là tương đương. Replay PCAP người dùng sau sửa vẫn báo động giả, nên phải thống nhất dữ liệu/extractor và có đánh giá độc lập trước nghiệm thu.
