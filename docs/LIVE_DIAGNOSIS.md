# Chẩn đoán 10 flow HTTP BENIGN trên Kali

Nguồn: người dùng cung cấp log replay và 10 dòng `benign02-truth.csv` ngày 10/11/2026. Đã nhận PCAP gốc bổ sung và phân tích cục bộ; không trực tiếp truy cập VM. Các mục đầu ghi lại chẩn đoán CSV trước khi có PCAP, phần cuối là kết quả kiểm chứng mới. Các flow được người chạy gán BENIGN theo kịch bản curl đã kiểm soát. Đây là một lượt chẩn đoán cùng loại HTTP, không đại diện mọi traffic hoặc attack.

## Kết quả đã tái hiện

Artifact được giữ nguyên: `multiclass-families-seed42/M3/models/stacking_ids.joblib`. Đưa đúng 12 cột của 10 CSV vào artifact trên Windows tái hiện cả 10 nhãn BRUTE_FORCE và các điểm xác suất trong log Kali (sai số <1e-6). Không có bằng chứng lỗi load khác hệ điều hành/package gây ra các dự đoán này.

| Model trong artifact | BENIGN | BRUTE_FORCE | Mean score BENIGN | Mean score BRUTE_FORCE |
|---|---:|---:|---:|---:|
| RF | 10 | 0 | 0,499813 | 0,178333 |
| XGB | 0 | 10 | 0,005623 | 0,595434 |
| LR base | 0 | 10 | Gần 0 | Gần 1 |
| Stacking | 0 | 10 | 0,340953 | 0,476880 |

Meta kết hợp xác suất bằng LR, không phải bỏ phiếu đa số. RF đúng trên 10 mẫu này không đủ căn cứ thay model triển khai bằng RF: còn thiếu attack và holdout mới để kiểm tra đánh đổi.

Log đánh giá người dùng: ghép đủ 10 flow, không có flow thiếu prediction/truth, FPR=100%, Accuracy=0% trên lượt BENIGN này; FNR=null vì không có attack. Suy luận replay p50=68,506 ms, p95=125,041 ms; độ trễ live không đo được từ replay. Không coi counts flow ghép đủ là bằng chứng không mất packet.

## Sai khác feature đã xác nhận

| Feature | 10 flow lab | Trong development hai nguồn đã học |
|---|---:|---|
| FIN Flag Count | 2 | 0/1 |
| SYN Flag Count | 2 | 0/1 |
| PSH Flag Count | 3 | 0/1 |
| ACK Flag Count | 9 | 0/1 |

[flows.py](../src/flows.py):61 đếm payload; :63 cộng flag từng packet trong cả hai hướng. FIN=2, SYN=2, ACK=9 có thể là số đếm hợp lệ của một kết nối TCP 10 packet, không chứng minh attack. Vấn đề là định nghĩa không khớp các cột mà model đã học.

[Tài liệu nghiên cứu gốc về lỗi CIC-IDS2017, mục TCP flag count](https://intrusion-detection.distrinet-research.be/WTMC2021/extended_doc.html) xác nhận CSV cũ có flag 0/1 vì CICFlowMeter chỉ cập nhật flag cho packet đầu; bản sửa cập nhật mỗi packet. Đây **không phải** phép OR/presence trên toàn flow. Nguồn còn mô tả cách đóng flow ở FIN và timeout của extractor cũ, nên đồng nhất riêng flag không đủ để chứng minh parity toàn bộ feature.

Với LR base, ACK của mẫu lab sau StandardScaler khoảng 18,14 độ lệch chuẩn so với mean train. Đóng góp trung bình vào chênh lệch logit BRUTE_FORCE−BENIGN: ACK +27,997; PSH +19,572; FIN +17,757; SYN +12,134. Đây là phân rã phép tính của LR trên chính các mẫu này, không là chứng minh nguyên nhân ngoài mô hình. Model đang ngoại suy mạnh trên các giá trị flag chưa gặp.

Mẫu development tại cổng 8080 còn lệch nhãn: CIC BOT=982, BENIGN=4, InSDN=0. Đây là dấu hiệu domain shift bổ sung; chưa đủ để quy mọi dự đoán BRUTE_FORCE cho cổng.

## Kiểm tra độ nhạy, không phải bản sửa được nghiệm thu

- Thử chuyển riêng flag thành presence (x>0) vẫn cho 10/10 BRUTE_FORCE. Không triển khai phép clip này như một bản sửa parity.
- Thử **giả định** packet đầu là SYN và giữ nguyên các feature khác vẫn cho 9 BRUTE_FORCE, 1 U2R. Đây là phép thử trên CSV, không phải trích xuất lại PCAP; không suy ra thứ tự packet từ tổng flag.
- Không đổi model, whitelist cổng, ngưỡng hoặc nhãn để ép lượt thử thành công. Điểm test offline cũ vẫn giữ nguyên.

## Dữ liệu cần tiếp theo

Cần `captures/benign02.pcap` để lấy cờ gói đầu, thứ tự FIN/RST, chiều flow, ranh giới flow, độ dài packet/payload và thời điểm thật. CSV tổng hợp hiện tại không chứa đủ dữ liệu phục dựng các thông tin này. Đối chiếu với extractor reference độc lập, ghi phiên bản/config; chỉ sau đó chọn cách thống nhất feature hoặc thu thập dữ liệu có nhãn bằng cùng extractor để huấn luyện bổ sung theo phiên.

Ngữ nghĩa flag của CIC gốc có nguồn xác nhận; các flag nhị phân quan sát ở InSDN local chưa tự chứng minh InSDN dùng đúng phiên bản/bug tương tự. Phải ghi rõ hạn chế này khi gộp dữ liệu.

Tài liệu và kết quả số lưu tại `experiments/completion-20261110/vm-user-benign02/`: CSV người dùng, xác suất base/meta, đóng góp logit LR và diagnostic-status.json. Lượt này được giữ làm dữ liệu chẩn đoán; đánh giá cải tiến phải có các phiên BENIGN/attack mới độc lập.

## Cập nhật sau khi nhận benign02.pcap

PCAP gốc 10.274 byte, SHA-256 `76710117184a0fb0b42bcd8fe7101a0370e43330b3940bf269429c6e887a7690`, gồm 100 packet TCP, 10 kết nối có GET / HTTP/1.1 và HTTP/1.0 200 OK. Packet đầu của cả 10 là SYN. Runtime cũ tái trích đúng từng giá trị CSV người dùng, nên khác biệt nằm ở cách đo/predict, không phải sai file CSV.

### Lỗi đã sửa: Ethernet padding bị tính thành TCP payload

Trong PCAP, ACK không mang dữ liệu có IP total length 40, IP header 20 và TCP header 20; frame Ethernet được pad lên 60 byte. Scapy thể hiện 6 byte padding dưới TCP.payload. `len(bytes(transport.payload))` trước đây đã cộng nhầm chúng vào payload: 3 packet × 6 byte = 18 byte dư mỗi chiều gửi HTTP. Request thật có 84 byte, response 199 byte; runtime cũ báo 102/199.

`flows.py` nay giới hạn payload theo độ dài IP/header TCP hoặc UDP length, giữ nguyên dữ liệu ứng dụng thật kể cả byte 0. Version `scapy-ip-payload-v2` được ghi vào log và CSV, log có thêm `feature_values` để kiểm tra 12 đầu vào. 62 test đã qua, gồm ACK được pad, UDP, TCP options, dữ liệu zero hợp lệ và header length không hợp lệ.

### Kết quả thật sau sửa

| Trạng thái | Flow | Byte gửi/nhận | Prediction | FPR trên lượt này |
|---|---:|---|---|---:|
| Runtime cũ | 10 | 102 / 199 | 10 BRUTE_FORCE | 100% |
| Payload v2 | 10 | 84 / 199 | 10 BRUTE_FORCE | 100% |

Bản sửa loại bỏ một lỗi đếm byte có thật, **chưa giải quyết khả năng tổng quát của model**. Không đổi model, ngưỡng hoặc gán lại nhãn. Nguồn lỗi semantic flag và khác biệt đóng flow đã nêu vẫn tồn tại; raw PCAP cho phép kiểm chứng chúng, không làm model tự tương thích với dataset cũ.

Một phép trích thăm dò theo gói đầu + first-FIN tạo 30 phân đoạn (21 BENIGN, 9 BRUTE_FORCE). Trong 10 phân đoạn HTTP chính vẫn có 9 bị dự đoán sai. Đây không phải chạy CICFlowMeter độc lập; số flow đã thay đổi nên không so FPR 9/30 với 10/10 để công bố cải thiện. Không đưa phép thăm dò này vào detector.

### Quyết định triển khai

Giữ model và benchmark cũ. Dùng runtime v2 cho các capture tiếp theo để đếm payload đúng, nhưng vẫn ghi parity unvalidated. Muốn hoàn thiện phát hiện, cần thống nhất extractor cho dữ liệu học và triển khai: tái trích PCAP có nhãn của nguồn dữ liệu bằng cùng extractor, hoặc xây dựng nhánh thực nghiệm lab có đủ BENIGN và attack, chia theo phiên trước train/validation/test. 10 phiên HTTP này chỉ dùng chẩn đoán; chưa có dữ liệu attack/holdout độc lập để huấn luyện và nghiệm thu một bản sửa hiệu năng.

Bản runtime v2 được đóng riêng tại `deliverables/ids-vm-multiclass-combined-seed42-padding-v2.zip`. Model không đổi; đây là gói sửa phép đếm và tăng khả năng truy vết, không phải model đã khắc phục FPR. Cần kiểm tra các phiên mới có nhãn độc lập sau mọi cải tiến.

## M3 huấn luyện lại với ba mô hình cây

Replay lại PCAP này với M3 mới seed 42 cho 9 BENIGN và 1 U2R trên cùng 10 flow. Kết quả ba seed và đường dẫn model mới ở [CURRENT_RESULTS.md](CURRENT_RESULTS.md#m3-đa-lớp-với-rf-xgboost-và-lightgbm). Gói `ids-vm-multiclass-combined-seed42-trees.zip` dùng để kiểm thử tiếp với capture mới trên Kali.
