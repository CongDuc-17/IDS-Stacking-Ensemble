# Host, Gaussian, đồ thị giao tiếp và kiểm chứng triển khai

Cập nhật 10/11/2026. Chạy các lệnh từ thư mục gốc dự án. Dùng output mới cho mỗi lượt để giữ kết quả cũ.

## Cài đặt và kiểm tra

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lab.in
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`requirements-lab.in` thêm Scapy cho PCAP/live. Capture trên Kali còn cần libpcap và quyền truy cập interface; các thư viện mô hình không tự cung cấp quyền bắt gói tin.

## 1. PCAP thành flow và host

Dùng `extract.py` hiện có, giữ cùng idle/max-age với detector:

```powershell
.\.venv\Scripts\python.exe src/extract.py --pcap captures/benign-session.pcap --out captures/benign-flows.csv --label BENIGN --idle 10 --max-age 60
.\.venv\Scripts\python.exe src/host_features.py --csv captures/benign-flows.csv --out experiments/host-benign --window 60
```

Chỉ dùng `--label` khi toàn capture thuộc đúng một kịch bản đã biết. Capture hỗn hợp phải gán nhãn theo endpoint/thời gian/hành động độc lập, không dùng output model làm ground truth.

`host_features.py` tạo `hosts.csv`, `edges.csv`, `protocol.json`. Mỗi host/window gồm số flow vào/ra, peer duy nhất, cổng đích ra duy nhất, packet/byte gửi nhận và tổng cờ SYN/RST trong flow liên quan. Các flow được đưa vào cửa sổ tại thời điểm **hoàn tất**, tránh lấy đặc trưng của những gói tin tương lai cho cửa sổ trước.

Nhãn ATTACK ở mức host/window chỉ nói host có liên quan đến flow tấn công, bao gồm cả nạn nhân. Không được diễn giải thành host đã nhiễm mã độc. Nếu có flow chưa có nhãn thật, cửa sổ đó là UNKNOWN và bị loại khỏi metrics có giám sát.

## 2. Metadata InSDN

CSV InSDN local có IP và timestamp, nên có thể dùng cho nhánh host/graph. CSV MachineLearningCVE hiện có không cung cấp metadata tương đương đầy đủ; muốn phân tích host của CIC cần bản CSV có metadata hoặc PCAP gốc.

File InSDN local có cả timestamp 24 giờ và dạng có giây/AM-PM. Lệnh sau **chọn rõ cách đọc ngày/tháng/năm**, không đoán ngày/tháng:

```powershell
.\.venv\Scripts\python.exe src/host_features.py --csv "data/InSDN(2020)/InSDN_Normal_and_Attack_Combined.csv" --out experiments/insdn-hosts-new --window 60 --timestamp-format "%d/%m/%Y %H:%M|%d/%m/%Y %I:%M:%S %p" --drop-invalid-time
```

Cần đối chiếu cách ghi ngày với nguồn tải nếu dùng mốc lịch làm bằng chứng. Nếu hai format cho hai ngày khác nhau, chương trình dừng. Dữ liệu local có 8 flow thời lượng âm; mặc định chương trình từ chối. `--drop-invalid-time` cho phép loại rõ ràng và ghi số lượng vào protocol. Không sửa hoặc ghi đè CSV nguồn.

## 3. Gaussian anomaly

Một Gaussian với covariance đường chéo được fit trên BENIGN train. Ngưỡng anomaly lấy từ quantile BENIGN validation với FPR mục tiêu mặc định 1%; test không tham gia chọn ngưỡng. Điểm anomaly là negative log-density, không phải xác suất bị tấn công. Không có bảo đảm phát hiện zero-day.

**Flow:** dùng chính ba split đã chuẩn bị cho Stacking để so sánh trên cùng các hàng test:

```powershell
.\.venv\Scripts\python.exe src/gaussian.py --train experiments/completion-20261110/three-models-seed42/splits/cicids2017/train.csv --validation experiments/completion-20261110/three-models-seed42/splits/cicids2017/validation.csv --test experiments/completion-20261110/three-models-seed42/splits/cicids2017/test.csv --out experiments/gaussian-flow-cic-new
```

Đổi `cicids2017` thành `insdn` để chạy nguồn còn lại. Flow mode kiểm tra vector không trùng giữa ba split. Dữ liệu flow có một số phép đo âm; Gaussian dùng `sign(x)*log(1+abs(x))`, giữ và ghi số đo âm trong protocol thay vì âm thầm clip. Các hạn chế random split/class cap vẫn được kế thừa.

**Host:** dùng `hosts.csv` có nhãn thật, chương trình chia 60/20/20 theo các cửa sổ thời gian hoàn tất; tất cả host trong cùng một cửa sổ ở cùng một phần:

```powershell
.\.venv\Scripts\python.exe src/gaussian.py --data experiments/insdn-hosts-new/hosts.csv --out experiments/gaussian-host-new
```

Cần ít nhất 5 hàng BENIGN train và 3 hàng BENIGN validation. Nếu thiếu, thu thập thêm giai đoạn bình thường độc lập; không kéo các hàng test về train. Các giai đoạn cùng thời gian không được vượt ranh giới chia tập.

Đầu ra: `gaussian.joblib`, `protocol.json`, `metrics.json`, `predictions.csv` và ba split. Nếu test chỉ có BENIGN, FNR là `null`, không được coi là 0 hoặc dùng để kết luận phát hiện tấn công. Host corpus hiện tại có phân bố thời gian rất lệch, nên cần lab hỗn hợp độc lập để đánh giá có ý nghĩa.

## 4. Đồ thị giao tiếp và ứng viên cấu trúc botnet

```powershell
.\.venv\Scripts\python.exe src/botnet_graph.py --edges experiments/insdn-hosts-new/edges.csv --out experiments/insdn-graph-new --min-peers 5
```

Đầu ra gồm GraphML đầy đủ có hướng, SVG tổng quan tối đa 40 host, thống kê theo cửa sổ và danh sách ứng viên fan-in/fan-out. Các endpoint được nối theo phía gửi đầu tiên quan sát được của flow hai chiều; không chứng minh đó là phía tấn công.

GraphML/CSV giữ đầy đủ dữ liệu; SVG là góc nhìn giới hạn và gộp thời gian/hướng. DNS/web server hợp pháp, máy scan và hạ tầng botnet có thể cùng tạo hub. Module này tạo bằng chứng cấu trúc để điều tra, chưa phải bộ phân loại botnet đã được xác nhận. Muốn đo Precision/Recall botnet cần capture có nhãn infected/C2 độc lập; InSDN local không có nhãn botnet như vậy.

## 5. Kiểm tra feature parity

Trích cùng một PCAP bằng hai extractor, chuyển metadata hai CSV về schema chuẩn: 12 cột trong `features.py` và `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `flow_first_epoch` (epoch giây). Ghi rõ phiên bản extractor, timeout, chiều flow và đơn vị byte/duration. Không suy đoán đơn vị từ tên cột.

```powershell
.\.venv\Scripts\python.exe src/feature_parity.py --reference captures/reference-normalized.csv --candidate captures/scapy-normalized.csv --out experiments/parity-run01.json
```

Chương trình ghép theo endpoint/protocol/timestamp gói đầu đến microsecond, đếm flow không ghép được và sai khác từng feature. Không ghép được cũng là kiểm tra không đạt; không coi số flow unmatched là đúng. Một capture khớp chưa chứng minh tính tương đương tổng quát. Chưa có cặp capture thật được kiểm tra trong phiên này.

## 6. Lab Kali cần đo thực tế

Thực hiện trên mạng lab riêng: traffic bình thường, port scan và nếu có máy gửi Linux thì tải SYN giới hạn. Các lệnh chi tiết nằm trong `KALI_LAB.md`; không dùng ICMP/ping flood vì extractor hiện hỗ trợ IPv4 TCP/UDP.

Lưu PCAP, ground truth độc lập và log detector của cùng phiên. Dùng `evaluate_lab.py` để tính FPR/FNR, p50/p95 suy luận và thời gian gói đầu đến kết quả; ghi cả flow không ghép, queue drops và capacity evictions. Kiểm thử PCAP tổng hợp chỉ là kiểm tra chức năng, không thay số đo trên VM thật.

## 7. Bằng chứng đã chạy

Xem `CURRENT_RESULTS.md`. Các benchmark mới nằm ở `experiments/completion-20261110/`; kết quả cũ được giữ nguyên. Các kết luận về live hoặc botnet vẫn cần bằng chứng ở mục 4–6.

## 8. Beaconing, đánh giá model đã lưu và ablation

Đã có `beaconing.py` phân tích interval/CV theo cặp endpoint/protocol trên flow chưa lấy mẫu. `evaluate_model.py` tính metrics bằng nhãn thật, khác với kiểm tra ExpectedPrediction. `size_ablation.py` giữ cùng class/partition budget giữa nguồn đơn và hỗn hợp, dùng nguyên test đã lưu. Xem lệnh, quy tắc và giới hạn trong [WINDOWS_VALIDATION.md](WINDOWS_VALIDATION.md).

Live capture hỗ trợ `--capture-filter` để thu hẹp BPF trong phạm vi IPv4 TCP/UDP; dùng cùng scope với recorder. Capture Windows trong phiên này bị driver Admin-only Mode từ chối; chưa có kết quả live thay thế cho lab Kali.
