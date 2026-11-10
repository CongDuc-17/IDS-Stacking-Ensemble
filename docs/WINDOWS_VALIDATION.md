# Kiểm chứng trên Windows và các thí nghiệm bổ sung

Cập nhật 10/11/2026. Chạy từ thư mục gốc dự án. Giữ mỗi `--out` mới; không dùng lại kết quả test để chọn seed/tham số rồi gọi đó là xác nhận độc lập.

## 1. Đo Accuracy bằng nhãn thật

`check_model.py` so với ExpectedPrediction để kiểm tra tái lập. `evaluate_model.py` so với Label/GroundTruth để tính Accuracy, Macro-F1, Precision/Recall ATTACK, FPR/FNR và confusion matrix. Không train lại. Tool từ chối dùng ExpectedPrediction làm nhãn thật, từ chối nhãn UNKNOWN/thiếu và ghi hash model/CSV vào protocol.

```powershell
$model = 'experiments/completion-20261110/three-models-seed42/M3/models/stacking_ids.joblib'
.\.venv\Scripts\python.exe src/evaluate_model.py --model $model --csv experiments/completion-20261110/three-models-seed42/splits/cicids2017/test.csv --out experiments/windows-cic-check-new
.\.venv\Scripts\python.exe src/evaluate_model.py --model $model --csv experiments/completion-20261110/three-models-seed42/splits/insdn/test.csv --out experiments/windows-insdn-check-new
```

Đầu ra: `metrics.json`, `report_stacking.json`, `confusion_stacking.csv`, `predictions.csv`, `errors.csv`, `protocol.json`. Errors giữ feature và nhãn để phân tích mẫu sai. Nếu dùng smoke CSV có GroundTruth thì thêm `--label-column GroundTruth`; đó chỉ là đánh giá trên mẫu smoke, chưa phải toàn bộ test.

Model nhị phân chuyển subtype đã xác minh thành ATTACK. Model đa lớp chỉ chấp nhận các nhãn nó đã học. Một CSV đưa vào tool chưa tự chứng minh độc lập với train; dùng test đã xuất và đối chiếu protocol nguồn.

Đã chạy lại toàn bộ hai test của M3 seed 42; kết quả khớp metrics gốc. CIC có 13 dự đoán sai/1882 flow, InSDN có 1/1485. Các artifact nằm trong `experiments/completion-20261110/windows-evaluation-m3-*`.

## 2. So sánh với cùng cỡ mẫu

M3 ban đầu học nhiều hàng hơn M1/M2. `size_ablation.py` đọc các split đã lưu, xác minh hash feature, số lượng nhãn và tính không trùng; không chia lại test. Mỗi seed tạo ba cấu hình:

| Cấu hình | Thành phần mỗi lớp trong train/validation |
|---|---|
| CIC_matched | 100% CIC |
| InSDN_matched | 100% InSDN |
| Mixed_matched | 50% CIC + 50% InSDN |

Mỗi lớp và mỗi partition có cùng số hàng giữa ba cấu hình. Budget là số chẵn lớn nhất không vượt số hàng sẵn có nhỏ nhất của hai nguồn. Vì vậy giữ được cùng quy mô và cùng class prior. Số hàng theo seed vẫn khác nhau do sampling/cleanup ban đầu.

```powershell
.\.venv\Scripts\python.exe src/size_ablation.py --runs experiments/completion-20261110/three-models-seed7 experiments/completion-20261110/three-models-seed21 experiments/completion-20261110/three-models-seed42 --out experiments/size-ablation-new
```

Mỗi cấu hình chạy năm baseline và Stacking, chọn bằng CV/validation theo cùng quy tắc cũ, rồi đánh giá trên cả Test CIC, Test InSDN và test gộp. Có 54 hàng/seed, 162 hàng/ba seed; lưu model, train/validation đã lấy mẫu, protocol, kết quả từng seed và mean/SD.

Đây là phân tích bổ sung trên các test đã được xem trước, không phải test xác nhận mới. Mixed đã thấy cả hai miền trong train. Kết quả tốt trên test gộp chưa chứng minh tổng quát sang một miền chưa thấy, cũng chưa chứng minh extractor của hai dataset tương đương.

## 3. Phân tích beaconing offline

```powershell
.\.venv\Scripts\python.exe src/beaconing.py --csv "data/InSDN(2020)/InSDN_Normal_and_Attack_Combined.csv" --out experiments/beaconing-insdn-new --timestamp-format "%d/%m/%Y %H:%M|%d/%m/%Y %I:%M:%S %p" --drop-invalid-time
```

Hoặc dùng CSV từ `extract.py`, khi đó không cần `--timestamp-format`. Phải dùng flow chưa lấy mẫu, vì sampling sẽ làm mất các khoảng kết nối.

Nhóm theo IP nguồn, IP đích, cổng đích và protocol TCP/UDP; sắp xếp timestamp bắt đầu và khử các timestamp trùng có thống kê. Tính các khoảng thời gian, trung bình, sample SD và CV = SD/mean. Cấu hình mặc định chọn ứng viên khi có ít nhất 6 thời điểm khác nhau, khoảng quan sát ít nhất 60 giây, mean interval ít nhất 1 giây và CV không quá 0,1. Các ngưỡng này được đặt trước, chưa được hiệu chỉnh như một bộ phân loại C2.

Đầu ra: `pairs.csv`, `candidates.csv`, `summary.json`. Những protocol ngoài TCP/UDP bị loại có thống kê; chương trình không đoán protocol 0 là một giao thức cụ thể. Metadata thời gian kế thừa giả định ngày/tháng/năm đã khai báo; dữ liệu nhiều timestamp chỉ chính xác đến phút nên cần thận trọng.

Thực nghiệm local giữ 131744 flow, loại 73415 hàng protocol 0 và 8 flow thời lượng âm; có 37443 nhóm và 3 ứng viên chu kỳ 120 giây. Đối chiếu CSV nguồn, các flow của cả ba ứng viên đều mang nhãn Normal. Đây là ví dụ cho thấy hành vi định kỳ có thể hợp pháp; không gán ba IP đích thành C2 hoặc báo Recall botnet từ số này.

Đây là heuristic trên toàn capture; chưa có cửa sổ trượt/live hay khả năng chịu jitter đã được đánh giá. Flow timeout, keep-alive, polling và timestamp thô có thể tạo chu kỳ giả. Phân tích timing/size được dùng trong [RITA của Active Countermeasures](https://activecm.github.io/threat-hunting-labs/beacons/); module hiện tại chỉ thực hiện heuristic CV đơn giản, không tái hiện toàn bộ scoring của RITA.

## 4. Capture live Windows

Lần agent thử loopback bị driver từ chối vì **Admin-only Mode**, giữ trạng thái lịch sử trong `experiments/completion-20261110/windows-localhost-benign/protocol.json`. Sau đó người dùng chạy PowerShell Administrator và đã capture HTTP localhost thành công, có log BENIGN. Snapshot ở `experiments/completion-20261110/windows-user-benign-observed/`; chưa có bộ PCAP/ground truth/metrics attack lab hoàn chỉnh.

Để tự chạy, mở PowerShell **Run as administrator**, vào project rồi xem interface:

```powershell
Set-Location 'D:\Downloads\network-stacking-ids-20261107\network-stacking-ids'
.\.venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"
```

Ví dụ chỉ bắt loopback và cổng demo; dùng `--out` mới nếu file predictions.jsonl đã có:

```powershell
.\.venv\Scripts\python.exe src/detect.py --model experiments/completion-20261110/three-models-seed42/M3/models/stacking_ids.joblib --iface '\Device\NPF_Loopback' --capture-filter 'host 127.0.0.1 and tcp port 8080' --out logs/windows-benign-new --idle 10 --max-age 60
```

Từ terminal thường khác, mở HTTP server trong thư mục trống chỉ chứa file demo công khai:

```powershell
New-Item -ItemType Directory -Force -Path "$env:TEMP\ids-demo-www" | Out-Null
'IDS benign demo' | Set-Content "$env:TEMP\ids-demo-www\index.html"
python -m http.server 8080 --bind 127.0.0.1 --directory "$env:TEMP\ids-demo-www"
```

Gửi `curl.exe http://127.0.0.1:8080/` từ terminal khác, chờ hơn 10 giây, rồi xem log. Dừng server và detector bằng Ctrl+C. HTTP hợp pháp bị dự đoán ATTACK phải ghi là false positive. Cần thêm PCAP, nhãn độc lập và attack lab mới tính được Recall/FNR; kết quả BENIGN-only không đủ.

`--capture-filter` là BPF bổ sung trong phạm vi IPv4 TCP/UDP. Dùng cùng filter ở recorder và detector khi đối chiếu. Không tự đổi cấu hình Npcap hoặc cấp quyền hệ thống trong lần chuẩn bị này.

## 5. Việc vẫn cần bằng chứng mới

- Cùng PCAP thật qua CICFlowMeter và extractor triển khai để kiểm tra parity.
- Phiên BENIGN/ATTACK độc lập để đo FPR/FNR, latency, drops, CPU/RAM và khả năng xử lý.
- Kali VM thật; thí nghiệm Windows không thay kết quả trên Kali.
- Holdout có phân bố tự nhiên và tách phiên/thời gian; test Gaussian host hiện chưa có attack.
- Chốt và xuất bản Word cuối theo kết quả hiện hành. Không chuyển các mục trên thành “đã hoàn thành” khi chưa có artifact.
