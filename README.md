# Phát hiện tấn công mạng bằng Ensemble Stacking

**PCAP-Combined-Refit** phân loại flow IPv4 TCP/UDP thành `BENIGN`, `RECON`, `DOS` và `BRUTE_FORCE`. Mô hình học từ các phiên PCAP của CIC-IDS2017 và InSDN. Tiền xử lý và detector dùng chung bộ gom flow Scapy `scapy-ip-payload-v2`.

| Nguồn | Phiên | Flow trích được | Flow có nhãn | Flow test |
|---|---:|---:|---:|---:|
| CIC-IDS2017 | 15 | 225.190 | 162.063 | 16.035 |
| InSDN | 16 | 111.120 | 80.618 | 10.440 |
| Tổng | 31 | 336.310 | 242.681 | 26.475 |

## Cài đặt trên Windows

Chạy PowerShell từ thư mục chứa README với Python **3.14.6**. Nếu đã có `.venv` của dự án, bắt đầu từ dòng khai báo `$py`.

```powershell
python -m venv .venv
$py = '.\.venv\Scripts\python.exe'
& $py -m pip install -r requirements-notebook.in
& $py -m unittest discover -s tests -v
```

Trong VS Code, chọn kernel Python của `.venv`, mở notebook rồi chọn **Run All**. Các notebook có sẵn output của lần kiểm tra. Mặc định các cell đọc đầu ra đã lưu. Bật biến ở đầu notebook để chạy lại bước tương ứng. Sau khi chạy lại, chuyển đường dẫn ở notebook kế tiếp sang thư mục mới nếu muốn xem đầu ra mới.

Nếu chỉ chạy CLI hoặc detector, cài bằng `& $py -m pip install -r requirements-tested.txt`.

| Notebook | Nội dung |
|---|---|
| [data_preparation.ipynb](notebooks/data_preparation.ipynb) | Mô tả nguồn, 31 phiên, 12 đặc trưng, điều kiện gán nhãn, EDA và kiểm tra tách tập |
| [training.ipynb](notebooks/training.ipynb) | Kiểm tra 20.307 flow dùng để fit, 23 fold OOF và cấu hình hai tầng. Có cell chạy lại train |
| [evaluation.ipynb](notebooks/evaluation.ipynb) | Đánh giá lại trên 26.475 flow, ma trận nhầm lẫn, kết quả từng lớp và smoke test |

## Dữ liệu và tiền xử lý

Đặt PCAP CIC-IDS2017 trong `data/cic-reference/` và PCAP InSDN trong `data/insdn-reference/pcap/`. Các tên tệp, cửa sổ UTC, điều kiện lọc và split nằm trong [kế hoạch phiên](configs/pcap_sessions_20261112.json). Một số phiên InSDN cần thêm CSV nhãn tham chiếu trong `data/insdn-reference/mohdadilz-insdn-dataset/InSDN_DatasetCSV/`. CSV tham chiếu cung cấp thông tin đối chiếu nhãn theo endpoint và thời gian. Các giá trị đầu vào của model đến từ PCAP.

[CIC-IDS2017 – UNB](https://www.unb.ca/cic/datasets/ids-2017.html) · [InSDN – bài báo bộ dữ liệu](https://doi.org/10.1109/ACCESS.2020.3022633)

```powershell
& $py src/pcap_experiments.py --out experiments/pcap-prepared-rerun
```

Lệnh trên đọc PCAP gốc. Dữ liệu CIC-IDS2017 gồm năm tệp lớn, mỗi cửa sổ đọc capture của ngày tương ứng. Nếu máy có sẵn CSV flow đã trích từ cùng phiên, thêm `--reuse-extracted` để chạy nhanh hơn. Kế hoạch phiên ghi đường dẫn cache cụ thể. Bước này xuất `label_audit.csv`, hai CSV có nhãn, `protocol.json` và sáu tệp dưới `splits/`.

1. [flows.py](src/flows.py) gom hai chiều theo IP, cổng và giao thức. Gói đầu xác định chiều đi. Độ dài IP/TCP/UDP xác định số byte payload để tránh đếm phần đệm Ethernet. Flow hết hạn sau 10 giây không có gói mới hoặc đạt tuổi tối đa 60 giây. Bộ gom giữ tối đa 10.000 flow mở.
2. [pcap_experiments.py](src/pcap_experiments.py) loại flow bị đóng do chạm giới hạn dung lượng và vector âm, thiếu hoặc vô hạn. Quy tắc phiên xét thời gian, endpoint, cổng và các điều kiện đã ghi trong kế hoạch. Với phiên có CSV tham chiếu, nhãn phải đồng nhất trên các bản ghi chồng lấp và có bản ghi cùng chiều bao phủ flow.
3. Nhãn nguồn được quy về bốn lớp. Test được giữ riêng theo phiên và ưu tiên khi loại vector trùng khỏi validation/train. Train loại vector mâu thuẫn nhãn, khử trùng rồi chia ngân sách tối đa 2.000 flow cho mỗi cặp nguồn–lớp giữa các phiên train. Bước này giữ đúng dữ liệu của lượt fit gốc.

## Huấn luyện và đánh giá

```powershell
& $py src/train.py --prepared experiments/pcap-prepared-rerun --out experiments/pcap-refit-rerun
```

`--prepared` có thể trỏ tới `experiments/pcap-scapy-20261112-seed42` nếu đã có sáu split gốc. Dùng thư mục `--out` mới cho mỗi lượt. Thư mục chứa `PCAP-Combined-Refit.joblib`, `REFIT_CARD.json`, report, confusion matrix, dự đoán và smoke CSV.

[train.py](src/train.py) gộp train và validation, lấy tối đa 2.000 flow mỗi phiên với seed 42 và giữ thứ tự dòng gốc trong từng phiên sau khi lấy mẫu. Kết quả gốc dùng 20.307 flow từ 23 phiên.

- Random Forest, XGBoost và LightGBM học xác suất ngoài fold (OOF). Mỗi fold giữ nguyên một phiên để mô hình tầng 1 dự đoán từ các phiên còn lại. Mỗi pipeline tầng 1 dùng median imputer.
- Logistic Regression nhận 12 xác suất OOF và 12 đặc trưng flow. Nhánh flow dùng `log1p` để nén thang đo lệch phải rồi dùng `StandardScaler` để cân bằng độ lớn. Nhánh xác suất đi thẳng vào Logistic Regression. Các mô hình tầng 1 phục vụ suy luận được fit trên toàn bộ tập phát triển.
- Random Forest dùng 60 cây. XGBoost và LightGBM dùng 60 vòng boosting. Logistic Regression dùng `C=0.1`, `max_iter=3000` và hội tụ sau 74 vòng trong lượt đã lưu.

| Tập test | Accuracy | Macro-F1 | FPR BENIGN | Recall ATTACK |
|---|---:|---:|---:|---:|
| CIC-IDS2017 | 93,73% | 69,59% | 3,13% | 92,73% |
| InSDN | 99,30% | 83,50% | 0,16% | 99,56% |
| Gộp | 95,92% | 86,04% | 1,95% | 95,42% |

Macro-F1 tính đều bốn lớp. FPR BENIGN là tỷ lệ flow bình thường bị gắn nhãn tấn công. Recall ATTACK là tỷ lệ flow tấn công được gắn vào một lớp tấn công. BRUTE_FORCE trên test gộp có F1 54,44% và 140 flow BENIGN bị gán nhầm sang lớp này.

Trên cùng 26.475 flow test gộp, Macro-F1 của ba base learner đã fit trong artifact lần lượt là 45,05% (Random Forest), 72,18% (XGBoost) và 72,05% (LightGBM). Notebook đánh giá tính lại bảng so sánh từ cùng artifact.

## Replay và live

Artifact gốc đặt trong `experiments/pcap-combined-refit-seed42/`. Khi dùng bản vừa fit, truyền `--model experiments/pcap-refit-rerun/PCAP-Combined-Refit.joblib`. Chỉ nạp file joblib từ nguồn tin cậy.

```powershell
& $py src/detect.py --pcap 'C:\captures\lab.pcapng' --out logs/replay-moi
& $py src/detect.py --list-ifaces
```

[Hướng dẫn Windows bắt gói và Kali gửi lưu lượng](docs/WINDOWS_LIVE.md) có lệnh chạy HTTP server, chọn adapter VMnet1, bắt gói, thử HTTP/quét cổng và chấm bằng PCAP ghi song song.

## Cấu trúc thư mục

| Thư mục | Chức năng |
|---|---|
| `src/` | Trích flow, gán nhãn, chuẩn bị dữ liệu, fit, detector và công cụ kiểm chứng |
| `configs/` | Kế hoạch dữ liệu của từng phiên |
| `notebooks/` | EDA, huấn luyện và đánh giá có giải thích theo cell |
| `tests/` | Kiểm thử flow, gán nhãn, OOF, suy luận và chấm lab |
| `data/` | PCAP và CSV tham chiếu cục bộ |
| `experiments/` | Các split, artifact và kết quả thử nghiệm cục bộ |
| `logs/`, `deliverables/` | Log suy luận và gói/báo cáo đã xuất |
| `docs/` | Hướng dẫn hiện hành và ghi chép thí nghiệm lịch sử |
