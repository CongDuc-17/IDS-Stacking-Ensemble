# Phát hiện tấn công mạng bằng Ensemble Stacking

Pipeline huấn luyện **M1 trên CIC-IDS2017**, **M2 trên InSDN** và **M3 trên cả hai bộ**: đọc dữ liệu, EDA, baseline, Stacking OOF và đánh giá bằng các tập test giữ riêng. PR3 chạy lại M1/M2 cùng M3 trên một protocol chung để so sánh đúng các hàng test.

Xem [hướng dẫn M1/M2/M3](docs/THREE_MODELS.md) và [những phần cần hoàn thiện cho đề tài/báo cáo](docs/COMPLETION_REVIEW.md).

Ngày 10/11/2026 đã bổ sung test gộp, host features, Gaussian anomaly và đồ thị giao tiếp; đã chạy EDA, ba seed M1/M2/M3 và đa lớp hai nguồn. Kết quả thật nằm trong [CURRENT_RESULTS.md](docs/CURRENT_RESULTS.md); hướng dẫn nhánh mở rộng ở [EXTENSIONS.md](docs/EXTENSIONS.md). Chưa có kết quả đo lab Kali thật hoặc xác nhận botnet bằng ground truth.

[REPORT.md](docs/REPORT.md) cung cấp bản nội dung Chương 1–3, kết luận và nguồn tham khảo để đưa vào mẫu Word. Các bảng số liệu chi tiết nằm trong CURRENT_RESULTS.md.

Đưa model đã huấn luyện lên Kali VM: [hướng dẫn triển khai từng bước](docs/VM_DEPLOYMENT.md), từ mạng Host-only, chuyển gói M3, cài môi trường đến kiểm tra CSV và bắt traffic live.

[Kiểm chứng trên Windows](docs/WINDOWS_VALIDATION.md) có lệnh đánh giá bằng nhãn thật, phân tích beaconing và so sánh dữ liệu gộp với cùng cỡ mẫu. Người dùng đã capture HTTP localhost thành công bằng Administrator; lần agent trước đó bị Admin-only Mode từ chối vẫn được giữ như lịch sử, chưa có attack lab hoặc kết quả Kali thật.

[STACKING_SCOPE.md](docs/STACKING_SCOPE.md) chốt phần ES chính và các nhánh mở rộng. Đã chạy meta-search đa lớp đủ ba seed trên cả hai nguồn; ES chưa vượt baseline. [notebooks/training.ipynb](notebooks/training.ipynb) hỗ trợ huấn luyện theo bước, mặc định chỉ đọc artifact; hướng dẫn demo gọi tên subtype ở [MULTICLASS_DEMO.md](docs/MULTICLASS_DEMO.md).

## Xem theo cell trong notebook

Notebook huấn luyện kết hợp: [notebooks/training_combined.ipynb](notebooks/training_combined.ipynb). Chạy M1/M2/M3 bằng pipeline chung, xác minh dữ liệu gộp và test chung; DO_TRAIN mặc định False để xem kết quả, đổi True và OUT mới để huấn luyện thật. Bài toán kết hợp hiện là BENIGN/ATTACK.

Mở [notebooks/experiment.ipynb](notebooks/experiment.ipynb) để xem bảng, biểu đồ EDA, mean/SD, confusion matrix, đa lớp, Gaussian và graph. Notebook đọc artifact đã lưu; Run All không tự huấn luyện lại. Logic train vẫn dùng chung trong `src/*.py`.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-notebook.in
```

Trong VS Code, mở notebook rồi chọn kernel Python của `.venv`. Chạy cell đầu đến cuối và Save để lưu output; có thể mở lại xem các bảng/ảnh đã lưu mà không cần train lại. Biến `RUN` chọn thư mục kết quả; muốn đọc lượt mới thì đổi `RUN`, Restart Kernel rồi Run All. Khi chạy lại cần các artifact tương ứng trong `experiments/`; output đã lưu là snapshot, không tự cập nhật theo file nguồn.

## Cài đặt

Chạy PowerShell từ thư mục chứa README. Máy hiện có Python 3.14.6; các lệnh dùng `python` và gọi trực tiếp Python trong venv.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.in
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_training.py -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_three_models.py -v
```

Để dùng PCAP/live và chạy toàn bộ test (gồm Scapy):

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lab.in
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Không cần activate venv. Bộ test CIC/InSDN độc lập với các module bắt gói tin. Các classifier nhỏ trong test chỉ kiểm tra logic chọn mô hình, OOF, refit và xuất file; điểm fixture không dùng làm kết quả thực nghiệm.

## Dữ liệu

| Dataset | Đường dẫn hiện tại | Nội dung |
|---|---|---|
| CIC-IDS2017 | `data/MachineLearningCVE/` | Tám CSV MachineLearningCVE |
| InSDN | `data/InSDN(2020)/` | `InSDN_Normal_and_Attack_Combined.csv` |

Dữ liệu được đọc theo chunk và chỉ lấy 12 đặc trưng khai báo trong `src/features.py`; `Label` là mục tiêu, không phải đầu vào mô hình. Tên cột được bỏ khoảng trắng/BOM rồi ánh xạ và kiểm tra. Cột thiếu hoặc hai cột cùng ánh xạ vào một feature bị từ chối. IP, Flow ID và timestamp không được đưa vào mô hình.

Ánh xạ schema InSDN sang hợp đồng feature chung:

| Cột InSDN | Feature chung |
|---|---|
| `Dst Port` | `Destination Port` |
| `Flow Duration` | `Flow Duration` |
| `Tot Fwd Pkts` | `Total Fwd Packets` |
| `Tot Bwd Pkts` | `Total Backward Packets` |
| `TotLen Fwd Pkts` | `Total Length of Fwd Packets` |
| `TotLen Bwd Pkts` | `Total Length of Bwd Packets` |
| `FIN Flag Cnt` | `FIN Flag Count` |
| `SYN Flag Cnt` | `SYN Flag Count` |
| `RST Flag Cnt` | `RST Flag Count` |
| `PSH Flag Cnt` | `PSH Flag Count` |
| `ACK Flag Cnt` | `ACK Flag Count` |
| `URG Flag Cnt` | `URG Flag Count` |

Truyền đúng thư mục riêng vào `--data`; tránh `--data data` khi thư mục đó chứa cả hai bộ. Huấn luyện kết hợp dùng `train_all.py` với hai đường dẫn riêng.

Không đưa CSV gốc, model, log hoặc môi trường Python vào Git. `.gitignore` đã loại `data/`, `models/`, `experiments/` và `.venv/`.

## EDA

```powershell
.\.venv\Scripts\python.exe src/eda.py --data data/MachineLearningCVE --out experiments/eda-cicids2017 --max-per-class 2000
.\.venv\Scripts\python.exe src/eda.py --data "data/InSDN(2020)" --out experiments/eda-insdn --max-per-class 2000
```

`eda.json` chứa số lượng nhãn gốc và missing/nonfinite trên toàn bộ CSV. Biểu đồ phân bố đặc trưng và tương quan dùng mẫu giới hạn RAM. EDA giữ tên loại tấn công gốc, chuẩn hóa nhãn bình thường `Normal` thành `BENIGN` trong mẫu; đếm nhãn thô vẫn giữ tên gốc.

## Huấn luyện M1 nhị phân

```powershell
.\.venv\Scripts\python.exe src/train.py --data data/MachineLearningCVE --dataset CIC-IDS2017 --binary --out experiments/m1-cicids2017-seed42 --max-per-class 5000 --trees 120 --folds 3 --seed 42 --tune
```

## Huấn luyện M2 nhị phân

```powershell
.\.venv\Scripts\python.exe src/train.py --data "data/InSDN(2020)" --dataset InSDN --binary --out experiments/m2-insdn-seed42 --max-per-class 5000 --trees 120 --folds 3 --seed 42 --tune
```

M1 và M2 dùng cùng thuật toán, feature, số cây, folds, seed và quy tắc chọn mô hình. Mỗi bộ được chia train/validation/test riêng; điểm của hai test khác nhau chưa chứng minh mô hình nào tốt hơn trên cùng miền dữ liệu.

## Huấn luyện M1/M2/M3 với test chung

```powershell
.\.venv\Scripts\python.exe src/train_all.py --combined --out experiments/three-models-seed42 --max-per-class 5000 --trees 120 --folds 3 --seed 42 --tune
```

| Cấu hình | Development data | Test |
|---|---|---|
| M1 | CIC | Test CIC |
| M2 | InSDN | Test InSDN |
| M3 | CIC + InSDN | Cùng Test CIC của M1, cùng Test InSDN của M2 và test gộp |

Khử trùng giữa hai nguồn trước khi chia tập. M3 được fit một lần rồi đánh giá trên ba test. `comparison_all.csv` có 30 hàng thuật toán/cấu hình/test; `comparison_stacking.csv` có năm hàng chỉ Stacking. Test gộp tính metrics trực tiếp trên các hàng test nối lại. `completed.json` chỉ xuất khi toàn lượt thành công. Mỗi `--out` phải mới hoặc trống. Các lượt cũ protocol v1 có 24 hàng được giữ nguyên, không tổng hợp lẫn với v2.

Không dùng các kết quả M1/M2 độc lập ở PR1/PR2 để so trực tiếp với M3 nếu hash test khác. Xem hướng dẫn chi tiết để chạy đủ seed 7/21/42 và tổng hợp mean/SD.

`--binary` chuyển `BENIGN`/`Normal` (không phân biệt hoa/thường) thành BENIGN và các nhãn hợp lệ còn lại thành ATTACK **trước** sampling/khử trùng. Nhãn trống bị loại. `--max-per-class` giới hạn mỗi nhãn nhị phân trước khử trùng, nên số hàng cuối có thể thấp hơn giới hạn. Số lượng từng nhãn gốc, gồm `Normal` của InSDN, vẫn được lưu trong `raw_class_counts` để truy nguồn.

Bỏ `--binary` để thực hiện thí nghiệm đa lớp riêng. Khi đó `Normal` được chuẩn hóa thành `BENIGN`, giữ tên các loại tấn công, và cap áp dụng theo lớp sau chuẩn hóa. Các lớp dưới 15 hàng sau cleanup bị loại, có ghi trong protocol. Không so trực tiếp điểm đa lớp với điểm nhị phân như cùng một bài toán.

Mỗi output phải dùng tên mới nếu đã có kết quả hoàn chỉnh. Có thể chọn `--test-data` là một CSV/thư mục holdout độc lập của cùng dataset; các vector train trùng holdout được loại trước chia train/validation. Tùy chọn này không tự tạo phép chia theo thời gian.

## Giao thức đánh giá

1. Chuẩn hóa numeric, thay Inf/giá trị không parse được bằng missing; loại hàng thiếu toàn bộ feature.
2. Lấy mẫu random-priority theo lớp, loại vector trùng và vector có nhãn mâu thuẫn trong mẫu.
3. Chia stratified random xấp xỉ 60% train, 20% validation, 20% test; kiểm tra không trùng vector giữa các phần.
4. Khi có `--tune`, chọn tham số DT, RF, XGBoost, LightGBM và Logistic Regression bằng CV trên train.
5. So hai stack OOF (RF/XGBoost/LightGBM và RF/XGBoost/LR) bằng Macro-F1 validation. Imputer/scaler nằm trong pipeline từng fold.
6. Refit các baseline và stack được chọn trên train + validation, rồi đánh giá một lần trên cùng tập test.

Lưu Accuracy, Macro-F1, Weighted-F1, Precision/Recall/F1 ATTACK, FPR, FNR, confusion matrix, thời gian refit và thời gian dự đoán batch. Các điểm là số thập phân 0–1. Không có bảo đảm Stacking sẽ vượt baseline; cần báo cáo đúng kết quả.

## Đầu ra mỗi lượt

| File | Nội dung |
|---|---|
| `protocol.json` | Tham số, nguồn dữ liệu, nhãn gốc, cleanup, số hàng và hash từng split, phiên bản Python |
| `selection.json` | Tham số và điểm chọn bằng train/validation |
| `comparison.csv/json` | Metrics của 5 baseline và Stacking |
| `report_*.json` | Báo cáo từng lớp và phát hiện BENIGN/ATTACK |
| `confusion_*.csv` | Ma trận nhầm lẫn có tên lớp |
| `predictions.csv` | Ground truth và dự đoán của mọi mô hình trên cùng test |
| `models/stacking_ids.joblib` | Model, thứ tự feature, nhãn và metadata |
| `models/requirements-deploy.txt` | Phiên bản thực tế của các thư viện mô hình |
| `smoke_test.csv` | Tối đa 100 hàng kèm dự đoán kỳ vọng để kiểm tra tái lập |

Chỉ load `.joblib` tự tạo hoặc từ nguồn đáng tin cậy. Khớp dự đoán kỳ vọng 100% chỉ xác nhận tái lập, không phải Accuracy 100%.

Kiểm tra lại model M3 đã lưu bằng CSV, không cần thư viện bắt gói tin:

```powershell
.\.venv\Scripts\python.exe src/check_model.py --model experiments/three-models-seed42/M3/models/stacking_ids.joblib --csv experiments/three-models-seed42/M3/cicids2017/smoke_test.csv
.\.venv\Scripts\python.exe src/check_model.py --model experiments/three-models-seed42/M3/models/stacking_ids.joblib --csv experiments/three-models-seed42/M3/insdn/smoke_test.csv
```

## Giới hạn

Class cap và khử trùng thay đổi phân bố nhãn. Random split chưa bảo đảm tách phiên/thời gian; điểm trên mẫu chưa đại diện cho traffic thực tế. Tuning trước OOF không phải nested CV đầy đủ. Cùng tên cột sau ánh xạ chưa chứng minh cùng ngữ nghĩa extractor giữa hai dataset. M3 có nhiều dữ liệu hơn M1/M2 và đã thấy cả hai miền trong train. Thời gian suy luận batch chưa phải độ trễ phát hiện live. Xem kết quả và giới hạn hiện hành trong `docs/CURRENT_RESULTS.md`.
