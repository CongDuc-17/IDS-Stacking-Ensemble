# Phát hiện tấn công mạng bằng Ensemble Stacking

Pipeline huấn luyện **M1 trên CIC-IDS2017** và **M2 trên InSDN**: đọc dữ liệu, EDA, baseline, Stacking OOF và đánh giá trên tập test giữ riêng của từng dataset. PR2 bổ sung InSDN trên pipeline chung của PR1; mỗi lượt vẫn chỉ huấn luyện một dataset.

## Cài đặt

Chạy PowerShell từ thư mục chứa README. Máy hiện có Python 3.14.6; các lệnh dùng `python` và gọi trực tiếp Python trong venv.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.in
.\.venv\Scripts\python.exe -m unittest discover -s tests -p test_training.py -v
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

Truyền đúng thư mục riêng vào `--data`; tránh `--data data` khi thư mục đó chứa cả hai bộ. Việc huấn luyện kết hợp thuộc PR3.

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

## Giới hạn

Class cap và khử trùng thay đổi phân bố nhãn. Random split chưa bảo đảm tách phiên/thời gian; điểm trên mẫu chưa đại diện cho traffic thực tế. Tuning trước OOF không phải nested CV đầy đủ. Cùng tên cột sau ánh xạ chưa chứng minh cùng ngữ nghĩa extractor giữa hai dataset. Thời gian suy luận batch chưa phải độ trễ phát hiện live. Phiên bổ sung PR2 chưa chạy huấn luyện booster thật.
