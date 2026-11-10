# Hướng dẫn thực nghiệm M1/M2/M3

Cập nhật 08/11/2026. Chạy từ thư mục `network-stacking-ids` chứa README.

## 1. Mục tiêu và nhãn

M1 học CIC-IDS2017, M2 học InSDN, M3 học development data của cả hai. Hai bộ có hệ nhãn tấn công khác nhau nên phép so sánh chung dùng **BENIGN/ATTACK**:

- `BENIGN`, `Normal` (không phân biệt hoa/thường) thành `BENIGN`.
- Các nhãn hợp lệ còn lại thành `ATTACK`; nhãn trống bị loại.
- Chuyển nhãn trước sampling/khử trùng để các subtype hiếm vẫn có cơ hội vào ATTACK.
- `raw_class_counts` trong protocol giữ số lượng nhãn gốc. Sampling nhị phân không bảo đảm giữ đủ từng subtype.

`src/train.py` vẫn phân loại đa lớp trên một dataset; không thay đổi ngầm mục tiêu các lượt cũ.

## 2. Chia tập và chống rò rỉ

1. Đọc riêng hai nguồn bằng chunk, ánh xạ cùng 12 feature và chuẩn hóa numeric. Lấy tối đa `--max-per-class` hàng mỗi nhãn nhị phân ở mỗi nguồn.
2. Trong mẫu, loại vector có nhãn nhị phân mâu thuẫn và vector trùng.
3. Khử trùng tiếp giữa hai nguồn trước mọi phép chia. Cùng vector và nhãn: giữ hàng CIC trước, sau đó InSDN. Khác nhãn: loại tất cả hàng liên quan. Protocol ghi số hàng trước/sau và chính sách này; ưu tiên nguồn có thể ảnh hưởng độ đại diện của InSDN.
4. Chia từng nguồn xấp xỉ 60% train, 20% validation, 20% test bằng stratified random split với seed cố định. Cả sáu phần của hai nguồn không được trùng vector đặc trưng.
5. M1 dùng train/validation CIC; M2 dùng train/validation InSDN; M3 nối hai train và nối hai validation. Các cấu hình dùng cùng số cây, folds và quy tắc chọn mô hình.
6. Có `--tune`: chọn tham số baseline bằng CV trên train. Chọn một trong hai stack bằng Macro-F1 validation. OOF tạo meta-feature; imputer/scaler nằm trong pipeline từng fold.
7. Refit trên development data rồi test. M3 fit một lần cho Test CIC, Test InSDN và test gộp (nối các hàng của hai test). M1/M3 dùng đúng các hàng Test CIC; M2/M3 dùng đúng các hàng Test InSDN. Hash từng test được lưu trong protocol.

M3 có nhiều dữ liệu hơn M1/M2; đây là so sánh tác động bổ sung dữ liệu, chưa kiểm soát cùng cỡ mẫu. Random split chưa loại hết tương quan phiên/thời gian. M3 đã thấy cả hai miền trong train nên chưa phải thử nghiệm miền chưa từng thấy. Cùng tên cột chưa chứng minh cùng ngữ nghĩa extractor.

## 3. Cài đặt và kiểm tra

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lab.in
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe src/train_all.py --help
```

Không cần activate venv hay đổi ExecutionPolicy. Nếu cài package lỗi, xử lý lỗi đó trước khi train. Test mới dùng classifier nhỏ thay booster để kiểm tra OOF/refit/xuất model và chia sẻ test. Kết quả fixture nằm trong thư mục tạm, không dùng cho báo cáo.

## 4. EDA

```powershell
.\.venv\Scripts\python.exe src/eda.py --data data/MachineLearningCVE --out experiments/eda-cicids2017-current --max-per-class 2000
.\.venv\Scripts\python.exe src/eda.py --data "data/InSDN(2020)" --out experiments/eda-insdn-current --max-per-class 2000
```

EDA giữ nhãn gốc nên cap là mỗi nhãn gốc. Đếm thô đọc toàn bộ CSV; biểu đồ feature/tương quan dùng mẫu. Số hàng mẫu EDA đa lớp khác mẫu train nhị phân.

## 5. Huấn luyện

Chọn protocol trước khi xem điểm test. Ví dụ lượt báo cáo seed 42:

```powershell
.\.venv\Scripts\python.exe src/train_all.py --combined --out experiments/three-models-seed42 --max-per-class 5000 --trees 120 --folds 3 --seed 42 --tune
```

Mặc định dữ liệu là `data/MachineLearningCVE` và `data/InSDN(2020)`. Nếu di chuyển, truyền `--cic-data` và `--insdn-data`. Bỏ `--combined` chỉ chạy M1/M2.

Muốn báo cáo nhiều seed, giữ tham số và chạy đủ seed định trước:

```powershell
foreach ($seed in 7, 21, 42) {
    .\.venv\Scripts\python.exe src/train_all.py --combined --out "experiments/three-models-seed$seed" --max-per-class 5000 --trees 120 --folds 3 --seed $seed --tune
    if ($LASTEXITCODE -ne 0) { throw "Training failed at seed $seed" }
}
```

Chọn lệnh đơn hoặc vòng lặp, tránh chạy lại seed 42 vào cùng output. Không loại seed điểm thấp. Sau khi chạy đủ ba seed, tổng hợp bằng:

```powershell
.\.venv\Scripts\python.exe src/summarize.py --runs experiments/three-models-seed7 experiments/three-models-seed21 experiments/three-models-seed42 --out experiments/three-models-summary
```

Tool tự nhận dạng luồng M1/M2/M3, từ chối lượt chưa hoàn tất, seed trùng hoặc khác protocol/nguồn file. `stacking_mean_std.csv` chứa mean ± sample SD theo từng cặp cấu hình/test; không trộn hai test thành một điểm. SD giữa ba seed chưa phải khoảng tin cậy cho traffic thực tế.

## 6. Đầu ra dưới `--out`

| Đường dẫn | Nội dung |
|---|---|
| `protocol.json` | Nguồn CSV, đếm nhãn gốc, sampling, cleanup, số hàng và hash split |
| `splits/cicids2017/`, `splits/insdn/` | `train.csv`, `validation.csv`, `test.csv`, có cột nguồn |
| `M1/models/stacking_ids.joblib` | Model CIC |
| `M2/models/stacking_ids.joblib` | Model InSDN |
| `M3/models/stacking_ids.joblib` | Một model kết hợp cho ba test |
| `M*/models/requirements-deploy.txt` | Phiên bản thư viện thực tế của lượt train |
| `M*/selection.json`, `M*/protocol.json` | Điểm chọn mô hình, tham số, hash test |
| `M1/cicids2017/`, `M2/insdn/` | Reports, confusion matrix, predictions, smoke test |
| `M3/cicids2017/`, `M3/insdn/`, `M3/combined/` | Ba nhóm đánh giá cùng model M3 |
| `comparison_all.csv` | 30 hàng khi chạy đủ: 6 thuật toán × 5 cặp cấu hình/test |
| `comparison_stacking.csv` | 5 hàng Stacking: M1/CIC, M2/InSDN, M3/CIC, M3/InSDN, M3/gộp |
| `completed.json` | Chỉ xuất khi toàn bộ cấu hình thành công |

Metrics gồm Accuracy, Macro-F1, Weighted-F1, Precision/Recall/F1 ATTACK, FPR, FNR, thời gian refit và dự đoán batch. Các điểm nằm trong 0–1; nhân 100 khi trình bày %. `fit_seconds_final_refit` không gồm tuning/chọn stack; thời gian đầy đủ mỗi cấu hình có trong protocol. Thời gian batch chưa phải độ trễ live.

Nếu lỗi ở cấu hình sau, kết quả cấu hình hoàn tất được giữ, kể cả `comparison_all.csv`. Không có `completed.json` nghĩa là chưa xong toàn lượt. Chọn output mới khi chạy lại.

## 7. Smoke test model mới

```powershell
.\.venv\Scripts\python.exe src/check_model.py --model experiments/three-models-seed42/M3/models/stacking_ids.joblib --csv experiments/three-models-seed42/M3/cicids2017/smoke_test.csv
.\.venv\Scripts\python.exe src/check_model.py --model experiments/three-models-seed42/M3/models/stacking_ids.joblib --csv experiments/three-models-seed42/M3/insdn/smoke_test.csv
```

Mỗi lệnh cần `Prediction match: 100.00%`: tái lập dự đoán, không phải Accuracy 100%. Chuyển Kali phải dùng đúng Python và requirements-deploy của model mới.

## 8. Trạng thái hiện hành

Ngày 10/11/2026 đã chạy đủ seed 7/21/42 theo protocol v2 có test gộp, cùng EDA và các nhánh bổ sung. Xem [kết quả thật](CURRENT_RESULTS.md), [Gaussian/host/graph/parity](EXTENSIONS.md) và [đối chiếu yêu cầu](COMPLETION_REVIEW.md). Các lượt mới ở `experiments/completion-20261110/`; các lượt 24 hàng cũ là protocol v1 và không được tổng hợp lẫn v2.

Toàn bộ bộ test hiện có 48 test, gồm cả meta-search OOF. Chưa có số đo trên VM Kali thật. Smoke test CSV kiểm tra tái lập; không xác nhận feature parity hoặc độ chính xác live. Xem WINDOWS_VALIDATION.md để đánh giá artifact và ablation; STACKING_SCOPE.md mô tả --stack-search cùng thí nghiệm đa lớp riêng.
