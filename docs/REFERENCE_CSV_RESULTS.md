# Huấn luyện lại Ensemble Stacking ngày 12/11/2026

Lượt đa lớp dùng đúng hai thư mục `data/cic-reference/GeneratedLabelledFlows/TrafficLabelling` và `data/insdn-reference/mohdadilz-insdn-dataset/InSDN_DatasetCSV`. Mã băm SHA-256 của 11 CSV nằm trong [input-sha256.json](../experiments/reference-csv-20261112/input-sha256.json).

| Nguồn | Tệp CSV | Flow có nhãn | Dòng nhãn trống bị loại | Nhãn gốc |
|---|---:|---:|---:|---:|
| CIC-IDS2017 TrafficLabelling | 8 | 2.830.743 | 288.602 | 15 |
| InSDN đầy đủ | 3 | 343.889 | 0 | 8 |

EDA quét toàn bộ CSV để đếm nhãn và dữ liệu thiếu. Biểu đồ đặc trưng và tương quan dùng mẫu giới hạn theo lớp. Không có giá trị thiếu hoặc vô hạn ở 12 đặc trưng của các dòng có nhãn. OVS bổ sung 138.722 flow cho InSDN, gồm 192 `Web-Attack` và 164 `BOTNET`. `HEARTBLEED` có 11 flow và bị loại bởi điều kiện tối thiểu 15 mẫu sau xử lý. M3 đánh giá chín nhóm nhãn. [EDA CIC](../experiments/reference-csv-20261112/eda/cic/eda.json) · [EDA InSDN](../experiments/reference-csv-20261112/eda/insdn/eda.json) · [Ánh xạ nhãn](../experiments/reference-csv-20261112/seed42/label_mapping.csv).

## Thiết kế và chọn tham số

- M1 fit CIC, M2 fit InSDN, M3 fit hợp hai tập development. M1/M3 dùng chung test CIC và M2/M3 dùng chung test InSDN. Test gộp của M3 là hợp hai test.
- Dùng 12 đặc trưng flow, giới hạn 2.000 dòng mỗi nhóm mỗi nguồn trước khử trùng. Chuẩn hóa tên cột, ánh xạ nhãn theo nguồn và loại vector trùng hoặc mâu thuẫn trước split. Mỗi nguồn chia ngẫu nhiên phân tầng 60/20/20. Cách chia này chưa tách phiên mạng hoặc thời gian thu thập.
- Baseline DT, RF, XGBoost, LightGBM, Logistic Regression chọn tham số bằng CV 3 fold trên train. M3 dùng xác suất ngoài fold từ RF, XGBoost và LightGBM để huấn luyện Logistic Regression ở tầng meta. Chọn `C ∈ {0.1, 1, 10}` và trọng số lớp theo Macro-F1 validation. Mọi mô hình refit trên train + validation trước khi chấm test. Chi tiết tham số và điểm ứng viên ở `selection.json` của từng mô hình.
- Seed 7, 21, 42 đã cố định. Cấu hình M3 được chọn theo thứ tự lần lượt là `trees_C10_balanced`, `trees_C10_unweighted`, `trees_C1_unweighted`.

## Kết quả đa lớp

Macro-F1 tính theo các lớp có ground truth trên từng test. Baseline tốt nhất trong bảng là thuật toán có Macro-F1 trung bình cao nhất trên cùng ba seed.

| Cấu hình | Test | ES Macro-F1 trung bình ± SD | Baseline tốt nhất | Macro-F1 baseline trung bình | Chênh lệch ES |
|---|---|---:|---|---:|---:|
| M1 | CIC | 0,963380 ± 0,002780 | XGBoost | 0,961828 | +0,001552 |
| M2 | InSDN | 0,945620 ± 0,023262 | RF | 0,950456 | −0,004836 |
| M3 | CIC | 0,962252 ± 0,008056 | XGBoost | 0,961977 | +0,000275 |
| M3 | InSDN | 0,934357 ± 0,039213 | RF | 0,950526 | −0,016168 |
| M3 | Gộp | 0,940095 ± 0,046247 | XGBoost | 0,957718 | −0,017622 |

Tiêu chí ES cao hơn baseline trên cùng dữ liệu được quan sát trên test CIC. Mức hơn trung bình của M3 nhỏ và ES thắng baseline tốt nhất của từng seed ở hai trong ba lượt. Trên test gộp, riêng seed 42 có ES **0,969323** so với XGBoost **0,965448**. Báo cáo cả ba seed để thể hiện độ biến thiên.

M3 seed 42 trên test gộp có 3.827 flow. Accuracy **97,47%**, Precision và Recall macro lần lượt **96,79%** và **97,09%**. Nếu quy dự đoán đa lớp về BENIGN/ATTACK, FPR **1,26%** và Recall ATTACK **99,51%**. Các chỉ số này đo trên test CSV đã lấy mẫu. Lớp `WEB_ATTACK` có F1 **0,839650** trên 167 flow. `U2R` đạt 3/3 flow test, với support quá nhỏ để suy rộng. [Kết quả mọi seed](../experiments/reference-csv-20261112/summary/all_seeds.csv) · [Mean/SD đầy đủ](../experiments/reference-csv-20261112/summary/mean_std.csv) · [Precision/Recall/F1 từng lớp](../experiments/reference-csv-20261112/seed42/M3/combined/report_stacking.json) · [Confusion matrix](../experiments/reference-csv-20261112/seed42/M3/combined/confusion_stacking.csv).

## Gaussian, replay và gói mô hình

Gaussian một thành phần được fit riêng cho từng nguồn trên BENIGN train seed 42. Ngưỡng lấy từ BENIGN validation với FPR mục tiêu 1%. Nhãn test được quy về BENIGN/ATTACK trên cùng split.

| Test | FPR Gaussian | Recall ATTACK Gaussian |
|---|---:|---:|
| CIC | 0,00% | 4,34% |
| InSDN | 1,51% | 1,14% |

Recall thấp làm Gaussian thiếu cơ sở để dùng làm tầng lọc bắt buộc. [Gaussian CIC](../experiments/reference-csv-20261112/gaussian/cicids2017/metrics.json) · [Gaussian InSDN](../experiments/reference-csv-20261112/gaussian/insdn/metrics.json).

Replay B04 từ PCAP qua detector Scapy, dùng M3 seed 42 mới, ghép đủ 12 flow BENIGN và cả 12 bị dự đoán U2R. FPR của lượt replay này là 100%. Capture chỉ có BENIGN, nên chưa đo được Recall tấn công hoặc độ trễ live. Hai nguồn huấn luyện vẫn dùng đặc trưng CSV có sẵn. Việc đồng nhất trích xuất PCAP với Kali và nghiệm thu live còn cần kiểm chứng riêng. [Metrics replay B04](../experiments/reference-csv-20261112/replay/B04/metrics.json).

Gói [M3 seed 42 cho Kali](../deliverables/ids-vm-reference-csv-20261112-seed42.zip) chứa model chín lớp, taxonomy, protocol, mã runtime và hai test nguồn. Dự đoán nạp lại model khớp toàn bộ hai test nguồn và cả hai smoke test. 62 kiểm thử mã nguồn đã qua. Khi giải nén trên Kali, chọn thư mục đích mới vì tên thư mục bên trong ZIP trùng gói seed 42 trước.

## Tái lập

[Notebook huấn luyện kết hợp](../notebooks/training_combined.ipynb) mặc định hiển thị lượt đa lớp seed 42 này. Bật `DO_TRAIN` và chọn đường dẫn đầu ra mới để huấn luyện lại. Để tái lập đủ ba seed từ PowerShell ở thư mục repo, dùng:

```powershell
$cic = 'data/cic-reference/GeneratedLabelledFlows/TrafficLabelling'
$insdn = 'data/insdn-reference/mohdadilz-insdn-dataset/InSDN_DatasetCSV'
$run = 'experiments/reference-csv-rerun'
foreach ($seed in 7, 21, 42) {
    .\.venv\Scripts\python.exe src/train_all.py --cic-data $cic --insdn-data $insdn --combined --multiclass --out "$run/seed$seed" --max-per-class 2000 --trees 60 --folds 3 --seed $seed --tune --stack-search
    if ($LASTEXITCODE -ne 0) { throw "Training failed for seed $seed" }
}
.\.venv\Scripts\python.exe src/summarize.py --runs "$run/seed7" "$run/seed21" "$run/seed42" --out "$run/summary"
```
