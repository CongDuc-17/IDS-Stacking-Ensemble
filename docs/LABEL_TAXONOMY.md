# Ánh xạ nhãn đa lớp CIC-IDS2017 + InSDN

Đây là **taxonomy nhóm tấn công do đề tài thiết kế**, phiên bản `cic-insdn-families-v1`; không phải bảng nhãn chung được hai tác giả công bố. Bảng được cố định trước lượt huấn luyện kết hợp, dựa trên mô tả kịch bản gốc và kiểm tra toàn bộ nhãn trong CSV tại máy. Chưa có kiểm định độc lập hoặc gán lại nhãn từng PCAP.

## Bảng ánh xạ

| Nhóm đích | Nhãn CIC-IDS2017 | Nhãn InSDN | Căn cứ và quyết định |
|---|---|---|---|
| BENIGN | BENIGN | Normal | Traffic bình thường |
| DOS | DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye | DoS | Từ chối dịch vụ; giữ khác DDOS |
| DDOS | DDoS | DDoS | Từ chối dịch vụ phân tán |
| RECON | PortScan | Probe | Nhóm dò quét; Probe có phạm vi rộng hơn quét cổng |
| BRUTE_FORCE | FTP-Patator, SSH-Patator, Web Attack - Brute Force | BFA | Nhóm theo cơ chế đoán mật khẩu; web brute force vào đây thay vì WEB_ATTACK |
| WEB_ATTACK | Web Attack - XSS, Web Attack - Sql Injection | Web-Attack | XSS/SQL injection; tách brute force theo quy ước trên |
| BOT | Bot | BOTNET | Nhãn traffic bot từ dataset; không chứng minh topology botnet |
| INFILTRATION | Infiltration | — | Giữ riêng kịch bản CIC |
| HEARTBLEED | Heartbleed | — | Giữ riêng khai thác Heartbleed, không đổi thành DOS |
| U2R | — | U2R | Giữ nguyên nhãn nguồn; không đồng nhất với Infiltration hoặc Heartbleed |

Nguồn chính:

1. [Trang CIC-IDS2017 của UNB](https://www.unb.ca/cic/datasets/ids-2017.html): lịch kịch bản FTP/SSH brute force, bốn DoS, web brute force/XSS/SQL injection, Heartbleed, Infiltration, ARES và port scan. Việc gộp theo nhóm trong bảng là lựa chọn của đề tài.
2. Elsayed, Le-Khac, Jurcut, [InSDN: A Novel SDN Intrusion Dataset, IEEE Access 2020](https://doi.org/10.1109/ACCESS.2020.3022633), [bản tác giả tại UCD](https://researchrepository.ucd.ie/bitstreams/f0050518-5407-4b43-81d8-2607e9c8dab4/download): Table 4 mô tả DoS, DDoS, XSS/SQL injection, password guessing, ARES, Probe và exploitation. Bài có cách gọi U2R/exploitation và R2L chưa thống nhất giữa bảng; pipeline giữ `U2R` của CSV, không suy diễn tất cả là cùng cơ chế leo thang đặc quyền.
3. [Trang công bố của nhóm UCD](https://aseados.ucd-cs.ie/insdn-datasets-published/).

Mã thực thi duy nhất: `src/taxonomy.py`. Chỉ chấp nhận các nhãn được liệt kê theo từng nguồn, không dùng quy tắc “nhãn còn lại = loại tấn công nào đó”. Chuẩn hóa khoảng trắng, hoa/thường và dấu phân cách en/em dash hoặc U+FFFD trong tên web CIC; tên lạ làm dừng cả lượt trước khi train. Đổi bảng phải đổi version; manifest và SHA-256 được lưu trong protocol và model.

## Phạm vi dữ liệu thực tế

CSV CIC tại máy có 15 nhãn gốc; CSV InSDN tại máy có 6 nhãn, 205.167 hàng: Normal 68.424, DDoS 73.529, Probe 61.757, DoS 1.145, BFA 295, U2R 17. Đây không phải toàn bộ các nhóm của bản phát hành InSDN trong bài gốc. BOTNET/Web-Attack được hỗ trợ trong bảng nhưng không tự tạo mẫu khi CSV thiếu.

Sau ánh xạ có 10 nhóm được khai báo. Heartbleed chỉ có 11 hàng, dưới ngưỡng 15 mẫu sau cleanup, nên model thực nghiệm hiện giữ **9 lớp**. Việc loại lớp hiếm được ghi rõ trong `sources.*.excluded_classes_below_minimum`, không gán sang nhóm khác để tránh loại. Nhóm chỉ có một nguồn vẫn được giữ; không ép lấy giao 5 nhóm chung để làm bài toán dễ hơn.

Từng lượt xuất `label_mapping.csv` (nhãn gốc → nhóm, số hàng toàn bộ dữ liệu), `family_support.csv` (số mẫu giữ lại của từng nguồn), `protocol.json` (số đếm trước/sau, exclusions, taxonomy/version/hash), và `splits/<source>/{train,validation,test}.csv`. Các split giữ `RawLabel`, `Label`, `source_dataset` để truy vết; model **chỉ dùng 12 FEATURES**, không đưa ba cột này làm đầu vào.

## Huấn luyện và đánh giá

Chạy PowerShell từ thư mục chứa README, dùng OUT mới:

```powershell
.\.venv\Scripts\python.exe src/train_all.py --combined --multiclass --tune --stack-search --max-per-class 2000 --trees 60 --folds 3 --seed 42 --out experiments/m3-trees/seed42
```

Một lệnh train M1 (nhóm CIC), M2 (nhóm InSDN), M3 (hợp train của hai nguồn), cùng 5 baseline DT/RF/XGB/LGBM/LR. Ánh xạ **trước sampling theo nhóm**, cleanup exact-feature trong/giữa nguồn trước split 60/20/20. M3 sử dụng đúng hàng test M1/M2, thêm test nối hai nguồn; mỗi model chỉ refit cuối một lần trên train+validation. CV chọn baseline trên train, OOF/meta-search dùng train và validation; test không chọn candidate.

Notebook `notebooks/training_combined.ipynb`: chọn `MULTICLASS=True`; mặc định đọc kết quả đã lưu, đổi `DO_TRAIN=True` và OUT mới để huấn luyện theo cell. `MULTICLASS=False` dùng lại nhánh nhị phân cũ. Không gộp model nhị phân đã huấn luyện thành model đa lớp.

Lượt hiện tại ở `experiments/m3-trees/seed42/`. Model gộp `M3/models/stacking_ids.joblib` dùng RF + XGBoost + LightGBM ở tầng base và Logistic Regression ở tầng meta. Chọn đường dẫn output mới nếu chạy lại.

```powershell
$run = 'experiments/m3-trees/seed42'
$model = "$run/M3/models/stacking_ids.joblib"
.\.venv\Scripts\python.exe src/check_model.py --model $model --csv "$run/M3/cicids2017/smoke_test.csv"
.\.venv\Scripts\python.exe src/evaluate_model.py --model $model --csv "$run/splits/cicids2017/test.csv" --out experiments/evaluate-family-cic-new
.\.venv\Scripts\python.exe src/evaluate_model.py --model $model --csv "$run/splits/insdn/test.csv" --out experiments/evaluate-family-insdn-new
```

`check_model` kiểm tra tái lập dự đoán, `evaluate_model` tính metrics với ground truth. CSV đánh giá phải dùng nhãn nhóm đã ánh xạ như các test lưu ở trên; công cụ không tự đoán nguồn cho CSV nhãn subtype gốc. `detect.py` đọc được model này và xuất tên nhóm tấn công trong log; chưa có kiểm chứng chính xác live cho model mới.

## Cách diễn giải

- Chỉ so baseline/ES trên cùng taxonomy, đúng nguồn test và seed; F1 nhóm không so trực tiếp với kết quả CIC 14 subtype hoặc InSDN 6 nhãn cũ. Sampling theo nhóm cũng thay đổi các hàng và tỷ lệ test.
- Có metrics trên CIC, InSDN và test gộp. Test gộp tính từ dự đoán toàn bộ hàng, không lấy trung bình hai F1. Macro-F1 dùng tập lớp có nhãn thật trong từng test, cố định cho mọi thuật toán của test đó; dự đoán nhầm sang lớp ngoài tập này vẫn làm giảm recall của lớp thật. Danh sách này lưu tại `macro_f1_classes_in_truth`. Report/confusion vẫn liệt kê toàn bộ nhãn model và support; dòng macro avg của classification_report bao gồm cả lớp support 0 nên có thể khác chỉ số so sánh này. Không suy ra khả năng phân loại lớp có support 0 ở một nguồn.
- Đây là pooled-data evaluation: model đã thấy cả hai miền trong train; chưa chứng minh tổng quát sang dataset thứ ba. Các lớp INFILTRATION/U2R và BOT/WEB_ATTACK trong CSV hiện tại gắn với riêng một nguồn.
- Split ngẫu nhiên và khử vector trùng không bảo đảm tách các phiên/thời gian liên quan. M3 có nhiều mẫu học hơn M1/M2. Các tên feature chung chưa chứng minh extractor parity.
- Seed 7/21/42 phải báo cáo đủ mean/SD; không chọn seed có test tốt nhất. Stacking không được bảo đảm vượt baseline.
