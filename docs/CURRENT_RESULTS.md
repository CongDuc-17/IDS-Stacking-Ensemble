# Kết quả hiện hành — 11/11/2026

Số liệu đọc từ artifact thật trong `experiments/completion-20261110/`. Không thay thế các kết quả cũ. Model/split/log/biểu đồ trong experiments được giữ local và không đưa vào Git.

## M1/M2/M3, ba seed

Protocol: nhị phân, cap 5.000 mỗi lớp mỗi nguồn trước cleanup, 120 cây, 3 folds, tuning trên train; seed 7/21/42. Cùng test theo nguồn trong từng seed; M3 fit một lần cho cả ba test. Mỗi seed có completed.json và 30 hàng kết quả.

Đơn vị %, mean ± sample SD. Baseline cao nhất là mô tả sau test, không phải quy tắc chọn mô hình.

| Cấu hình/test | Accuracy Stacking | Macro-F1 Stacking | Baseline Macro-F1 cao nhất (mean) |
|---|---:|---:|---|
| M1/cicids2017 | 99.329 ± 0.164 | 99.328 ± 0.164 | rf: 99.329 |
| M2/insdn | 99.889 ± 0.077 | 99.876 ± 0.085 | rf: 99.925 |
| M3/cicids2017 | 99.330 ± 0.132 | 99.329 ± 0.132 | rf: 99.311 |
| M3/insdn | 99.889 ± 0.038 | 99.876 ± 0.042 | xgb: 99.926 |
| M3/combined | 99.577 ± 0.074 | 99.565 ± 0.075 | rf: 99.575 |

Stacking chưa vượt baseline nhất quán; chênh lệch nhỏ giữa các seed không đủ để tuyên bố thắng tổng quát. Class cap và random split làm hạn chế khả năng suy rộng. Không dùng điểm offline để suy ra live Accuracy.

## Phân loại đa lớp, seed 42

Cap 2.000 theo lớp, 60 cây, tuning. Đây là protocol khác bảng nhị phân.

| Dataset | Số lớp test | Macro-F1 Stacking | Baseline tốt nhất trên test | Lớp bị loại do ít mẫu |
|---|---:|---:|---|---|
| cicids2017 | 14 | 87.876% | xgb: 92.018% | {'Heartbleed': 11} |
| insdn | 6 | 91.139% | dt: 94.513% | Không |

## Gaussian anomaly trên flow, seed 42

Dùng đúng split của lượt nhị phân seed 42. Fit BENIGN train, chọn ngưỡng bằng BENIGN validation (FPR mục tiêu 1%), không dùng nhãn test để chọn ngưỡng.

| Dataset | Số mẫu test | FPR | FNR | Recall ATTACK |
|---|---:|---:|---:|---:|
| cicids2017 | 1882 | 0.813% | 90.089% | 9.911% |
| insdn | 1485 | 0.303% | 100.000% | 0.000% |

Gaussian hiện bỏ sót nhiều attack, đặc biệt không phát hiện ATTACK trên Test InSDN này. Đây là kết quả thất bại cần phân tích, không phải bằng chứng zero-day. Signed-log1p giữ các phép đo âm của flow dataset; số lượng nằm trong protocol.

## Host và graph trên CSV InSDN local

- Loại có khai báo 8 flow thời lượng âm; còn 205159 flow. Giả định timestamp explicit ngày/tháng/năm, hai format đã ghi protocol.
- Tạo 88072 host/window; nhãn: {'ATTACK': 73640, 'BENIGN': 14432}. ATTACK chỉ là liên quan đến attack traffic, bao gồm nạn nhân.
- Graph có 74615 node và 75528 cạnh có hướng (gộp qua thời gian); 584 ứng viên host/window fan-in/fan-out.
- GraphML giữ toàn bộ node/cạnh; SVG chỉ hiện 40 host nhiều flow nhất. Không có ground truth infected/C2 nên không báo cáo độ chính xác botnet.

Gaussian host đánh giá 1488 hàng test, FPR 0.403%. Test chỉ có BENIGN; FNR là null. Không có bằng chứng Recall ATTACK hoặc hiệu quả botnet từ test này.

## Kiểm tra và phần chưa hoàn thành

- 48 unit/integration test đã qua, gồm schema, rò rỉ split, test gộp, xuất/load model, Gaussian, host, graph, parity, PCAP tổng hợp, kiểm tra nhãn lab, bảo vệ log, đánh giá nhãn thật, beaconing, ablation cùng cỡ mẫu và meta-search OOF.
- Chưa có capture trích độc lập bởi hai extractor để đo feature parity thật.
- Windows đã có log HTTP BENIGN thật do người dùng chạy; chưa có bộ attack lab Windows/Kali đầy đủ để đo FPR/FNR, latency theo kịch bản và drops.
- File Word còn cần điền Chương 1–3, sửa tài liệu tham khảo và cập nhật kết luận theo các kết quả này. Xem COMPLETION_REVIEW.md.
- Báo cáo này không sử dụng kiểm tra chức năng bằng dữ liệu tổng hợp làm số liệu benchmark.

## Đánh giá lại M3 seed 42 bằng nhãn thật

`evaluate_model.py` nạp model đã lưu, không fit lại. Dùng toàn bộ test đã xuất; metrics khớp kết quả gốc. Khác với Prediction match, đây là so dự đoán với Label. Các thư mục `windows-evaluation-m3-cicids2017` và `windows-evaluation-m3-insdn` có metrics, confusion, predictions, errors và hash model/CSV.

| Test | Flow | Sai | Accuracy | Macro-F1 | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|
| CIC | 1882 | 13 | 99.309% | 99.308% | 0.508% | 0.891% |
| InSDN | 1485 | 1 | 99.933% | 99.924% | 0.101% | 0.000% |

Đây là cùng sampled holdout đã dùng, không phải test độc lập mới hay đo live.

## Ablation cùng cỡ mẫu, ba seed

Thư mục `size-ablation` có 162 hàng kết quả (54/seed): ba cấu hình, ba test và sáu thuật toán. Trong từng seed, số hàng từng lớp ở train và validation bằng nhau giữa ba cấu hình. Mixed lấy 50% mỗi nguồn cho từng lớp; CIC/InSDN matched lấy hoàn toàn từ nguồn tương ứng. Test giữ nguyên và đã kiểm tra hash.

| Cấu hình Stacking | Test CIC Macro-F1 | Test InSDN Macro-F1 | Test gộp Macro-F1 |
|---|---:|---:|---:|
| CIC_matched | 99.275 ± 0.171% | 50.041 ± 7.643% | 84.598 ± 1.354% |
| InSDN_matched | 41.553 ± 7.022% | 99.900 ± 0.043% | 69.514 ± 2.982% |
| Mixed_matched | 99.099 ± 0.276% | 99.851 ± 0.074% | 99.422 ± 0.161% |

Mean ± sample SD. Mixed cải thiện việc bao phủ hai miền trên test gộp ở cùng quy mô, nhưng thấp hơn model cùng miền ở cả hai test riêng. Đã thấy hai miền trong train không phải tổng quát sang miền chưa thấy. Đây là phân tích bổ sung trên test đã được xem trước, chưa phải xác nhận độc lập hoặc chứng minh ý nghĩa thống kê.

## Beaconing offline trên InSDN local

Thư mục `beaconing-insdn`: 131744 flow TCP/UDP hợp lệ, 37443 nhóm IP nguồn/đích/cổng đích/protocol. Loại có thống kê 73415 hàng protocol 0 và 8 flow thời lượng âm; 61513 thời điểm trùng trong nhóm được đếm và khử trước tính interval.

Có 3 ứng viên, mỗi nhóm 7–9 thời điểm khác nhau, mean interval 120 giây và CV=0. Toàn bộ 23 flow tương ứng mang nhãn Normal trong CSV nguồn. Không coi đây là ba C2 hay tính Recall botnet từ kết quả này. Timestamp thô, polling hợp pháp và timeout có thể tạo regularity; chương trình chỉ phân tích toàn capture offline.

## Trạng thái capture Windows

Lần agent thử mở capture trên Npcap loopback cho cổng HTTP demo riêng bị từ chối với lỗi Admin-only Mode, vì phiên không có quyền Administrator. `windows-localhost-benign/protocol.json` giữ trạng thái blocked của lần đó. Sau đó người dùng đã chạy Administrator thành công; xem mục cập nhật bên dưới. Chưa có bộ metrics attack lab. Lệnh chạy nằm trong [WINDOWS_VALIDATION.md](WINDOWS_VALIDATION.md).

## Stacking đa lớp có tìm kiếm meta learner

Phạm vi ES được chốt theo ghi chú riêng; Gaussian/graph/beaconing là nhánh bổ sung, không phải các tầng bắt buộc. Xem STACKING_SCOPE.md và notebooks/training.ipynb.

Đã chạy --stack-search trên cả hai dataset, seed 7/21/42, cùng cap 2000, 60 cây, 3 folds và tuning baseline. Hai nhóm base learner × ba giá trị C × hai class_weight = 12 ứng viên; chọn bằng OOF train và validation. Test không tham gia chọn. Các lượt mới nằm trong multiclass-search-*-seed*, summary riêng cho mỗi nguồn.

| Dataset | Mean Macro-F1 ES ± SD | Baseline cao nhất theo mean |
|---|---:|---|
| cicids2017 | 88.404 ± 1.310% | rf: 90.606% |
| insdn | 93.902 ± 3.282% | lgbm: 94.734% |

Tìm kiếm meta learner chưa tạo ưu thế ES so với baseline trên cả hai nguồn. InSDN seed 7 hòa XGBoost; các lượt còn lại thấp hơn baseline tốt nhất. Không chọn riêng seed hòa để báo cáo thành công.

Seed 42 giữ nguyên hash train/validation/test so với thí nghiệm đa lớp trước. CIC: ES cũ 87,876%, mới 87,604%; InSDN giữ 91,139%. Số liệu phản ánh một tìm kiếm không cải thiện test như kỳ vọng. Đây là phân tích bổ sung trên test đã được xem trước; chưa phải xác nhận độc lập.

Các lượt mới xuất đủ splits/train.csv, validation.csv, test.csv; đã nạp lại model và đánh giá toàn test, khớp metrics gốc. Bộ test cập nhật có 48 kiểm tra.

## Cập nhật capture của người dùng

Người dùng đã mở PowerShell Administrator và capture HTTP localhost thành công. Snapshot log windows-benign-new hiện có các flow BENIGN; đây là bằng chứng live Windows đã chạy, chưa có nhãn attack hoặc PCAP/metrics lab hoàn chỉnh. Trạng thái blocked trước đó chỉ thuộc lần agent thử không có quyền, không mô tả lần chạy của người dùng.

## Đa lớp kết hợp hai nguồn theo nhóm chung

Đã hoàn thành ánh xạ và huấn luyện M1/M2/M3 nhóm chung, độc lập với các model subtype bên trên. Quy ước `cic-insdn-families-v1` có 10 nhóm khai báo; model hiện học 9 nhóm, Heartbleed 11 mẫu bị loại dưới ngưỡng 15. [LABEL_TAXONOMY.md](LABEL_TAXONOMY.md) ghi bảng ánh xạ và nguồn đối chiếu. CSV InSDN tại máy chỉ có 6 nhãn; BOT/WEB_ATTACK/INFILTRATION chỉ có CIC, U2R chỉ có InSDN.

Lượt chính thức của nhánh này: `multiclass-families-seed7`, `multiclass-families-seed21`, `multiclass-families-seed42`, cùng cap 2.000 mỗi nhóm/mỗi nguồn, 60 cây, 3 folds, baseline tuning và 12 lựa chọn meta. `multiclass-families-summary` có 90 hàng kết quả và mean/SD. Các thư mục `multiclass-combined-seed*` là lượt kiểm tra trước khi cố định scope Macro-F1; không dùng chúng thay bảng dưới.

Macro-F1 dưới đây dùng tập lớp có ground truth trong từng test, cố định cho mọi thuật toán; report đầy đủ còn có các lớp support 0. Đây là mean ± SD mẫu qua ba seed, không phải khoảng tin cậy. Baseline cao nhất theo mean là mô tả kết quả test, không được dùng để chọn stack.

| Cấu hình | Test | ES Macro-F1 mean ± SD | Baseline cao nhất theo mean | ES − baseline |
|---|---|---:|---|---:|
| M1 | cicids2017 | 96.338 ± 0.278% | xgb: 96.183% | +0.155 điểm % |
| M2 | insdn | 93.817 ± 3.518% | lgbm: 94.734% | -0.917 điểm % |
| M3 | cicids2017 | 96.473 ± 0.288% | xgb: 96.361% | +0.112 điểm % |
| M3 | combined | 94.409 ± 2.578% | rf: 94.467% | -0.058 điểm % |
| M3 | insdn | 93.480 ± 4.121% | rf: 95.055% | -1.574 điểm % |

ES nhỉnh hơn mean baseline trên test CIC theo nhóm; trên InSDN và test gộp vẫn thấp hơn. Chưa đáp ứng kết luận ES vượt baseline trên cả hai nguồn. Không so điểm này trực tiếp với CIC 14 subtype hoặc InSDN 6 nhãn cũ vì taxonomy/sampling/split đã thay đổi. Ba seed phát triển không thay thế kiểm định trên holdout mới tách theo phiên/thời gian.

Seed 42 M3 có 9 lớp, test CIC 2.288 flow, InSDN 1.097 flow, test gộp 3.385 flow. Accuracy gộp 97,578%, Macro-F1 94,608%. Chỉ có 7 mẫu INFILTRATION và 3 mẫu U2R trong test: kết quả lớp hiếm còn dao động lớn. Source test giữ hash giống M1/M2 trong cùng lượt; hash giữa các thí nghiệm khác taxonomy không được coi là tương đương.

Model dùng ngay: `multiclass-families-seed42/M3/models/stacking_ids.joblib`, chọn seed cố định 42 thay vì seed có test tốt nhất. Đã nạp lại model, smoke match 100%, chấm lại toàn bộ hai test bằng `evaluate_model.py` và đối chiếu khớp số liệu train. Snapshot notebook `training_combined.ipynb` đã chạy 8 cell code, hiển thị mapping/support, xác minh split và confusion 9 lớp. Bộ test hiện có 53 kiểm tra đều qua.

Phần kết hợp đa lớp hiện hoàn thành ở mức offline theo nhóm. Chưa chứng minh taxonomy đã được đánh giá độc lập, extractor parity hay độ chính xác realtime trên Linux của model mới.

## Cập nhật gói VM 9 nhóm và rà soát Stacking

Đã dựng `deliverables/ids-vm-multiclass-combined-seed42.zip`: 32 file, có SHA256SUMS cho 31 payload file. Model, taxonomy và code suy luận/chấm điểm đồng bộ với nhánh đa lớp kết hợp, thay vì dùng nhầm ZIP M3 nhị phân. Giải nén vào thư mục tách biệt, hai smoke đều match 100% và nạp model chấm lại hai full test khớp Accuracy/Macro-F1/Weighted-F1/FPR/FNR gốc. Replay PCAP tổng hợp ghép đúng 1 flow chỉ dùng làm self-check, không là kết quả lab thật.

Tool lab hỗ trợ `--model`, `--truth-source` và `--binary-only`, từ chối nhãn không thuộc model nếu chấm đa lớp. Full CICFlowMeter reference có thể chuẩn hóa để đối chiếu parity với format/timezone rõ và checksum PCAP/CSV; chưa có reference/capture thật để xác nhận pass. Hiện có 58 test đều qua.

[STACKING_AUDIT.md](STACKING_AUDIT.md) chỉ từng vị trí code tương ứng lý thuyết, xác nhận artifact RF+XGB+LR → meta LR có 27 cột xác suất cho 9 lớp và phân tích phần lớn chênh lệch InSDN đến từ U2R hiếm. [VM_DEPLOYMENT.md](VM_DEPLOYMENT.md) hướng dẫn gói mới; [FEATURE_PARITY.md](FEATURE_PARITY.md) là bước kiểm chứng còn cần thực hiện trên capture thật. Không tự train lại hoặc thay số liệu ES để tạo kết luận vượt baseline.

## Kết quả lab HTTP do người dùng cung cấp

Người dùng đã chạy được detector trên Kali thật và gửi log/CSV của 10 kết nối curl Windows → Kali:8080. Replay ghép đủ 10 flow, cả 10 nhãn thật BENIGN bị dự đoán BRUTE_FORCE: Accuracy=0%, FPR=100% trên chính lượt này; chưa có attack nên FNR=null. Đây là bằng chứng pipeline chạy trên Linux và một thất bại về chất lượng phát hiện, không phải độ chính xác chung của mọi traffic.

Đã tái hiện 10 nhãn và các điểm dự đoán bằng artifact giữ nguyên trên Windows. RF nhận cả 10 là BENIGN; XGB/LR base và meta nhận BRUTE_FORCE. Các cột flag lab FIN=2/SYN=2/PSH=3/ACK=9 ngoài miền 0/1 của development. Nghiên cứu CIC-IDS2017 xác nhận ngữ nghĩa flag cũ chỉ cập nhật packet đầu, trong khi extractor hiện cộng toàn flow. Chuyển đơn giản thành presence hoặc chỉ giả định flag gói đầu vẫn không giải quyết các dự đoán sai; cần PCAP để đối chiếu ranh giới/định nghĩa đầy đủ.

Chi tiết và giới hạn tại [LIVE_DIAGNOSIS.md](LIVE_DIAGNOSIS.md). Chưa thay model/runtime hoặc sửa số liệu để ép lượt BENIGN thành công; chưa nhận PCAP gốc. Các ghi chú chưa có Linux thật ở những mục trước mô tả thời điểm chuẩn bị gói, không thay thế bằng chứng người dùng mới gửi này.

## PCAP thật và bản sửa payload v2

Đã nhận benign02.pcap: 100 TCP packet, 10 kết nối GET/HTTP 200, tái trích runtime cũ khớp CSV người dùng. Phát hiện code cộng Ethernet padding vào TCP payload: chiều gửi 102 thay vì 84 byte. Đã sửa theo network/header lengths; log và CSV ghi version `scapy-ip-payload-v2`, log giữ 12 feature đầu vào. 62 test đều qua.

Replay cùng PCAP sau sửa cho 10 flow, payload 84/199 byte nhưng vẫn 10 BRUTE_FORCE, FPR=100% trên lượt BENIGN này. Do đó bản sửa byte chưa sửa được độ chính xác model. Không dùng chia nhỏ flow để đổi mẫu số tạo điểm tốt hơn. Chi tiết và hướng dữ liệu/holdout tiếp theo ở LIVE_DIAGNOSIS.md; gói runtime riêng `ids-vm-multiclass-combined-seed42-padding-v2.zip` giữ nguyên model.

## M3 đa lớp với RF, XGBoost và LightGBM

Chạy lại M1/M2/M3 trên CIC-IDS2017 và InSDN với seed 7, 21, 42. M3 cố định RF, XGBoost và LightGBM ở tầng base, giữ Logistic Regression ở tầng meta. Cờ `--stack-search` chọn 6 cặp C/class weight bằng Macro-F1 validation. M1, M2 và nhánh nhị phân giữ quy tắc chọn stack trước đó. Đã đối chiếu hash cả sáu split ở mỗi seed với lượt đa lớp cũ. Các bảng và model mới nằm trong `experiments/m3-trees/`.

| Test M3 | Macro-F1 cũ | Macro-F1 mới, mean ± SD | Baseline tốt nhất theo mean |
|---|---:|---:|---:|
| CIC-IDS2017 | 96,473% | 96,908 ± 0,704% | XGBoost 96,361% |
| InSDN | 93,480% | 94,670 ± 2,433% | RF 95,055% |
| Gộp | 94,409% | 95,112 ± 2,447% | RF 94,467% |

M3 seed 42 chọn C=10, `class_weight=None`. Trên test gộp 3.385 flow, Accuracy đạt 97,637% và Macro-F1 đạt 94,788%. Seed 42 dùng cho gói Kali theo quy ước trước đó. Replay PCAP HTTP chẩn đoán cho 9 BENIGN và 1 U2R, so với 10 BRUTE_FORCE của M3 cũ. FPR giảm từ 100% xuống 10% trên chính capture này. Các tập test và PCAP đã được dùng trong quá trình phát triển. Cần capture độc lập có cả BENIGN và attack để đo FPR, Recall và độ trễ live.

```powershell
foreach ($seed in @(7, 21, 42)) {
    .\.venv\Scripts\python.exe src/train_all.py --combined --multiclass --out "experiments/m3-trees/seed$seed" --max-per-class 2000 --trees 60 --folds 3 --seed $seed --tune --stack-search
}
.\.venv\Scripts\python.exe src/summarize.py --runs experiments/m3-trees/seed7 experiments/m3-trees/seed21 experiments/m3-trees/seed42 --out experiments/m3-trees/summary
.\.venv\Scripts\python.exe src/package_vm.py
```
