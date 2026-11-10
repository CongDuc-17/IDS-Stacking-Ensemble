# Kết quả hiện hành — 10/11/2026

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
