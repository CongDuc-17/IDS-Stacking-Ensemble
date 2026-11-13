# Phân tích và kế hoạch thực hiện đề tài

Ngày lập: 07/11/2026. Đề tài: **Phát hiện tấn công mạng dựa trên mô hình Ensemble Stacking**.

## 1. Phạm vi phù hợp với tên đề tài

Tài liệu mẫu CNN gộp nhiều hướng nghiên cứu: Gaussian bất thường, phân loại có giám sát, đồ thị botnet, beaconing và vận hành Linux. Không có cơ sở để xem mọi nhánh này là bắt buộc chỉ từ tên đề tài Stacking. Các ghi chú riêng yêu cầu ít nhất hai dataset, EDA, baseline, mô hình mở rộng và so sánh metrics; đây là phạm vi chính của bản triển khai.

Nếu giảng viên xác nhận Gaussian và đồ thị là đầu ra bắt buộc, cần bổ sung thành các thí nghiệm riêng, thay vì trình bày chúng như thành phần đã được thực hiện trong Stacking. Bản hiện tại không triển khai các nhánh này.

Hai bài toán được phân biệt:

- **Phát hiện tấn công đã biết:** BENIGN/ATTACK, có thể suy từ đầu ra đa lớp; phải đo Recall lớp ATTACK, FPR và FNR.
- **Phân loại loại tấn công:** nhiều nhãn theo từng dataset; ưu tiên Macro-F1 và Precision/Recall/F1 từng lớp.

Mô hình phân loại có giám sát không tự trở thành bộ phát hiện zero-day hoặc phương pháp phát hiện bất thường không giám sát. Nhãn `Bot` cũng không chứng minh hệ thống đã phát hiện cấu trúc botnet tập trung/P2P.

## 2. Ensemble Stacking hai tầng hoạt động thế nào?

Tầng 1 gồm nhiều bộ học cơ sở. Với một flow, từng bộ học xuất vector xác suất của các lớp. Tầng 2 nhận các vector đó và học cách kết hợp chúng để dự đoán nhãn cuối. Đây là mô hình học cách kết hợp; Voting chỉ lấy trung bình/biểu quyết theo quy tắc cố định.

Ví dụ ba mô hình, bốn lớp: mỗi flow tạo tối đa 12 giá trị đầu vào cho tầng 2. Với bài toán nhị phân, scikit-learn bỏ một cột xác suất phụ thuộc tuyến tính ở mỗi mô hình nên đầu vào gồm ba cột khi không passthrough.

Điểm quan trọng nhất là tạo đầu vào tầng 2 bằng **out-of-fold (OOF)**. Chia train thành K phần, huấn luyện tầng 1 trên K−1 phần và dự đoán phần còn lại. Sau K vòng, mỗi hàng có dự đoán từ mô hình chưa được fit trên hàng đó. Tầng 2 học từ bảng OOF này. Cuối cùng, tầng 1 được fit lại trên toàn bộ development data để suy luận.

Không huấn luyện tầng 1 trên toàn train, lấy dự đoán ngay trên train, rồi coi đó là OOF. Cách này làm tầng 2 học từ dự đoán quá lạc quan. Script dùng `StackingClassifier` với `StratifiedKFold(shuffle=True, random_state=seed)`, imputer/scaler nằm bên trong từng pipeline. Không dùng `cv='prefit'`.

Việc chọn tham số baseline trước khi tạo OOF không phải nested CV hoàn chỉnh. Các điểm CV phục vụ chọn mô hình; tập test được giữ riêng mới là phép đánh giá ngoài cùng. Bản triển khai ghi rõ giới hạn này.

## 3. Chọn hai dataset

| Dataset | Lý do chọn | Giới hạn và vai trò |
|---|---|---|
| CIC-IDS2017 | Đã có tám CSV thật trong project; nhiều loại tấn công; nguồn chính thức có PCAP và flow CSV từ CICFlowMeter | Dataset lab cũ; có lớp cực ít; phép chia ngẫu nhiên có thể học dấu vết chiến dịch. Dataset thực nghiệm số 1 |
| InSDN | Dataset SDN của nhóm UCD, gồm traffic bình thường và nhiều loại tấn công; phù hợp kiểm tra cùng phương pháp trên môi trường khác | Không đồng nhất với mạng Kali thông thường; không mặc định mọi feature là telemetry OpenFlow. Dataset thực nghiệm số 2, chưa tải được trong phiên này |

Huấn luyện và đánh giá độc lập trên mỗi bộ. Không trộn nhãn/CSV rồi gọi là hai dataset. Cũng không lấy model CIC áp lên InSDN và coi đó là thí nghiệm độc lập chuẩn nếu chưa đồng bộ nhãn và ngữ nghĩa đặc trưng.

CIC-DDoS2019 là lựa chọn thay thế nếu muốn chuyên DDoS, nhưng quy mô lớn hơn và làm hẹp bài toán. CTU-13 phù hợp nghiên cứu botnet; nhãn/background và flow schema khác nên không phải lựa chọn thứ hai ít công tích hợp nhất cho code hiện có.

## 4. EDA và xử lý dữ liệu

`src/eda.py` đọc tất cả hàng bằng chunk 50.000 hàng; lưu số lượng lớp thô và thiếu/không hữu hạn ở 12 đặc trưng. Biểu đồ phân bố và tương quan dùng mẫu giới hạn RAM, có chú thích rõ.

Quy trình dữ liệu:

1. Kiểm tra tên cột theo hợp đồng, bỏ khoảng trắng/BOM; ánh xạ tên viết tắt của InSDN; không đoán theo vị trí.
2. Loại nhãn trống, thống nhất `Normal` thành `BENIGN`. Giữ tên các loại tấn công còn lại để truy nguồn.
3. Chuyển feature sang numeric; ±Inf/giá trị không parse được thành missing. Bỏ hàng thiếu toàn bộ feature.
4. Lấy mẫu ngẫu nhiên bằng random-priority reservoir theo lớp. Mỗi hàng có cơ hội vào mẫu như nhau trong lớp trước khử trùng; RAM không tăng theo số chunk.
5. Trong mẫu, loại các vector đặc trưng có nhãn mâu thuẫn; loại feature-identical duplicates kể cả khi xuất hiện ở file khác. Ghi số lượng loại bỏ.
6. Lớp dưới 15 hàng sau xử lý không đủ cho phép chia 60/20/20 + OOF nên bị loại và được ghi riêng. Đây là hạn chế, không được báo cáo là đã đánh giá đủ mọi lớp.
7. Chia train/validation/test theo lớp; fit imputer/scaler chỉ trong train/fold. Không dùng nhãn, IP, timestamp, flow ID như đầu vào học.

Class cap và khử trùng làm thay đổi prevalence. Vì vậy Accuracy, Precision và Weighted-F1 trên mẫu không đại diện trực tiếp cho traffic tự nhiên. Nên có holdout thu thập độc lập với tỷ lệ BENIGN thật cho đánh giá bổ sung. Đếm thiếu hiện tại chỉ áp dụng cho 12 feature được chọn, không phải toàn bộ 78+ cột của CSV gốc.

Không dùng SMOTE/ADASYN mặc định. Nếu bổ sung, chỉ resample trong train fold; không tạo mẫu tổng hợp trước split. Class weight là lựa chọn đầu tiên ít phức tạp; bản hiện tại dùng cho DT, RF, LR và tầng 2, chưa áp dụng weight cho XGBoost/LightGBM.

## 5. Thiết kế thí nghiệm

Baseline gồm DT, RF, XGBoost, LightGBM, Logistic Regression. RF là baseline bắt buộc theo mẫu; không cần chạy toàn bộ danh sách RF/DT/XGB/SVM/KNN mới đúng ghi chú. LR tạo đối chứng tuyến tính và thành phần khác nhóm cây.

Khi có `--tune`, mỗi baseline được xét hai giá trị tham số bằng CV trên train, chọn theo Macro-F1. Đây là tìm kiếm nhỏ để phù hợp máy cá nhân, không phải tối ưu đầy đủ. Seed, số cây, fold và kết quả mọi ứng viên được lưu.

Hai giả thuyết stack được định nghĩa trước:

| Cấu hình | Tầng 1 | Tầng 2 |
|---|---|---|
| Trees | RF + XGBoost + LightGBM | Logistic Regression, C=1, balanced |
| Diverse | RF + XGBoost + LR đã scale | Logistic Regression, C=1, balanced |

Chọn stack bằng Macro-F1 validation, không dựa vào test. Sau đó refit mọi baseline và stack được chọn trên cùng development data (train + validation) rồi đánh giá trên cùng test. Không có passthrough trong hai cấu hình này.

Metrics: Accuracy, Macro-F1, Weighted-F1, Precision/Recall/F1/support từng lớp, confusion matrix, FPR trên BENIGN, FNR trên ATTACK và thời gian fit/suy luận batch. Phát hiện nhị phân từ đa lớp được báo cáo riêng; không giả vờ rằng đây là một model nhị phân đã được train riêng.

Lặp seed 7, 21, 42 trên cùng quy trình đã cố định, báo cáo mọi lượt và trung bình ± SD. Những lượt này vẫn là tham khảo từ random split; không thay thế kiểm thử theo phiên/thời gian. Không dùng SD giữa ba seed như khoảng tin cậy thống kê độc lập.

## 6. Yêu cầu “Stacking phải cao hơn baseline”

Đây là mục tiêu thực nghiệm cần kiểm chứng, không phải tính chất được bảo đảm bởi thuật toán. Cần thống nhất với giảng viên metric chính trước thí nghiệm; bản này dùng Macro-F1 vì mất cân bằng lớp. Accuracy tăng nhưng Macro-F1 giảm không đủ để kết luận tốt hơn nói chung.

Kết quả cũ trong `results/comparison.json`: Stacking Accuracy 0,968590, Macro-F1 0,893750; RF Macro-F1 0,919327. Lượt mới seed 42, 60 cây, cap 2.000: XGBoost Macro-F1 0,920180, Stacking 0,878762. Không so trực tiếp hai lượt như cùng protocol vì cách lấy mẫu và chia dữ liệu khác nhau.

Lượt mới chưa đạt mục tiêu. Báo cáo đúng kết quả và phân tích lỗi: nhóm web attack thiếu thông tin tầng ứng dụng; lớp SQL Injection chỉ có 3 mẫu test; meta-learner balanced có thể tăng Recall lớp hiếm nhưng giảm Precision. Những giải thích này là giả thuyết, cần thí nghiệm ablation mới để kiểm tra.

Hướng cải tiến hợp lý là kiểm tra thêm feature có ý nghĩa, cấu hình regularization/weight của tầng 2, và tương quan lỗi tầng 1. Chỉ chọn bằng development CV/validation; nếu đã dùng test để quyết định cải tiến, cần test mới/holdout độc lập để kết luận cuối. Không làm baseline yếu đi, bỏ lớp khó hoặc đổi seed chỉ để đạt yêu cầu.

## 7. Triển khai và các giới hạn cần bảo vệ

CSV dataset → pipeline học → model/phiên bản → Kali → capture → cùng extractor cho PCAP/live → dự đoán/log → đối chiếu ground truth.

Mã dùng 12 feature của bản starter để giữ phạm vi PoC. Có cùng tên cột không có nghĩa Scapy đo giống CICFlowMeter. Vì vậy mô hình đã train trên CSV chuẩn chỉ được dùng live như bản thử nghiệm cho đến khi so sánh cùng PCAP qua hai extractor, hoặc thu thập/gán nhãn và train lại bằng chính extractor dùng live.

Flow timeout đóng trước khi thêm gói của phiên mới; bảng flow và hàng đợi có giới hạn. Capture chạy liên tục trong thread riêng, dự đoán ở main thread. Nếu queue đầy, bỏ gói mới và đếm rõ; không khẳng định không mất gói. NIC/kernel drops và throughput chịu tải thực tế phải đo trên Kali.

Độ trễ suy luận vài millisecond không phải độ trễ phát hiện: flow có thể cần chờ idle timeout hoặc max-age. Log live ghi thêm thời gian từ gói đầu quan sát được đến kết quả; số này còn chứa thời gian flow, chờ queue và timeout, không phải độ trễ tính từ thời điểm chiến dịch tấn công bắt đầu.

## 8. Đầu ra cần nộp và trạng thái

| Yêu cầu | Trạng thái |
|---|---|
| Giải thích ES hai tầng và OOF | Có tài liệu, có code |
| Chọn ≥2 dataset | CIC-IDS2017 + InSDN; mới có CSV thật của CIC |
| EDA, làm sạch, thống kê loại bỏ | Có script; đã chạy CIC |
| Baseline + chọn tham số | Có, đã chạy trên CIC |
| Stacking + chọn cấu hình | Có, đã chạy trên CIC |
| Stacking vượt baseline | Chưa đạt; không bảo đảm trước |
| Chuyển PCAP thành CSV | Có extractor dùng chung với live; đã/đang kiểm thử PCAP tổng hợp, chưa có PCAP lab thật |
| Dự đoán PCAP/live và log | Có chương trình; chưa đo live trên Kali |
| Ít nhất 2–3 kịch bản lab | Có hướng dẫn; chưa thực thi trên VM |
| Bảng so sánh hai dataset + độ trễ live | Chưa đủ dữ liệu để hoàn tất |
| Gaussian/đồ thị botnet/dashboard/firewall | Ngoài phạm vi cốt lõi hiện tại |

## 9. Tài liệu chính

- [CIC-IDS2017, UNB](https://www.unb.ca/cic/datasets/ids-2017.html). Sharafaldin, Lashkari, Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, ICISSP 2018.
- [InSDN, nhóm UCD](https://aseados.ucd-cs.ie/insdn-datasets-published/), [DOI 10.1109/ACCESS.2020.3022633](https://doi.org/10.1109/ACCESS.2020.3022633).
- [StackingClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.StackingClassifier.html).
- [Data leakage và Pipeline](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).
- [Scapy usage](https://scapy.readthedocs.io/en/latest/usage.html).
