# Đối chiếu các yêu cầu còn thiếu

Cập nhật nhánh kết hợp đa lớp: đã có bảng ánh xạ có version/nguồn đối chiếu, kiểm tra nhãn lạ, thống kê nhãn trước/sau, shared splits, M1/M2/M3 theo nhóm và notebook huấn luyện. Xem [LABEL_TAXONOMY.md](LABEL_TAXONOMY.md). Đây là kiểm tra triển khai theo nhãn dataset, chưa phải thẩm định độc lập taxonomy hoặc kiểm chứng live.


Cập nhật 10/11/2026 sau khi bổ sung code và chạy thực nghiệm. Căn cứ chính là 5 ghi chú cho Ensemble Stacking, code và artifact trong `experiments/completion-20261110/`. Hướng dẫn CNN và mẫu Word là tài liệu tham khảo. Gaussian, beaconing và graph trong bảng là các nhánh mở rộng, không tự thành tiêu chí bắt buộc của ES; xem STACKING_SCOPE.md.

| Yêu cầu | Trạng thái và giới hạn |
|---|---|
| Hai dataset, EDA | Đã chạy CIC và InSDN, có biểu đồ và thống kê thô |
| Baseline + Stacking M1/M2/M3 | Đã chạy lại đủ seed 7/21/42 trên cùng protocol |
| M3 test CIC, InSDN, gộp | Đã có ba test; cùng model đã fit, test gộp tính từ toàn bộ hàng chứ không trung bình F1 |
| Phân loại đa lớp | Đã chạy riêng cả hai dataset; CIC loại Heartbleed 11 mẫu theo quy tắc tối thiểu, có ghi protocol |
| Chọn tham số meta learner | Đã có --stack-search, 12 ứng viên từ OOF train/validation; chạy đa lớp 3 seed trên 2 nguồn, chưa vượt baseline |
| Notebook huấn luyện theo bước | Đã có notebooks/training.ipynb gọi pipeline chung, DO_TRAIN mặc định False; khi bật sẽ chạy đọc/split/fit/test thật |
| Gaussian anomaly | Có model flow và metrics thật trên hai nguồn; có chế độ host theo cửa sổ thời gian |
| PCAP → flow/host | Có extractor và bộ tổng hợp host, có kiểm thử |
| Botnet graph | Có đồ thị giao tiếp, GraphML/SVG và ứng viên fan-in/fan-out; chưa có ground truth để xác nhận botnet |
| Beaconing | Đã có heuristic interval/CV offline, chạy InSDN ra 3 ứng viên; các flow mang nhãn Normal, không xác nhận C2 |
| Kiểm chứng nhãn thật trên Windows | Đã nạp lại M3 và đánh giá toàn bộ hai test; kết quả khớp metrics gốc, có errors.csv |
| Ablation cùng cỡ mẫu | Đã chạy ba seed, cùng budget từng lớp/partition, 162 hàng kết quả; test đã xem trước nên là phân tích bổ sung |
| Stacking cao hơn baseline | Chưa đạt nhất quán; giữ kết quả thật, không lựa seed hoặc làm yếu baseline |
| Kali realtime, 2–3 kịch bản | Có code/hướng dẫn; chưa có số đo từ VM thật trong phiên này |
| Feature parity hai extractor | Có tool đối chiếu; cần cùng PCAP trích độc lập để thực nghiệm |
| Báo cáo hoàn chỉnh | Có khung nội dung cần bổ sung dưới đây; file Word chưa được viết lại |

M1/M2/M3 là ba cấu hình nguồn dữ liệu, mỗi cấu hình có năm baseline và Stacking. Chúng không phải ba thuật toán khác nhau. Model nhị phân phát hiện ATTACK không tự gọi tên subtype; các thí nghiệm đa lớp là nhánh riêng.

## Chương 1 cần viết thêm

- Thay mục 1.3 còn ghi “Nội dung Lý thuyết 03” bằng Ensemble Learning, Stacking hai tầng và OOF. Giải thích meta learner học từ dự đoán ngoài fold; imputer/scaler nằm trong pipeline của từng fold. Không dùng dự đoán ngay trên train làm OOF.
- Bảng feature trong mục 1.2.2 phải phân biệt ví dụ lý thuyết Flow IAT/Flow Bytes/s với 12 feature thực sự đang dùng. Ghi đúng đơn vị và ranh giới flow.
- Thêm Gaussian một thành phần/covariance đường chéo, log-density và ngưỡng chọn bằng BENIGN validation. Đây là anomaly score, không phải xác suất attack hay bằng chứng zero-day.
- Thêm mô hình graph: host là node, giao tiếp là edge, fan-in/fan-out theo cửa sổ; giải thích false positives từ server hợp pháp và khác biệt giữa “ứng viên cấu trúc” với “botnet đã xác nhận”.
- Bổ sung Precision/Recall/F1, Macro-F1, FPR/FNR, support và độ trễ. Quy ước ATTACK là lớp dương; mẫu số bằng 0 là không xác định.

## Chương 2 cần viết thêm

1. Phát biểu bài toán: đầu vào flow/host, nhãn nhị phân/đa lớp, giới hạn offline/live và các đầu ra cần kiểm chứng.
2. Mô tả hai nguồn CSV, phiên bản/URL/archive tải về, schema mapping, nhãn Normal/BENIGN và thống kê cleanup. File InSDN local có 205.167 hàng, không tự khẳng định đó là toàn bộ bản phát hành gốc.
3. Sơ đồ pipeline dữ liệu → train/validation/test → chọn model → refit → đánh giá → artifact; nhánh PCAP → flow → host → Gaussian/graph.
4. Giải thích các module và hợp đồng file thay vì chép nguyên code vào báo cáo. Mục CSDL trong mẫu có ghi có thể bỏ; pipeline CSV/JSON/joblib không cần thêm database để lấp mục này.
5. Nêu rõ cửa sổ host tính theo lúc flow hoàn tất, nhãn host bao gồm nạn nhân và UNKNOWN không dùng như nhãn thật.

## Chương 3 cần viết bằng kết quả thật

- Thay các kịch bản mẫu đăng nhập/tìm kiếm bằng EDA, huấn luyện/đánh giá M1/M2/M3, đa lớp, Gaussian, host/graph và lab khi có capture thật.
- Ghi CPU/RAM/OS/Python, phiên bản package, cap/trees/folds/seed và thời gian toàn lượt. Phân biệt refit cuối với toàn bộ tuning.
- Bảng mean ± SD giữa ba seed phải tách Test CIC/Test InSDN/Test gộp. SD giữa seed chưa phải khoảng tin cậy cho traffic thực tế.
- Phân tích FP/FN của Gaussian và Stacking. Gaussian flow đang bỏ sót nhiều attack: báo đúng thay vì chỉ đưa FPR thấp.
- Class cap trước chia tập làm thay đổi cả phân bố test. Đây là sampled benchmark; muốn kết luận gần triển khai cần holdout có phân bố tự nhiên và tách phiên/thời gian phù hợp. Không diễn giải điểm gần 100% là độ chính xác live.
- M3 ban đầu có nhiều dữ liệu hơn M1/M2. Đã bổ sung ablation cùng cỡ mẫu; báo cáo Mixed bao phủ test gộp tốt hơn nhưng không thắng trên mọi test riêng. Không coi phân tích trên test đã xem trước là xác nhận độc lập.
- Corpus host hiện có thứ tự thời gian rất lệch: test về sau chỉ có BENIGN. Không thể tính FNR hoặc Recall ATTACK từ test host đó. Cần lab hỗn hợp độc lập.

## Nguồn và kết luận

Danh mục trong mẫu Word còn tài liệu GIS/tuyến thu gom rác, không khớp các trích dẫn dataset. Thay bằng nguồn thực sự sử dụng:

- [CIC-IDS2017, UNB](https://www.unb.ca/cic/datasets/ids-2017.html).
- [InSDN, UCD](https://aseados.ucd-cs.ie/insdn-datasets-published/) và [DOI 10.1109/ACCESS.2020.3022633](https://doi.org/10.1109/ACCESS.2020.3022633).
- [StackingClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.StackingClassifier.html), [GaussianMixture](https://scikit-learn.org/stable/modules/generated/sklearn.mixture.GaussianMixture.html), [data leakage/Pipeline](https://scikit-learn.org/stable/common_pitfalls.html#data-leakage).

Kết luận phải tách: code đã thực hiện, kết quả đã đo và các yêu cầu chưa kiểm chứng. Không bảo đảm Stacking luôn thắng baseline; không gọi graph hub là botnet; không gọi PCAP tổng hợp là lab thật. Hướng hoàn tất còn lại là sửa Word theo nội dung trên, xác minh nguồn metadata/timestamp, thực hiện parity và thu thập các phiên Kali có nhãn độc lập.

Hướng dẫn chạy: `EXTENSIONS.md`, `THREE_MODELS.md` và `KALI_LAB.md`. Kết quả hiện hành: `CURRENT_RESULTS.md`. Các tài liệu AUDIT/DE_TAI/RESULTS cũ mô tả giai đoạn 07/11/2026, không thay cho kết quả hiện hành.

Phần làm tiếp trên Windows ở `WINDOWS_VALIDATION.md`. Người dùng đã chạy Administrator và có log HTTP BENIGN thật; lần agent bị Npcap từ chối là lịch sử riêng. Chưa có số đo attack lab/Linux, parity thật, Recall host/C2 hoặc Word cuối để nghiệm thu các mục tương ứng.
