# Kết quả đã chạy và giới hạn

Ngày thực hiện: 07/11/2026. Các số dưới đây lấy từ file kết quả thật của project, không phải kết quả ví dụ hoặc số lấy từ bài báo.

## Dữ liệu và giao thức

Đã đọc tám CSV CIC-IDS2017, tổng **2.830.743 hàng**, 15 nhãn thô. BENIGN có 2.273.097 hàng. Bộ 12 feature hiện dùng không có missing/Inf trong dữ liệu gốc này; điều đó không có nghĩa mọi cột của dataset đều sạch.

Mỗi lượt dùng random-priority sampling tối đa 2.000 hàng/lớp trước khử trùng, seed 7/21/42, 60 cây cho các ensemble, 3-fold CV chọn hai giá trị tham số mỗi baseline. Test chiếm 20%; validation chiếm 20%; các mô hình cuối fit trên 80% development data. Hai cấu hình Stacking được chọn bằng validation, không chọn bằng test. Cùng feature/split cuối được dùng cho mọi mô hình trong từng lượt.

Ở seed 42, mẫu sau xử lý có 19.561 hàng, 14 lớp; Heartbleed 11 mẫu bị loại vì dưới mức tối thiểu 15. Loại 155 hàng có cùng feature nhưng mâu thuẫn nhãn và 2.466 hàng trùng feature trong mẫu. Test có 3.913 hàng; SQL Injection chỉ 3 hàng, Infiltration 7 hàng. Mẫu đã thay đổi tỷ lệ lớp; đây là kết quả tham khảo từ random split, không phải test theo phiên/traffic tự nhiên.

## Trung bình ba seed

Đơn vị %, trung bình ± SD mẫu giữa ba seed. SD này không phải khoảng tin cậy cho traffic thực tế.

| Mô hình | Accuracy | Macro-F1 |
|---|---:|---:|
| DT | 94,86 ± 0,26 | 90,54 ± 1,62 |
| RF | 94,87 ± 0,38 | **90,61 ± 0,68** |
| XGBoost | **96,05 ± 0,32** | 90,27 ± 2,38 |
| LightGBM | 94,54 ± 2,56 | 84,10 ± 2,35 |
| Logistic Regression | 62,06 ± 11,54 | 56,26 ± 10,21 |
| Stacking chọn bằng validation | 94,70 ± 0,41 | 87,57 ± 0,95 |

Chi tiết có tại `experiments/cicids2017-summary/all_seeds.csv` và `mean_std.csv`. Mean Macro-F1 Stacking thấp hơn RF khoảng **3,04 điểm phần trăm**; chưa có cơ sở kết luận Stacking cải thiện so với baseline.

| Seed | Stack được chọn | Baseline Macro-F1 cao nhất trên test (chỉ mô tả) | Delta Macro-F1 stack − baseline |
|---|---|---|---:|
| 7 | Trees | RF | −1,61 điểm % |
| 21 | Trees | DT | −5,66 điểm % |
| 42 | Diverse | XGBoost | −4,14 điểm % |

Việc gọi tên “baseline cao nhất trên test” ở bảng này chỉ mô tả kết quả sau thực nghiệm, không phải quy tắc chọn mô hình trước test. Cả ba seed được giữ, không loại lượt thua. Hai lượt seed 7/21 có thêm báo cáo binary detection suy từ đầu ra đa lớp; seed 42 ban đầu chỉ có FPR/FNR và báo cáo đa lớp. Không tạo lại kết quả cũ bằng số giả để đồng nhất hình thức.

Nguyên nhân khả dĩ: 12 flow features thiếu tín hiệu phân biệt các web attack; meta-learner balanced đánh đổi Precision/Recall ở lớp hiếm; các cây có lỗi tương quan. Đây là giả thuyết cần ablation, không phải kết luận nhân quả đã kiểm chứng.

## Những kiểm tra đã hoàn thành

- 9 test unittest: schema/sampling tái lập, nhãn mâu thuẫn, independent-holdout overlap, Inf, flow hai chiều/byte/flags, idle/max-age, capacity, smoke mismatch, queue drop/drain, ghép ground truth và CLI PCAP dùng cùng extractor.
- Smoke test model seed 42 với 100 hàng xuất kèm: dự đoán khớp 100% trên môi trường Windows hiện tại. Đây là kiểm tra tái lập, không phải độ chính xác 100% và chưa phải smoke test Windows → Kali.
- PCAP tổng hợp ba gói được xử lý thành hai flow; chạy qua extractor và model thật để kiểm tra đường CLI. Dữ liệu này chỉ dùng self-check, không dùng để tuyên bố Recall/Accuracy trên attack thật.
- Đã chạy EDA với số đếm thô trên toàn dataset và biểu đồ từ mẫu có giới hạn.

Python 3.14.6; các phiên bản model deploy được pin trong từng thư mục `models/requirements-deploy.txt`. Không thay các file kết quả cũ trong `results/` hoặc model cũ trong `models/`.

## Những phần chưa đạt

1. **Hai dataset có kết quả đầy đủ:** mới chạy CIC-IDS2017. InSDN chưa có CSV thật; trang tải UCD không truy cập được từ phiên làm việc. Mã ánh xạ cột chỉ mới kiểm tra bằng fixture tổng hợp, chưa xác minh trên toàn InSDN thật.
2. **Stacking vượt baseline:** cả ba lượt hiện tại chưa đạt. Cần nghiên cứu thêm bằng development data và một holdout độc lập nếu dùng kết quả test đã xem để quyết định cải tiến.
3. **Chạy và đo trên Kali:** chưa có phiên kết nối VM, chưa bắt traffic thật, chưa có FPR/FNR/độ trễ lab hoặc số đo queue/NIC drops thật.
4. **Parity:** dùng chung extractor Scapy giúp PCAP/live nhất quán với nhau; chưa chứng minh Scapy tương đương CICFlowMeter của dữ liệu huấn luyện.
5. **Nghiệm thu đề tài:** chưa thể tuyên bố hoàn thành các mục 1–4 chỉ bằng model đã serialize hoặc ảnh cảnh báo.
