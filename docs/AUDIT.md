# Audit mã nguồn ban đầu

**What this repo does:** Project đọc mẫu flow CIC-IDS2017, so sánh RF/XGBoost/LightGBM với Stacking, lưu model rồi dự đoán từ CSV hoặc traffic Scapy trên Kali. Giả định vận hành: một người làm đồ án trên máy cá nhân và một VM, không phải IDS cho đường truyền doanh nghiệp.

Đã đọc toàn bộ README, requirements, `.gitignore`, ba module Python ban đầu, feature contract, comparison và các report/model metadata hiện có. Báo cáo này mô tả bản trước thay đổi; việc sửa mã là phần triển khai riêng theo yêu cầu người dùng. Các tên hàm bên dưới chỉ vị trí trong bản đầu, không phải số dòng của bản mới.

## Must fix

1. **Đặc trưng Scapy chưa tương đương CICFlowMeter** (`src/features.py`; `src/detect.py: FlowDetector.process/flush_expired`).
   - **What this is:** Model học byte, hướng và ranh giới flow từ CSV của CICFlowMeter; live dùng cách gom flow và payload của Scapy.
   - **Problem:** Một phiên TCP có thể tạo vector khác nhau dù có cùng tên cột. Smoke test CSV không kiểm tra vấn đề này; nhãn live có thể sai dù Accuracy offline cao.
   - **Fix:** So sánh cùng PCAP qua hai extractor theo flow và feature, hoặc thu thập lab có nhãn rồi train lại bằng chính extractor live. Bản mới chỉ dùng chung Scapy cho PCAP/live và gắn cờ thử nghiệm; chưa có bằng chứng parity với CICFlowMeter.
   - **If we skip it:** Không thể bảo vệ tuyên bố độ chính xác realtime. **Còn mở, chặn kết luận triển khai chính thức.**

2. **Lấy tối đa 350 hàng mỗi chunk làm lệch xác suất lấy mẫu** (`src/train.py: read_sample`).
   - **What this is:** Mỗi nhóm nhãn trong một chunk được lấy tối đa 350 hàng, các mẫu được giữ trong list rồi mới cap toàn cục.
   - **Problem:** Cùng một lớp có 500 hàng ở chunk A và 50.000 hàng ở chunk B thì xác suất vào mẫu bước đầu lần lượt là 70% và 0,7%. List còn tăng theo số chunk trước khi áp dụng giới hạn cuối.
   - **Fix:** Random-priority reservoir theo lớp, giới hạn sau từng chunk; lưu phân bố thô và mẫu. **Đã sửa trong `src/dataset.py`, có test tính tái lập và metadata.**
   - **If we skip it:** Kết quả phụ thuộc cách chia file/chunk và có thể thiếu RAM trên dataset lớn.

3. **Capture dừng trong lúc xử lý dự đoán** (`src/detect.py: main`, vòng `sniff(timeout=2)` rồi `flush_expired`).
   - **What this is:** Chương trình mở capture theo từng đợt, dừng capture rồi dự đoán từng flow hết hạn.
   - **Problem:** Với nhiều flow kết thúc cùng lúc, thời gian suy luận nằm ngoài khoảng capture. Traffic tới trong khoảng đó không được quan sát bởi phiên capture mới.
   - **Fix:** AsyncSniffer liên tục đẩy vào queue có giới hạn, main thread xử lý; đếm queue drops. **Đã sửa và kiểm thử queue bằng sniffer giả, chưa đo NIC/kernel drops thật.**
   - **If we skip it:** Bỏ sót lưu lượng đúng lúc tải tăng và số liệu phát hiện lab không có độ bao phủ rõ ràng.

4. **Gói mới nối vào flow đã hết hạn** (`src/detect.py: process` gọi trước `flush_expired`).
   - **What this is:** Gói cập nhật `last` trước khi kiểm tra idle timeout.
   - **Problem:** Hai gói cùng 5-tuple tại t=100 và t=120, idle=10, có thể bị gộp vào một flow vì `last` đã thành 120. Cùng PCAP sẽ bị chia flow sai.
   - **Fix:** Kiểm tra timeout trước khi thêm gói của key đó. **Đã sửa trong `src/flows.py`, có test idle và max-age.**
   - **If we skip it:** Duration, số gói và nhãn dự đoán phụ thuộc sai vào thứ tự expire.

5. **Không giới hạn số flow đang mở** (`src/detect.py: FlowDetector.flows`).
   - **What this is:** Một dict giữ trạng thái mọi flow chưa hết hạn.
   - **Problem:** Lưu lượng nhiều source port/5-tuple mới trong thử nghiệm scan/SYN làm trạng thái tăng đến kỳ expire, không có giới hạn cứng phù hợp RAM máy cá nhân.
   - **Fix:** Giới hạn `--max-flows`; khi đầy, đóng flow tạo sớm nhất và ghi `capacity`. Giới hạn cả queue capture. **Đã sửa; có test eviction, chưa đo throughput thật.**
   - **If we skip it:** Mất RAM hoặc tiến trình bị dừng; với bản mới, eviction vẫn làm thay đổi flow và phải được báo cáo.

6. **Smoke test sai vẫn có thể trả exit code thành công; Inf không được xử lý như training** (`src/detect.py: csv_smoke`).
   - **What this is:** Hàm chỉ in cảnh báo khi dự đoán khác Windows; đầu vào numeric vẫn có thể chứa Inf.
   - **Problem:** Script triển khai tự động có thể báo thành công dù model/thư viện không khớp; CSV Inf có thể làm imputer/model lỗi dù training đã thay Inf bằng NaN.
   - **Fix:** Dùng chung chuẩn hóa numeric, dừng bằng lỗi khi mismatch, kiểm tra mapping nhãn và cột xác suất. **Đã sửa; test âm cố ý mismatch phải thất bại.**
   - **If we skip it:** Kiểm tra chuyển máy không đáng tin và CSV hợp lệ theo quy tắc train có thể không suy luận được.

## Should fix

7. **Thiếu dấu vết chọn mô hình và điều kiện tái lập** (`src/train.py: main`; `results/comparison.json`).
   - **What this is:** Chỉ có một split 80/20, tham số cố định; không lưu manifest sampling, lớp bị bỏ, split và điểm chọn cấu hình.
   - **Problem:** Kết quả cũ không chứng minh đã chọn tham số hoặc đã hoàn thành yêu cầu hai dataset; không thể giải thích đủ phân bố sau lấy mẫu. Stacking cũ có Accuracy cao hơn RF nhưng Macro-F1 thấp hơn.
   - **Fix:** Train/validation/test, CV chọn baseline, validation chọn stack, manifest và bảng kết quả mỗi run; EDA độc lập. **Đã thêm và chạy CIC trên ba seed. InSDN còn thiếu dữ liệu.**
   - **If we skip it:** Dễ chọn mô hình theo test hoặc kết luận “tốt hơn” chỉ từ Accuracy.

8. **Chỉ ghi cảnh báo nên không đủ dữ liệu đánh giá lab** (`src/detect.py: flush_expired`).
   - **What this is:** Flow được dự đoán BENIGN không được ghi log.
   - **Problem:** Khi một flow tấn công bị dự đoán BENIGN, không có bản ghi để ghép với ground truth và đếm false negative. Timestamp gói cuối cũng không cho biết thời điểm chương trình trả kết quả.
   - **Fix:** Ghi mọi dự đoán, mốc flow/cảnh báo, thời gian suy luận; thêm bộ ghép nhãn lab có kiểm tra một-một. **Đã sửa, có test FNR và flow không khớp nhãn.**
   - **If we skip it:** Không đủ cơ sở tính Recall/FPR/độ trễ từ log cảnh báo.

9. **Logic flow không có kiểm thử** (`src/detect.py`, bản đầu không có thư mục tests).
   - **What this is:** Gom flow hai chiều, flag, timeout, I/O và model output nằm trên đường suy luận chính.
   - **Problem:** Thay đổi hướng gói hoặc timeout dễ làm sai đặc trưng mà không gây crash; smoke CSV không đi qua đường PCAP này.
   - **Fix:** Test số gói hai chiều, payload, cờ, timeout, giới hạn, smoke mismatch và ghép ground truth; chạy PCAP tổng hợp qua CLI. **Đã bổ sung unit tests; kết quả thực thi ghi trong `docs/RESULTS.md`.**
   - **If we skip it:** Những sai khác nhỏ của extractor có thể bị nhầm thành hành vi mô hình.

## Nice to have

10. **Cài seaborn dù không dùng** (`requirements.in`, toàn bộ `src/` ban đầu).
    - **What this is:** Seaborn nằm trong danh sách package cần cài.
    - **Problem:** Không module/entry point nào import hoặc gọi thư viện này; cài thêm một dependency không phục vụ luồng hiện tại.
    - **Fix:** Bỏ dòng seaborn, dùng matplotlib vốn đã có cho EDA. **Đã bỏ khỏi requirements; không gỡ package đã cài trong môi trường người dùng.**
    - **If we skip it:** Tốn thêm cài đặt và quản lý phiên bản mà không thêm chức năng.

**Verdict:** Có nền tảng PoC phù hợp để tiếp tục; ưu tiên dữ liệu thứ hai và kiểm chứng đặc trưng/đánh giá Kali trước khi tuyên bố hoàn thành đề tài. Không phát hiện căn cứ cần thêm web framework, dashboard hay firewall tự động vào phần lõi.

**Lean:** Bỏ được 1 dòng dependency và 1 dependency trực tiếp (seaborn); không có căn cứ định lượng để hứa giảm thêm mã nguồn.

**Not checked:** Nội dung pickle/joblib cũ không được load trong audit; chưa kiểm tra đủ mọi hàng/cột gốc, PCAP chuẩn, InSDN thật, quyền capture trên Kali, throughput/NIC drops, phiên lab độc lập, hay hiệu quả zero-day. Mẫu test tổng hợp không chứng minh độ chính xác phát hiện mạng thật.
