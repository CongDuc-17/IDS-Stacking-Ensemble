# Phạm vi nghiệm thu Ensemble Stacking

Căn cứ chính là ghi chú cho đề tài ES: hai dataset, EDA, baseline, chọn mô hình mở rộng và so sánh trên cùng test. Hướng dẫn CNN là khung tham khảo cho quy trình; không tự biến Gaussian, graph centralized/P2P, beaconing, dashboard hoặc firewall thành các tầng bắt buộc của Stacking.

## Phần nghiên cứu chính

- CIC-IDS2017 và InSDN; kiểm tra schema/nhãn, EDA và cleanup.
- Baseline DT, RF, XGBoost, LightGBM, LR, chọn tham số bằng CV trên train.
- Hai nhóm base learner và Logistic Regression meta learner; tạo OOF đúng fold, chọn cấu hình bằng validation, refit development rồi báo test.
- Bảng metrics cùng test, support từng lớp, confusion, FPR/FNR và phân tích lỗi; đủ ba seed, giữ các lượt thất bại.
- M1/M2/M3 nhị phân là thí nghiệm nguồn dữ liệu; hai mô hình đa lớp riêng phục vụ nhận diện subtype. Không gộp taxonomy khác nhau rồi gọi là mô hình đa lớp chung.

## Tìm kiếm meta learner đa lớp

Trước đây meta learner cố định C=1 và class_weight=balanced. Cờ `--stack-search` thử C=0,1/1/10 và weight=None/balanced cho cả hai nhóm base learner. Tổng cộng 12 ứng viên. Không đổi ngân sách tuning baseline để làm baseline yếu đi.

OOF chỉ tạo trên train cho RF/XGB/LightGBM/LR, cache vào stack_oof.npz và dùng chung giữa các ứng viên. Xác suất validation đến từ base learner đã fit trên train. Chọn bằng Macro-F1 validation; test không tham gia. Cấu hình cuối được fit lại bằng StackingClassifier trên train+validation, với quy tắc bỏ cột xác suất đầu ở bài toán nhị phân giống khi chọn cấu hình.

Đây vẫn chưa phải nested CV hoàn chỉnh vì tham số base learner đã chọn bằng CV trên toàn train. Các test đã được xem ở giai đoạn phát triển, nên các lượt mới là phân tích bổ sung, không phải xác nhận độc lập mới. Không bảo đảm ES sẽ thắng baseline.

```powershell
foreach ($taskSeed in @(7,21,42)) {
  .\.venv\Scripts\python.exe src/train.py --data data/MachineLearningCVE --dataset CIC-IDS2017 --out "experiments/multiclass-cic-search-$taskSeed-new" --max-per-class 2000 --trees 60 --folds 3 --seed $taskSeed --tune --stack-search
}
```

Đổi data thành `data/InSDN(2020)` và dataset thành InSDN để chạy nguồn còn lại. Không có `--binary` là thí nghiệm đa lớp. `train_all.py --combined --stack-search` cũng hỗ trợ tìm meta learner cho protocol M1/M2/M3; cờ mặc định tắt để giữ cách chạy cũ. Summarize từ chối trộn lượt bật/tắt search.

Các lượt mới của cả hai nguồn nằm trong `experiments/completion-20261110/multiclass-search-*-seed*`. Mỗi lượt lưu ba CSV split để đánh giá lại toàn test bằng model đã lưu, selection của đủ 12 ứng viên, OOF cache, predictions và báo cáo từng lớp.

## Notebook huấn luyện

`notebooks/training_combined.ipynb` dành riêng cho huấn luyện kết hợp hai nguồn: gọi run_three_models, chạy M1/M2/M3 và đối chiếu số hàng, hash test chung, baseline/Stacking và ba confusion matrix M3. DO_TRAIN mặc định False; bật True và OUT mới để train thật. Bài toán gộp là nhị phân, không tự tạo taxonomy đa lớp.

`notebooks/training.ipynb` hướng dẫn từng bước đọc/làm sạch, chia tập, tuning/OOF/refit và xem metrics. Nó gọi trực tiếp các hàm trong src; không sao chép thuật toán. Mặc định DO_TRAIN=False để xem artifact; muốn train thì đổi True, chọn DATASET và OUT mới, Restart Kernel rồi Run All. `notebooks/experiment.ipynb` tiếp tục là notebook tổng hợp kết quả.

## Phần ứng dụng/demo

Demo hợp lý cho ES: capture/PCAP → feature → Stacking → nhãn và log → đánh giá với nhãn độc lập. Linux cần chạy thật nếu nằm trong phạm vi đã thống nhất với giảng viên. Một phiên Windows BENIGN không thay thế 2–3 kịch bản attack có PCAP/ground truth hoặc số đo Kali.

Windows của người dùng đã capture HTTP localhost thành công; log có các flow BENIGN sau khi mở PowerShell Administrator. Lần agent thử trước đó bị Admin-only Mode từ chối vẫn giữ nguyên như một lần thất bại lịch sử. Chưa có kết quả attack lab, parity hai extractor hoặc số đo Linux để kết luận độ chính xác live.

Gaussian, beaconing và graph được giữ làm thí nghiệm bổ sung. Gaussian đang bỏ sót nhiều attack nên chưa dùng như bộ lọc bắt buộc trước ES. Mục tiêu ES vượt baseline chỉ được đánh dấu đạt trên đúng bài toán/metric/test có bằng chứng; không thay kết quả đa lớp bằng điểm nhị phân.
