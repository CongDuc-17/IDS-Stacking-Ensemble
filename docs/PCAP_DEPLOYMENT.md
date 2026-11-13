# Kiểm thử các model PCAP trên Kali

PCAP-Combined học từ flow trích bằng cùng `FlowTable` dùng trong detector. `MODEL_CARD.json` ghi các lớp có trong model và cấu hình extractor. Thông số capture của bản này gồm idle 10 giây, max-age 60 giây và tối đa 10.000 flow đang mở.

## Cài và kiểm tra môi trường

Chép `ids-vm-pcap-models-seed42.zip` vào `~/Downloads` bằng thư mục chia sẻ hoặc SCP trong lab. Dùng thư mục giải nén mới cho từng bản chạy.

```bash
cd ~
unzip ~/Downloads/ids-vm-pcap-models-seed42.zip
cd ~/ids-vm-pcap-models-seed42
sha256sum -c SHA256SUMS
```

Dùng Python ghi trong `MODEL_CARD.json`. Với `uv` đã cài, tạo môi trường và kiểm tra dự đoán trên cả hai nguồn.

```bash
py_version=$(python3 -c 'import json; print(json.load(open("MODEL_CARD.json"))["python_version"])')
uv venv --python "$py_version" .venv
uv pip install --python .venv/bin/python -r requirements-vm.in
for source in cicids2017 insdn; do
  .venv/bin/python src/check_model.py --model models/stacking_ids.joblib --csv "smoke/$source.csv"
done
for model in PCAP-CIC PCAP-InSDN; do
  .venv/bin/python src/check_model.py --model "models/$model.joblib" --csv "smoke/$model.csv"
done
```

`models/stacking_ids.joblib` là PCAP-Combined. Để kiểm thử PCAP-CIC hoặc PCAP-InSDN, đổi đường dẫn `--model` trong các lệnh bên dưới thành `models/PCAP-CIC.joblib` hoặc `models/PCAP-InSDN.joblib`, và dùng thư mục log riêng cho mỗi lần chạy.

## Bắt lưu lượng thật

Xác nhận IP và interface bằng `ip -br -4 addr`. Ví dụ trước đây dùng `eth1`, Windows `192.168.230.1` và Kali `192.168.230.130`.

```bash
out="logs/pcap-combined-live-$(date +%Y%m%d-%H%M%S)"
sudo .venv/bin/python src/detect.py --model models/stacking_ids.joblib --iface eth1 \
  --capture-filter 'host 192.168.230.1 and host 192.168.230.130' --out "$out"
```

Chạy các kịch bản B01 HTTP, A01 quét cổng và ca DoS có giới hạn trong mạng Host-only, lưu mỗi ca một PCAP. Với detector live, chờ flow đóng rồi xem `predictions.jsonl`. Ghi lại thời gian từ gói đầu tới kết quả, số flow, eviction và số gói bị bỏ tại hàng đợi. Có thể dùng `ps` hoặc `pidstat -r -u` với PID detector để đo CPU và RAM trong lúc thử.

## Chấm cùng một PCAP với hai model

Ví dụ với một capture chỉ có traffic HTTP bình thường đã xác minh:

```bash
pcap=captures/B01-new.pcap
.venv/bin/python src/extract.py --pcap "$pcap" --out captures/B01-new-truth.csv --label BENIGN
.venv/bin/python src/detect.py --model models/stacking_ids.joblib --pcap "$pcap" --out logs/pcap-combined-B01
.venv/bin/python src/evaluate_lab.py --model models/stacking_ids.joblib \
  --predictions logs/pcap-combined-B01/predictions.jsonl --truth captures/B01-new-truth.csv \
  --out logs/pcap-combined-B01/metrics.json
```

Lặp lại bằng model M3 CSV cũ trong thư mục của bản đó và dùng cùng PCAP, nhãn thật và timeout. Đối chiếu FPR, tỷ lệ bỏ sót và nhóm dự đoán. Với ca A01 đã xác minh, gán `RECON` khi tạo truth. Kết quả replay đo suy luận offline, còn độ trễ từ gói đầu tới cảnh báo lấy từ log live.

## Tái tạo ba model trong repo

Chạy từ thư mục gốc của repo. Lệnh đọc các PCAP và CSV tham chiếu theo `configs/pcap_sessions_20261112.json`. Thêm `--reuse-extracted` khi có các flow CSV đúng đường dẫn và phiên bản extractor ghi trong kế hoạch.

```powershell
.\.venv\Scripts\python.exe src/pcap_experiments.py --plan configs/pcap_sessions_20261112.json --out experiments/pcap-rebuild --seed 42 --folds 2 --trees 60 --max-per-class 2000
.\.venv\Scripts\python.exe src/package_vm.py --run experiments/pcap-rebuild --out deliverables/ids-vm-pcap-models-seed42.zip
```

Ba thư mục model là `PCAP-CIC`, `PCAP-InSDN` và `PCAP-Combined`. Dùng `label_audit.csv` để kiểm tra số flow được gán nhãn theo phiên, `protocol.json` để xem các phiên thuộc từng tập, và `comparison_all.csv` để đối chiếu các thuật toán trên cùng test. `eda/` chứa thống kê và biểu đồ cho từng nguồn. Đổi `--out` khi chạy lại để giữ đầy đủ kết quả của từng lần.
