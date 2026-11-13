> Cập nhật đường dẫn model ngày 10/11/2026: hướng dẫn dùng M3 đã chạy; xem EXTENSIONS.md và CURRENT_RESULTS.md. Chưa có kết quả đo VM thật trong phiên này.

# Thử nghiệm trên Kali của bạn

Nếu mới bắt đầu chuyển model từ Windows sang VM, làm theo [VM_DEPLOYMENT.md](VM_DEPLOYMENT.md) trước; tài liệu đó dùng gói M3 gọn và có hai smoke test.

Chương trình đã có; hướng dẫn này cần chạy trên VM thật. Chưa có kết quả live trong phiên triển khai hiện tại. Không thay đổi cấu hình mạng/firewall của máy cá nhân tự động.

## 1. Mạng và vị trí sensor

Cấu hình đơn giản: Windows thật và Kali VM cùng mạng **Host-only**. Kali vừa là máy được kiểm thử vừa chạy detector; Windows gửi traffic thử nghiệm vào Kali. Nếu cần Internet để cài package, dùng adapter NAT riêng để cài, còn thử nghiệm dùng adapter Host-only. Các địa chỉ bên dưới là ví dụ mạng lab, phải thay bằng địa chỉ thật.

```bash
ip -br addr
ip route
python3 --version
```

Ghi lại interface Host-only và IP Kali, ví dụ `eth1`, `192.168.56.101`; IP Windows ví dụ `192.168.56.1`. Sensor chỉ thấy traffic đi qua interface được chọn. Kali ở chế độ NAT không tự thấy toàn bộ traffic Windows hoặc toàn mạng. Không dùng mạng công cộng cho các kịch bản kiểm thử.

## 2. Chuyển và kiểm tra model

Chép nguyên project đã đóng gói vào `~/network-stacking-ids/`. Không cần chép tám CSV gốc để chạy dự đoán. Thư mục `experiments/completion-20261110/multiclass-families-seed42/M3/models` và `smoke_test.csv` phải đi cùng nhau.

```bash
cd ~/network-stacking-ids
```

Model đi kèm được train bằng Python 3.14.6. Nếu Kali có cùng Python, tạo venv bằng Python đó. Nếu chưa có, cài uv theo [hướng dẫn chính thức](https://docs.astral.sh/uv/getting-started/installation/), rồi:

```bash
uv python install 3.14.6
uv venv --python 3.14.6 .venv
uv pip install --python .venv/bin/python -r requirements-lab.in -r experiments/completion-20261110/multiclass-families-seed42/M3/models/requirements-deploy.txt
.venv/bin/python src/detect.py \
  --model experiments/completion-20261110/multiclass-families-seed42/M3/models/stacking_ids.joblib \
  --csv experiments/completion-20261110/multiclass-families-seed42/M3/cicids2017/smoke_test.csv
```

Phải có `Prediction match: 100.00%`. Nếu package pin không cài được trên nền tảng Kali, tạo môi trường tương thích trên cả Windows và Kali rồi train lại; không ép load model với phiên bản scikit-learn khác. Không cần cài Jupyter/matplotlib chỉ để suy luận.

## 3. Giám sát

Ví dụ dùng `eth1`; thay bằng interface đã xác minh. Cần quyền capture và libpcap (trên Kali thường đã có; nếu thiếu, cài `libpcap0.8`/gói libpcap phù hợp bằng apt).

```bash
sudo "$(pwd)/.venv/bin/python" src/detect.py \
  --model experiments/completion-20261110/multiclass-families-seed42/M3/models/stacking_ids.joblib \
  --iface eth1 --capture-filter 'host 192.168.56.1' --out logs/run01 --idle 10 --max-age 60 --max-flows 10000
```

Mở terminal Kali khác để lưu PCAP của cùng interface:

```bash
mkdir -p captures
sudo tcpdump -i eth1 -nn -s 0 -w captures/run01.pcap 'host 192.168.56.1 and (tcp or udp)'
```

Filter PCAP và detector phải quan sát cùng phạm vi khi đối chiếu. `--capture-filter` bổ sung BPF trong phạm vi IPv4 TCP/UDP; thay IP Windows đúng ở cả hai lệnh. Cô lập mạng lab và ghi rõ các flow không khớp, không tính traffic ngoài kịch bản thành nhãn đã xác minh.

Chờ tối thiểu idle timeout sau mỗi kịch bản, rồi Ctrl+C. Flow dài có thể phải chờ max-age; vì vậy “realtime” ở đây là phát hiện khi cửa sổ/flow được chốt, không phải mỗi gói lập tức có nhãn.

## 4. Ba kịch bản có kiểm soát

### A. Traffic bình thường

Trên Kali, dùng thư mục trống chứa file demo để mở HTTP server thử nghiệm:

```bash
mkdir -p lab-www
cd lab-www
python3 -m http.server 8080 --bind 192.168.56.101
```

Trên Windows dùng trình duyệt hoặc `curl.exe http://192.168.56.101:8080/`. Thử nhiều phiên cách nhau hơn idle timeout; giữ PCAP và thời gian bắt đầu/kết thúc. Đây là nhãn BENIGN từ hành động đã biết, không phụ thuộc nhãn dự đoán. Đo FPR trên traffic bình thường đa dạng hơn nếu muốn kết luận thực tế.

### B. Port scan

Nếu Windows đã có Nmap, dùng đúng IP Kali thuộc mạng lab:

```powershell
nmap -sT -p 1-1000 --max-rate 50 192.168.56.101
```

Chương trình cần ghi dự đoán cho các flow liên quan. Không bảo đảm model học từ CIC sẽ nhận đúng scan lab; phải đo thực tế. Phân loại `PortScan` theo từng flow cũng có giới hạn vì chưa có đặc trưng tổng hợp số cổng unique theo host.

### C. SYN load giới hạn (khi có máy gửi Linux trong lab)

Nếu có máy Linux thứ hai làm máy gửi, có thể dùng thử nghiệm nhỏ, hữu hạn:

```bash
sudo hping3 -S -p 8080 -c 300 -i u10000 192.168.56.101
```

Đây là tải SYN khoảng 100 gói/giây trong khoảng 3 giây, **không tự tương đương DDoS**. CIC-IDS2017 không có nhãn SYN flood tổng quát phù hợp trực tiếp; đánh giá phát hiện nhị phân và độ trễ, không gán cứng thành `DoS Hulk` hay `DDoS`. Không cần kịch bản C nếu chỉ có Windows + Kali: hoàn thành A và B trước, sau đó bổ sung capture tấn công có nhãn chuẩn để đánh giá đa lớp.

Không dùng ping flood để minh họa detector hiện tại vì ICMP chưa được hỗ trợ. Beaconing và botnet graph hiện phân tích CSV offline theo WINDOWS_VALIDATION.md/EXTENSIONS.md, chưa xác nhận C2 hay tích hợp vào detector live.

## 5. Gán nhãn và đánh giá

Trích flow từ PCAP bằng đúng timeout như detector:

```bash
.venv/bin/python src/extract.py --pcap captures/run01.pcap \
  --out captures/run01-truth.csv --idle 10 --max-age 60
```

Thêm cột `Label` vào CSV, gán nhãn theo kịch bản, endpoint và khoảng thời gian thật. Không gán nhãn bằng output của model. Nếu capture chỉ gồm một loại traffic đã xác minh, có thể dùng `--label BENIGN` hoặc `--label RECON` cho M3 9 nhóm khi extract; không gán mọi flow trong capture hỗn hợp là attack.

Tool đánh giá chuẩn hóa khoảng trắng và BENIGN/Normal/ATTACK không phân biệt hoa thường; từ chối nhãn rỗng, thiếu hoặc UNKNOWN. Mỗi lượt detector dùng `--out` mới: nếu `predictions.jsonl` đã tồn tại, chương trình báo lỗi để giữ riêng log của từng lượt.

Với nhãn CIC gốc như PortScan, thêm `--truth-source cicids2017` để đổi sang RECON theo taxonomy model. Đối với lớp lab chưa tồn tại trong model, như `SYN-LAB`, thêm `--binary-only` để chỉ báo cáo binary detection; điểm phân loại chi tiết vào các lớp dataset không có ý nghĩa tương ứng. Chạy:

```bash
.venv/bin/python src/evaluate_lab.py \
  --model experiments/completion-20261110/multiclass-families-seed42/M3/models/stacking_ids.joblib \
  --predictions logs/run01/predictions.jsonl \
  --truth captures/run01-truth.csv --out logs/run01/lab-metrics.json
```

Việc ghép đòi hỏi endpoint, protocol và timestamp gói đầu khớp đến microsecond; khác timeout, capture mất gói, bắt đầu giữa phiên hoặc khác hướng có thể khiến không ghép được. Tool không âm thầm bỏ qua: ghi số flow thiếu prediction/thiếu truth, và metrics chỉ áp dụng cho các flow đã ghép. File truth chứa flow một-một, không phải bảng thời gian kịch bản chung.

Ghi p50/p95 `inference_ms`, `observed_first_packet_to_result_seconds`, FPR, FNR, số flow, queue drops và capacity evictions. Log dùng `src_ip` cho phía gửi gói đầu quan sát, không phải kết luận quy trách nhiệm tấn công. Các file log chứa địa chỉ mạng lab nên cần xem lại trước khi đưa vào báo cáo công khai.

## 6. Điều kiện kết luận triển khai

- Smoke test qua máy khớp 100%.
- PCAP/live dùng cùng extractor, timeout và phạm vi traffic.
- Đã chứng minh tương đương feature với dataset hoặc train lại bằng extractor lab và chia test theo phiên độc lập.
- Có BENIGN và attack thật để tính FPR/FNR, không chỉ ảnh chụp vài cảnh báo.
- Báo cáo mẫu bị bỏ/mất gói, flow eviction, latency có cả thời gian chờ flow.

Nếu thiếu các điều kiện này, mô tả kết quả là **PoC pipeline chạy được**, chưa phải IDS đã được xác nhận độ chính xác ngoài thực tế.
