# Đưa M3 lên máy ảo Kali Linux

Hướng dẫn cho Windows làm host, Kali Linux x86_64 làm VM. Dùng model M3 seed 42 đã học cả CIC-IDS2017 và InSDN, phân loại **BENIGN / ATTACK**. Không cần train lại hoặc chuyển CSV gốc sang VM. Gói này phục vụ chạy suy luận; notebook và toàn bộ kết quả nghiên cứu vẫn ở project chính.

## 1. Chuẩn bị máy ảo và mạng

Gợi ý cấu hình cho demo nhỏ: 2 vCPU, RAM 4 GB, ổ đĩa trống khoảng 20 GB. Đây là cấu hình khởi đầu, chưa phải số đo capacity của detector.

Tắt VM trước khi đổi adapter. Trong VirtualBox, vào Settings → Network:

| Adapter | Chế độ | Mục đích |
|---|---|---|
| 1 | NAT | Tải Python và thư viện |
| 2 | Host-only Adapter | Windows giao tiếp với Kali trong lab |

Nếu chưa có Host-only, tạo trong Tools → Network/Network Manager và bật DHCP. Với VMware, cấu hình tương đương là một adapter NAT và một adapter Host-only; tên interface/IP có thể khác.

Khởi động Kali và kiểm tra:

```bash
ip -br -4 addr
ip route
uname -m
```

Chọn địa chỉ IPv4 của adapter Host-only, không chọn địa chỉ NAT. Ví dụ xuyên suốt tài liệu: Windows `192.168.56.1`, Kali `192.168.56.101`, interface Kali `eth1`. **Thay các giá trị ví dụ bằng kết quả thật của bạn.** Windows xem adapter Host-only bằng `ipconfig`.

Sensor chỉ quan sát traffic đi qua interface đã chọn. Với cấu hình này, demo traffic Windows ↔ Kali; Kali không tự quan sát mọi traffic của Windows hay các máy khác. Thử nghiệm scan chỉ nhắm IP máy Kali thuộc lab của bạn.

## 2. Chuyển gói triển khai sang Kali

File được chuẩn bị ở project Windows:

`deliverables/ids-vm-m3-20261110.zip`

Gói chứa script suy luận/trích flow/đánh giá và beaconing offline, model M3, phiên bản thư viện, protocol/selection, hai CSV smoke và hai test CSV có nhãn để đánh giá lại. Không chứa dữ liệu huấn luyện gốc hay `.venv` Windows.

Dùng Shared Folder hoặc kéo thả file ZIP sang `~/Downloads/` trong Kali. Cách dự phòng khi chia sẻ file chưa hoạt động: trong PowerShell Windows, mở terminal riêng:

```powershell
Set-Location 'D:\Downloads\network-stacking-ids-20261107\network-stacking-ids\deliverables'
python -m http.server 8000 --bind 192.168.56.1
```

Chỉ bind địa chỉ Host-only thật của Windows. Trên Kali:

```bash
mkdir -p ~/Downloads
curl -f http://192.168.56.1:8000/ids-vm-m3-20261110.zip \
  -o ~/Downloads/ids-vm-m3-20261110.zip
```

Nếu Windows hỏi quyền firewall, chỉ cho phép kết nối lab tương ứng; không tắt toàn bộ firewall. Dừng server bằng Ctrl+C sau khi tải. Nếu dùng Shared Folder, không cần mở server HTTP này.

## 3. Giải nén và cài môi trường

Các lệnh dưới đây chạy bằng tài khoản Kali thường; chỉ `apt` và bắt gói tin cần `sudo`.

```bash
sudo apt update
sudo apt install -y curl unzip tcpdump libpcap-dev libgomp1

mkdir -p ~/ids-lab
cd ~/ids-lab
unzip ~/Downloads/ids-vm-m3-20261110.zip
cd ids-vm-m3
sha256sum -c SHA256SUMS
```

Mọi file phải báo `OK`. Nếu thư mục `ids-vm-m3` đã tồn tại, dùng thư mục lab mới để tránh trộn các phiên bản.

Model được tạo bằng **Python 3.14.6**. Dùng uv cài đúng Python và thư viện đã pin:

```bash
curl -LsSf https://astral.sh/uv/install.sh -o /tmp/ids-uv-install.sh
sh /tmp/ids-uv-install.sh
export PATH="$HOME/.local/bin:$PATH"

uv python install 3.14.6
uv venv --python 3.14.6 .venv
uv pip install --python .venv/bin/python -r requirements-vm.in
.venv/bin/python --version
```

Nếu đã có uv, bỏ ba lệnh cài uv. Không dùng `.venv` chép từ Windows. Không cần cài notebook/Jupyter/matplotlib để chạy gói suy luận này. `requirements-vm.in` dùng bảy phiên bản thư viện trong artifact và Scapy 2.8.0 đã dùng ở máy phát triển.

Nếu uv chưa tìm thấy bản Python yêu cầu, cập nhật uv theo phương thức đã cài và thử lại. Nếu Python/package pin không có bản phù hợp cho Linux của bạn, dừng ở đây để chọn môi trường chung và train lại; không tự thay scikit-learn rồi coi model cũ đã tương thích.

## 4. Kiểm tra model trước khi bắt traffic

Chạy từ `~/ids-lab/ids-vm-m3`:

```bash
.venv/bin/python src/check_model.py \
  --model models/stacking_ids.joblib --csv smoke/cicids2017.csv

.venv/bin/python src/check_model.py \
  --model models/stacking_ids.joblib --csv smoke/insdn.csv
```

Cả hai lệnh phải kết thúc thành công và in:

```text
Prediction match: 100.00%
```

Đây là khớp dự đoán đã lưu trên hai mẫu kiểm tra, chưa phải Accuracy 100% hoặc bằng chứng nhận diện attack lab. Chỉ load `.joblib` do bạn tạo/đáng tin cậy.

Đánh giá Accuracy bằng nhãn thật trên toàn bộ hai test đi kèm, không train lại:

```bash
.venv/bin/python src/evaluate_model.py --model models/stacking_ids.joblib \
  --csv evaluation/cicids2017.csv --out logs/evaluate-cic01
.venv/bin/python src/evaluate_model.py --model models/stacking_ids.joblib \
  --csv evaluation/insdn.csv --out logs/evaluate-insdn01
```

M3 seed 42 hiện có Accuracy CIC khoảng 99,309%, InSDN khoảng 99,933%; output có errors.csv và confusion matrix. Đây là đánh giá lại test đã có, không phải phép đo live trên VM.

## 5. Chạy detector live

Kiểm tra lại tên interface Host-only bằng `ip -br -4 addr`. Mở **terminal Kali A**:

```bash
cd ~/ids-lab/ids-vm-m3
mkdir -p logs/run01 captures

sudo "$(pwd)/.venv/bin/python" src/detect.py \
  --model models/stacking_ids.joblib \
  --iface eth1 --capture-filter 'host 192.168.56.1' --out logs/run01 \
  --idle 10 --max-age 60 --max-flows 10000
```

Đổi `eth1` trước khi chạy. Chờ dòng `Capturing eth1; Ctrl+C to stop.`. Cảnh báo `EXPERIMENTAL ... parity is unvalidated` là giới hạn nghiên cứu đã biết, không phải thông báo cài đặt thất bại.

Detector gom gói thành flow. Flow thường được chốt khi idle 10 giây; flow tiếp diễn có giới hạn max-age 60 giây. Không kỳ vọng mỗi request đều in kết quả ngay lập tức. Terminal chỉ in các flow dự đoán ATTACK; file `logs/run01/predictions.jsonl` lưu cả BENIGN và ATTACK.

## 6. Gửi traffic thử từ Windows

Mở **terminal Kali B**, tạo thư mục demo chỉ chứa file công khai:

```bash
mkdir -p ~/ids-demo-www
printf 'IDS lab demo\n' > ~/ids-demo-www/index.html
python3 -m http.server 8080 --bind 192.168.56.101 --directory ~/ids-demo-www
```

Đổi IP theo Kali thật. Trong PowerShell Windows:

```powershell
Test-NetConnection 192.168.56.101 -Port 8080
curl.exe http://192.168.56.101:8080/
```

Phải kết nối thành công và nhận `IDS lab demo`. Chờ hơn 10 giây không gửi request, rồi mở **terminal Kali C**:

```bash
cd ~/ids-lab/ids-vm-m3
tail -n 5 logs/run01/predictions.jsonl
```

Thành công ở bước này: detector có log flow TCP của kết nối Windows ↔ Kali. Nếu request bình thường bị dự đoán ATTACK, ghi nhận false positive; không đổi nhãn thật theo dự đoán. Nếu file log còn rỗng, kiểm tra IP/interface, terminal A đã capture chưa và thời gian chờ flow.

Nếu Windows đã có Nmap, có thể thử lượt scan nhỏ trên đúng VM lab:

```powershell
nmap -sT -p 1-1000 --max-rate 50 192.168.56.101
```

M3 nhị phân chỉ trả BENIGN/ATTACK, không trả tên PortScan. Không có bảo đảm mọi scan đều được nhận đúng. Tách lượt BENIGN và lượt scan ra PCAP/log riêng nếu định tính FPR/FNR.

## 7. Lưu PCAP và đánh giá có thể kiểm tra lại

Trước khi tạo traffic, có thể mở thêm terminal và bắt đúng interface Host-only:

```bash
cd ~/ids-lab/ids-vm-m3
mkdir -p captures
sudo tcpdump -Z "$USER" -i eth1 -nn -s 0 \
  -w captures/benign01.pcap 'host 192.168.56.1 and (tcp or udp)'
```

Chỉ tạo request bình thường vào HTTP server trong lượt này. Dừng tcpdump bằng Ctrl+C sau lượt thử. Detector live và tcpdump có thể khác thời điểm bắt đầu; cách kiểm tra đầu tiên dễ tái lập hơn là chạy lại **cùng một PCAP** qua detector và extractor:

```bash
.venv/bin/python src/detect.py --model models/stacking_ids.joblib \
  --pcap captures/benign01.pcap --out logs/benign01-offline \
  --idle 10 --max-age 60

.venv/bin/python src/extract.py --pcap captures/benign01.pcap \
  --out captures/benign01-truth.csv --label BENIGN \
  --idle 10 --max-age 60

.venv/bin/python src/evaluate_lab.py \
  --predictions logs/benign01-offline/predictions.jsonl \
  --truth captures/benign01-truth.csv --out logs/benign01-offline/metrics.json
```

Mỗi lượt dùng đường dẫn output mới: detector từ chối khởi động nếu `predictions.jsonl` đã tồn tại, kể cả file rỗng; extractor cũng từ chối ghi đè CSV. Gán `--label BENIGN` chỉ khi đã xác minh capture chỉ có traffic BENIGN; capture hỗn hợp cần nhãn theo từng flow. Với capture attack đã xác minh, dùng `ATTACK` vì M3 là nhị phân. File metrics sẽ ghi FPR, FNR (null nếu không có attack), số flow ghép/không ghép và thời gian suy luận. Độ trễ từ gói đầu tới kết quả chỉ đo ở live, không suy ra từ replay offline.

Trước khi đánh giá, mỗi hàng truth phải có nhãn đã xác minh. Tool chuẩn hóa khoảng trắng và các nhãn BENIGN/Normal/ATTACK không phân biệt hoa thường, giữ tên subtype khác, và báo lỗi nếu gặp nhãn rỗng, thiếu hoặc UNKNOWN ở truth/prediction. Không tự tính flow chưa rõ nhãn thành attack.

## 8. Khi nào coi là đã triển khai được?

1. Hai smoke test đều `Prediction match: 100.00%`.
2. HTTP Windows → Kali kết nối được trên Host-only.
3. Detector tạo log flow đúng endpoint và dừng sạch bằng Ctrl+C.
4. Replay một PCAP qua detector/extractor/đánh giá cho ra metrics, không trộn log các lượt.

Đạt các bước này chứng minh pipeline chạy được trên VM. Muốn kết luận độ chính xác thực tế cần traffic BENIGN/ATTACK có ground truth, đo mất gói/flow và kiểm tra khác biệt feature giữa extractor lab và dataset. Phiên chuẩn bị này chưa truy cập hoặc chạy máy ảo của bạn.

## Tra cứu

| Tình huống | Kiểm tra |
|---|---|
| Không kết nối được HTTP | Host-only IPv4, cùng subnet, server bind đúng IP, firewall; chưa cần đổi model |
| `No such device` / không thấy flow | `ip -br -4 addr`; thay đúng interface Host-only |
| `libgomp.so.1` thiếu | Cài `libgomp1` bằng apt |
| Không khởi động được capture | Quyền sudo, `libpcap-dev`, tên interface, `sudo tcpdump -D` |
| Smoke test không khớp | Kiểm tra checksum, Python, package pin; không bỏ qua lỗi phiên bản |
| Terminal detector im lặng | Terminal chỉ in ATTACK; chờ idle và xem `predictions.jsonl` |
| VM RAM cao khi cài | Cài gói suy luận; không chuyển dữ liệu/train/notebook nếu chưa cần |

Tài liệu chính thức: [VirtualBox networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html), [cài uv](https://docs.astral.sh/uv/getting-started/installation/), [cài Python bằng uv](https://docs.astral.sh/uv/guides/install-python/), [scikit-learn model persistence](https://scikit-learn.org/stable/model_persistence.html).
