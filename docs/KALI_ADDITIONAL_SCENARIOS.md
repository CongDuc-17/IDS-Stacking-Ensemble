# Kịch bản kiểm thử bổ sung cho M3 trên Kali

Dùng gói `ids-vm-multiclass-combined-seed42-trees.zip` và môi trường `.venv` đã cài. Các ca bên dưới tạo traffic mới để đo M3 trước khi chỉnh detector. Chạy trên mạng Host-only, với Kali `192.168.230.130`, Windows `192.168.230.1` và interface Kali `eth1`. Thay các địa chỉ nếu lab của bạn khác.

| Ca | Traffic và đối chứng | Nhãn để chấm |
|---|---|---|
| B02 / A02 | Đăng nhập đúng / thử 20 mật khẩu sai vào cùng endpoint | `BENIGN` / `BRUTE_FORCE` |
| B03 / A03 | Tìm kiếm hợp lệ / SQL injection vào bảng SQLite chứa dữ liệu giả | `BENIGN` / `WEB_ATTACK` |
| B04 / A04 | Request tuần tự / request đồng thời từ một máy làm dịch vụ demo hết chỗ xử lý | `BENIGN` / `DOS` |
| A05 | Hai máy lab cùng tạo tải làm dịch vụ demo hết chỗ xử lý | `DDOS`, mô phỏng nhiều nguồn |
| E01–E03 | Chấm các mẫu mang nhãn gốc trong tập test đi kèm gói | `BOT`, `INFILTRATION`, `U2R` |

Chạy B02/A02 và B03/A03 trước, rồi B04/A04. Nếu hiện chỉ có Windows và Kali, dùng tập test đi kèm để đánh giá `DDOS`. A05 cần một máy phát traffic thứ hai ngoài Kali. [Định nghĩa DDoS của NIST](https://csrc.nist.gov/glossary/term/distributed_denial_of_service)

## 1. Chuẩn bị một lần

### Terminal Kali để bắt và chấm

```bash
cd ~/ids-lab/ids-vm-multiclass-combined-seed42-trees
WIN_IP=192.168.230.1
KALI_IP=192.168.230.130
IFACE=eth1
py=./.venv/bin/python
mkdir -p captures logs

capture_extra() {
  local sources="${4:-host $WIN_IP}"
  label="$2"
  run="$1-$(date +%Y%m%d-%H%M%S-%N)"
  pcap="captures/$run.pcap"
  out="logs/$run"
  sudo tcpdump -Z "$(id -un)" -i "$IFACE" -nn -s 0 -U \
    -w "$pcap" "ip and tcp and host $KALI_IP and ($sources) and ($3)"
}

grade_extra() {
  truth="captures/$run-truth.csv"
  "$py" src/detect.py --model models/stacking_ids.joblib \
    --pcap "$pcap" --out "$out" --idle 10 --max-age 60 &&
  "$py" src/extract.py --pcap "$pcap" --out "$truth" --label "$label" \
    --idle 10 --max-age 60 &&
  "$py" src/evaluate_lab.py --model models/stacking_ids.joblib \
    --predictions "$out/predictions.jsonl" --truth "$truth" \
    --out "$out/metrics.json"
}
```

Mỗi ca có PCAP riêng. Chờ tcpdump báo đang nghe rồi mới phát traffic. Khi lệnh phía máy phát kết thúc, bấm Ctrl+C ở terminal bắt gói. Chỉ chạy `grade_extra` sau khi đã xác nhận kết quả theo ca và capture chỉ chứa traffic có cùng nhãn. Ghi lại số packet bị drop mà tcpdump in khi dừng.

### Terminal Kali để chạy server demo

Tạo server dưới đây. Dùng cùng file cho ba cổng `8081`, `8082` và `8083`. Cổng truyền vào khi khởi động. Server bind vào IP Host-only của Kali. Tài khoản và bảng SQLite đều là dữ liệu giả dùng riêng cho lab. [Tài liệu Python http.server](https://docs.python.org/3/library/http.server.html)

```bash
cat > "$HOME/ids-lab-demo-server.py" <<'PY'
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sqlite3
import sys
import threading
import time
from urllib.parse import parse_qs, urlsplit

expected = "Basic " + base64.b64encode(b"ids-lab:lab-pass").decode("ascii")
slot = threading.BoundedSemaphore(1)


class LabServer(ThreadingHTTPServer):
    request_queue_size = 32


class LabHandler(BaseHTTPRequestHandler):
    def reply(self, code, text):
        body = (text + "\n").encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)

        if url.path == "/login":
            valid = self.headers.get("Authorization") == expected
            self.reply(200 if valid else 401, "login-ok" if valid else "login-failed")
            return

        if url.path == "/search":
            query = parse_qs(url.query).get("q", [""])[0]
            db = sqlite3.connect(":memory:")
            try:
                db.execute("CREATE TABLE items (name TEXT)")
                db.executemany("INSERT INTO items VALUES (?)",
                               [("public-demo",), ("private-lab-marker",)])
                # Intentionally vulnerable query against this throwaway lab table.
                rows = db.execute(f"SELECT name FROM items WHERE name = '{query}'").fetchall()
            except sqlite3.Error:
                self.reply(400, "invalid-query")
            else:
                self.reply(200, " ".join(name for (name,) in rows))
            finally:
                db.close()
            return

        if url.path == "/health":
            available = slot.acquire(blocking=False)
            if available:
                slot.release()
            self.reply(200 if available else 503, "available" if available else "busy")
            return

        if url.path == "/work":
            if not slot.acquire(blocking=False):
                self.reply(503, "busy")
                return
            try:
                time.sleep(1.2)
                self.reply(200, "work-done")
            finally:
                slot.release()
            return

        self.reply(404, "not-found")


LabServer((sys.argv[1], int(sys.argv[2])), LabHandler).serve_forever()
PY
```

## 2. BRUTE_FORCE và đối chứng đăng nhập

Khởi động server trên Kali:

```bash
python3 "$HOME/ids-lab-demo-server.py" 192.168.230.130 8081
```

**B02**. Trong terminal bắt gói Kali, chạy `capture_extra B02 BENIGN 'tcp port 8081'`. Sau đó chạy trên Windows PowerShell:

```powershell
$KaliIp = '192.168.230.130'
1..10 | ForEach-Object {
    curl.exe --noproxy "*" --max-time 5 -sS --basic --user "ids-lab:lab-pass" -o NUL -w "HTTP %{http_code}\n" "http://${KaliIp}:8081/login"
    Start-Sleep -Milliseconds 300
}
```

Đối chiếu 10 mã HTTP 200, dừng capture rồi chạy `grade_extra`.

**A02**. Chạy `capture_extra A02 BRUTE_FORCE 'tcp port 8081'`, rồi phát traffic trên Windows:

```powershell
1..20 | ForEach-Object {
    $guess = "bad-{0:D4}" -f $_
    curl.exe --noproxy "*" --max-time 5 -sS --basic --user "ids-lab:$guess" -o NUL -w "HTTP %{http_code}\n" "http://${KaliIp}:8081/login"
    Start-Sleep -Milliseconds 300
}
```

Đối chiếu 20 mã HTTP 401, dừng capture rồi chạy `grade_extra`. Đây là ca đoán mật khẩu **qua HTTP trong lab**. Nhãn dựa trên chuỗi lần thử do bạn chủ động tạo và phản hồi của server demo. CIC-IDS2017 có các kịch bản brute force qua nhiều dịch vụ, gồm cả web. [Mô tả CIC-IDS2017 của UNB](https://www.unb.ca/cic/datasets/ids-2017.html)

## 3. WEB_ATTACK và đối chứng tìm kiếm

Dừng server cổng 8081 rồi khởi động trên cổng 8082:

```bash
python3 "$HOME/ids-lab-demo-server.py" 192.168.230.130 8082
```

**B03**. Chạy `capture_extra B03 BENIGN 'tcp port 8082'`, rồi trên Windows:

```powershell
1..10 | ForEach-Object {
    curl.exe --noproxy "*" --max-time 5 -sS --get --data-urlencode "q=public-demo" -w "HTTP %{http_code}\n" "http://${KaliIp}:8082/search"
    Start-Sleep -Milliseconds 300
}
```

Mỗi lần cần trả HTTP 200 và chỉ hiện `public-demo`. Dừng capture rồi chạy `grade_extra`.

**A03**. Chạy `capture_extra A03 WEB_ATTACK 'tcp port 8082'`, rồi gửi yêu cầu kiểm thử SQL injection tới bảng demo:

```powershell
1..10 | ForEach-Object {
    curl.exe --noproxy "*" --max-time 5 -sS --get --data-urlencode "q=public-demo' OR '1'='1" -w "HTTP %{http_code}\n" "http://${KaliIp}:8082/search"
    Start-Sleep -Milliseconds 300
}
```

Mỗi lần cần trả HTTP 200 và có thêm `private-lab-marker`. Marker cho thấy truy vấn đã trả hàng nằm ngoài điều kiện tìm kiếm bình thường. Dừng capture rồi chạy `grade_extra`. SQL injection thuộc nhóm `WEB_ATTACK` theo bảng ánh xạ của dự án. [Mô tả các ca web của CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)

## 4. DOS và DDOS mô phỏng có giới hạn

Dừng server cổng 8082 rồi khởi động trên cổng 8083:

```bash
python3 "$HOME/ids-lab-demo-server.py" 192.168.230.130 8083
```

Lưu đoạn sau thành `ids-lab-load.py` trên máy phát, trong thư mục chạy lệnh. Có thể dùng cùng file trên Windows và máy lab thứ hai. Tổng tải của mỗi ca là **12 request**. Server demo chỉ cho một request `/work` chạy cùng lúc, nên có thể quan sát quá tải ở cấp ứng dụng với số request nhỏ.

```python
import argparse
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
import time

parser = argparse.ArgumentParser()
parser.add_argument("host")
parser.add_argument("mode", choices=("sequential", "burst"))
parser.add_argument("count", type=int, choices=(6, 12))
parser.add_argument("--start-at", type=int, help="Unix timestamp in seconds")
args = parser.parse_args()


def request(_):
    connection = HTTPConnection(args.host, 8083, timeout=4)
    try:
        connection.request("GET", "/work")
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


if args.start_at is not None:
    delay = args.start_at - time.time()
    if delay <= 0:
        parser.error("--start-at must be in the future")
    time.sleep(delay)

if args.mode == "sequential":
    codes = list(map(request, range(args.count)))
else:
    with ThreadPoolExecutor(max_workers=args.count) as workers:
        codes = list(workers.map(request, range(args.count)))

print("HTTP status:", codes)
print("200:", codes.count(200), "503:", codes.count(503))
```

### B04 và A04 từ Windows

| Ca | Lệnh bắt gói trên Kali | Lệnh Windows PowerShell |
|---|---|---|
| B04 | `capture_extra B04 BENIGN 'tcp port 8083'` | `python ids-lab-load.py 192.168.230.130 sequential 12` |
| A04 | `capture_extra A04 DOS 'tcp port 8083'` | `python ids-lab-load.py 192.168.230.130 burst 12` |

B04 cần 12 mã HTTP 200. A04 cần có HTTP 503 khi tải đến dồn. Để xác nhận ảnh hưởng lên yêu cầu hợp lệ, kiểm tra `/health` từ **một terminal Kali khác** trước và trong lượt A04. Khởi động vòng lặp ngay trước khi chạy lệnh Windows.

```bash
for i in $(seq 1 40); do
  curl --noproxy '*' --max-time 2 -sS -o /dev/null -w 'HTTP %{http_code}\n' \
    http://192.168.230.130:8083/health
  sleep 0.25
done
```

Kỳ vọng `/health` trả 200 khi rảnh và có 503 lúc slot bận. Probe xuất phát từ Kali nên nằm ngoài bộ lọc chỉ bắt traffic Windows ↔ Kali. Nếu không thấy 503 ở probe, giữ lại bằng chứng tải bị từ chối từ client và ghi rõ chưa quan sát được probe bị ảnh hưởng. Dừng và chấm từng capture riêng.

### A05 khi có thêm một máy phát

Thay `192.168.230.131` bằng IP thật của máy lab thứ hai. Bắt cả hai nguồn trong cùng capture:

```bash
capture_extra A05 DDOS 'tcp port 8083' \
  'host 192.168.230.1 or host 192.168.230.131'
```

Trên Windows lấy một timestamp UTC Unix ở tương lai, rồi dùng cùng giá trị đó trên **cả hai máy phát**. Đồng hồ hai máy cần khớp đủ để các đợt tải chồng lên nhau.

```powershell
$startAt = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 30
$startAt
python ids-lab-load.py 192.168.230.130 burst 6 --start-at $startAt
```

Trên máy thứ hai, chạy trước thời điểm đã hẹn và thay `START_AT` bằng số Windows in ra:

```bash
python3 ids-lab-load.py 192.168.230.130 burst 6 --start-at START_AT
```

Chỉ chấm A05 dưới nhãn `DDOS` mô phỏng nếu PCAP có **hai IP nguồn**, các yêu cầu chồng thời gian và có HTTP 503. Dùng `tcpdump -nn -tt -r "$pcap" 'tcp dst port 8083'` để đối chiếu IP và timestamp. Có thể chạy probe `/health` từ Kali ngay trước giờ bắt đầu để kiểm tra ảnh hưởng lên request hợp lệ. Giữ cùng tổng số request với A04 để đối chiếu số nguồn phát. [Định nghĩa DDoS của NIST](https://csrc.nist.gov/glossary/term/distributed_denial_of_service)

## 5. BOT, INFILTRATION, U2R và đối chiếu offline

Từ thư mục gói trên Kali, chạy M3 trên **toàn bộ** hai tập test đã đóng gói. Báo cáo đầy đủ giữ cả các mẫu lớp khác để xem model dự đoán nhầm vào lớp nào. Dùng cùng lệnh để đối chiếu offline `BRUTE_FORCE`, `WEB_ATTACK`, `DOS` và `DDOS`.

```bash
cd ~/ids-lab/ids-vm-multiclass-combined-seed42-trees
run="offline-m3-$(date +%Y%m%d-%H%M%S-%N)"

for dataset in cicids2017 insdn; do
  .venv/bin/python src/evaluate_model.py \
    --model models/stacking_ids.joblib \
    --csv "evaluation/$dataset.csv" \
    --out "logs/$run-$dataset"
done
```

| Ca | Lớp và tập test | Số flow mang nhãn thật |
|---|---|---:|
| E01 | `BOT` trên CIC-IDS2017 | 387 |
| E02 | `INFILTRATION` trên CIC-IDS2017 | 7 |
| E03 | `U2R` trên InSDN | 3 |
| E04 | `DDOS` trên CIC-IDS2017 và InSDN | 400 và 40 |

Mở `report_stacking.json` để xem `support`, `precision` và `recall` từng lớp. Xem `confusion_stacking.csv` và `errors.csv` để biết nhãn bị nhầm. Với E02/E03, báo cả **số đúng trên tổng số mẫu**, vì mỗi flow làm tỷ lệ thay đổi đáng kể. Đây là đánh giá offline trên test gốc của M3. Nhãn `BOT`, `INFILTRATION` và `U2R` ở đây đến từ dữ liệu đã ánh xạ, nên có thể dùng để kiểm tra phân loại trước khi xây dựng kịch bản live riêng.

## 6. Ghi kết quả trước khi cải tiến

- **Mỗi ca lab** giữ PCAP, log client hoặc server xác nhận hành vi, CSV truth, `predictions.jsonl` và `metrics.json`. Kiểm tra `matched_flows`, `truth_flows_without_prediction` và `predicted_flows_without_truth` trước khi đọc tỷ lệ.
- **Ca bình thường** ghi số flow đúng `BENIGN` và `benign_false_positive_rate`. **Ca tấn công** ghi số flow bị bỏ sót, số flow đúng nhóm và nhóm bị nhầm. Một flow `WEB_ATTACK` được đoán `BRUTE_FORCE` được tính là phát hiện tấn công ở mức nhị phân và sai nhóm ở mức đa lớp.
- **Cảnh báo theo lượt quét** đọc từ `recon_alert` trong JSONL của bản detector đã bổ sung quy tắc. `metrics.json` của `evaluate_lab.py` vẫn chấm trường `predicted_label` theo từng flow M3.
- **Độ trễ** lấy `inference_ms` khi replay. Khi chạy live, lấy `observed_first_packet_to_result_seconds` của flow hoặc `first_packet_to_alert_seconds` của cảnh báo theo lượt quét.
- Dùng các capture này làm mốc so sánh trước và sau khi chỉnh detector. Nếu đã xem chúng để chọn cách cải tiến, thu lượt mới để kiểm tra sau khi chốt thay đổi. M3 đang dùng 12 đặc trưng flow, vì vậy cần đối chiếu kết quả theo đúng nhãn và ca đã chạy, kể cả khi model dự đoán sai.
