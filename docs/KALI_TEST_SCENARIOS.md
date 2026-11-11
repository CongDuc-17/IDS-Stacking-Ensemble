# Kịch bản kiểm thử IDS trên Kali

Dùng gói `ids-vm-multiclass-combined-seed42-trees.zip` đã cài theo [VM_DEPLOYMENT.md](VM_DEPLOYMENT.md). Ví dụ dưới đây dùng Windows `192.168.230.1`, Kali `192.168.230.130` và interface `eth1`.

| Ca | Traffic tạo ra trong lab | Giá trị `ports` | Giá trị `label` |
|---|---|---|---|
| B01 | 20 HTTP GET hợp lệ | `tcp port 8080` | `BENIGN` |
| A01 | Thử kết nối TCP lần lượt vào 20 cổng | `tcp portrange 8100-8119` | `RECON` |
| B02 | 10 lần đăng nhập đúng vào endpoint demo | `tcp port 8081` | `BENIGN` |
| A02 | 20 lần đoán mật khẩu sai vào cùng endpoint | `tcp port 8081` | `BRUTE_FORCE` |

Chạy B01 rồi A01 trước. B02 và A02 dùng server xác thực thử nghiệm ở phần cuối. Mỗi ca dùng một PCAP riêng, bắt đầu capture trước khi tạo traffic.

## Bắt PCAP cho một ca

Dùng cùng terminal Kali cho capture, replay và chấm điểm. Server HTTP chạy trong terminal Kali khác. Đổi `case_id`, `label` và `ports` theo đúng hàng của ca cần chạy.

```bash
cd ~/ids-lab/ids-vm-multiclass-combined-seed42-trees
py="./.venv/bin/python"
mkdir -p captures

case_id=B01
label=BENIGN
ports='tcp port 8080'

run="$case_id-$(date +%Y%m%d-%H%M%S)"
pcap="captures/$run.pcap"
out="logs/$run"

sudo tcpdump -Z "$USER" -i eth1 -nn -s 0 -U \
  -w "$pcap" \
  "ip and host 192.168.230.1 and host 192.168.230.130 and ($ports)"
```

Chờ dòng `listening on eth1`, chạy lệnh Windows của ca đó, rồi dừng tcpdump bằng Ctrl+C. Nếu VM vừa đổi mạng, đối chiếu địa chỉ và interface bằng `ip -br -4 addr`. Ghi lại thống kê packet mà tcpdump in khi dừng. Khi capture chứa traffic ngoài ca thử, xác minh nhãn từng flow trước khi chấm.

## B01 · HTTP bình thường

Dùng HTTP server demo đang chạy trên Kali. Nếu server đã dừng, mở terminal Kali khác:

```bash
mkdir -p ~/ids-demo-www
test -f ~/ids-demo-www/index.html || printf 'IDS lab demo\n' > ~/ids-demo-www/index.html
python3 -m http.server 8080 --bind 192.168.230.130 --directory ~/ids-demo-www
```

Sau khi bắt đầu capture B01, chạy trên PowerShell Windows:

```powershell
1..20 | ForEach-Object {
    curl.exe --noproxy "*" --max-time 5 -sS -o NUL -w "HTTP %{http_code}\n" http://192.168.230.130:8080/
    Start-Sleep -Milliseconds 300
}
```

Đối chiếu 20 phản hồi `HTTP 200`. Nhãn BENIGN dựa trên các request hợp lệ vừa tạo. B01 là lượt mới để kiểm tra báo động giả đã thấy ở `benign02.pcap`.

## A01 · Quét cổng TCP

Sau khi bắt đầu capture A01, chạy trên PowerShell Windows từ thư mục project:

```powershell
Set-Location 'D:\Downloads\network-stacking-ids-20261107\network-stacking-ids'

@'
import socket
import time

host = "192.168.230.130"
for port in range(8100, 8120):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            print(f"{port} open")
    except ConnectionRefusedError:
        print(f"{port} refused")
    except TimeoutError:
        print(f"{port} timeout")
    time.sleep(0.15)
'@ | .\.venv\Scripts\python.exe -
```

Nhãn RECON dựa trên dãy thử kết nối có chủ đích vào các cổng của Kali. Cổng trả `refused` vẫn có thể có SYN/RST trong PCAP. Xem các cổng thực tế đã quan sát bằng `tcpdump -nn -r "$pcap"`.

## Replay và chấm điểm sau mỗi capture

Trong terminal Kali đã đặt `py`, `pcap`, `run`, `out` và `label`, chạy:

```bash
truth="captures/$run-truth.csv"

"$py" src/detect.py \
  --model models/stacking_ids.joblib \
  --pcap "$pcap" --out "$out" --idle 10 --max-age 60 &&
"$py" src/extract.py \
  --pcap "$pcap" --out "$truth" --label "$label" --idle 10 --max-age 60 &&
"$py" src/evaluate_lab.py \
  --model models/stacking_ids.joblib \
  --predictions "$out/predictions.jsonl" \
  --truth "$truth" --out "$out/metrics.json"
```

| Trường trong metrics | Cách đọc |
|---|---|
| `matched_flows` và hai trường `without_prediction` / `without_truth` | Số flow ghép được và số flow thiếu đối chiếu. Metrics áp dụng cho các flow ghép được |
| `benign_false_positive_rate` | Tỷ lệ flow BENIGN bị báo attack trong B01/B02 |
| `attack_false_negative_rate` | Tỷ lệ flow attack bị gán BENIGN trong A01/A02 |
| `classification_report_matched_only` | Xem recall của đúng nhóm RECON hoặc BRUTE_FORCE |
| `inference_ms` | Thời gian suy luận p50/p95 khi replay |

Giá trị `null` ở FPR/FNR nghĩa là capture thiếu lớp cần tính. Nếu flow RECON bị gán BRUTE_FORCE, model đã cảnh báo attack nhưng phân loại sai nhóm. Lưu PCAP, log lệnh tạo traffic, CSV truth, JSONL dự đoán và metrics cùng mã ca.

## B02 và A02 · Đăng nhập đúng và đoán mật khẩu

Mở terminal Kali khác và chạy endpoint xác thực demo. Tài khoản dưới đây chỉ phục vụ lab:

```bash
python3 - <<'PY'
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer

expected = "Basic " + base64.b64encode(b"ids-lab:lab-pass").decode("ascii")

class LabLogin(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/login":
            self.send_error(404)
            return

        authenticated = self.headers.get("Authorization") == expected
        body = b"Lab login OK\n" if authenticated else b"Invalid lab login\n"
        self.send_response(200 if authenticated else 401)
        if not authenticated:
            self.send_header("WWW-Authenticate", 'Basic realm="IDS lab"')
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

HTTPServer(("192.168.230.130", 8081), LabLogin).serve_forever()
PY
```

Bắt đầu capture B02 rồi chạy trên PowerShell Windows:

```powershell
1..10 | ForEach-Object {
    curl.exe --noproxy "*" --max-time 5 -sS --basic --user "ids-lab:lab-pass" -o NUL -w "HTTP %{http_code}\n" http://192.168.230.130:8081/login
    Start-Sleep -Milliseconds 300
}
```

B02 cần trả 10 mã `200`. Dừng capture B02 và mở capture A02 trước khi chạy:

```powershell
1..20 | ForEach-Object {
    $guess = "bad-{0:D4}" -f $_
    curl.exe --noproxy "*" --max-time 5 -sS --basic --user "ids-lab:$guess" -o NUL -w "HTTP %{http_code}\n" http://192.168.230.130:8081/login
    Start-Sleep -Milliseconds 300
}
```

A02 cần trả 20 mã `401`. Nhãn BRUTE_FORCE đến từ kịch bản nhiều lần đoán mật khẩu có kiểm soát. B02 và A02 dùng cùng IP, cổng và đường dẫn để đo phản ứng của model với hai hành vi trên cùng dịch vụ.

## Đo live khi cần số liệu độ trễ

Sau khi đã chạy các ca bằng PCAP, có thể lặp một ca với detector live chạy đồng thời với tcpdump. Dùng cùng interface, filter và timeout. Đối chiếu log live với CSV truth của capture tương ứng. Trường `observed_first_packet_to_result_seconds` cho biết thời gian từ gói đầu đến lúc có dự đoán, gồm thời gian chờ chốt flow.
