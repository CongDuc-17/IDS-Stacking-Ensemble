# Demo model Stacking đa lớp

Đã bổ sung **M3 đa lớp học từ cả CIC + InSDN**, dùng 9 nhóm chung thay vì giữ nguyên subtype của từng nguồn. Xem [LABEL_TAXONOMY.md](LABEL_TAXONOMY.md) và notebook `training_combined.ipynb` (`MULTICLASS=True`). Các model và số liệu riêng từng nguồn dưới đây là thí nghiệm subtype cũ, tiếp tục được giữ để đối chiếu đúng bài toán.


Model mẫu cố định: CIC-IDS2017, seed 42, cap 2000/lớp, 60 cây, 3 folds, tuning baseline và meta-search bằng train/validation. Không chọn seed theo điểm test. Kết quả thực nghiệm phải đọc từ CURRENT_RESULTS.md, không mặc định ES thắng baseline.

## Windows: đánh giá và gọi tên subtype

```powershell
$model = 'experiments/completion-20261110/multiclass-search-cicids2017-seed42/models/stacking_ids.joblib'
.\.venv\Scripts\python.exe src/check_model.py --model $model --csv experiments/completion-20261110/multiclass-search-cicids2017-seed42/smoke_test.csv
.\.venv\Scripts\python.exe src/evaluate_model.py --model $model --csv experiments/completion-20261110/multiclass-search-cicids2017-seed42/splits/test.csv --out experiments/evaluate-multiclass-cic-new
```

Prediction match là tái lập, còn evaluate_model dùng Label. Artifact này có 14 lớp (Heartbleed bị loại vì ít mẫu); lớp hiếm có rất ít mẫu test, nên cần trình bày support. M3 cũ vẫn là nhị phân; đổi model đa lớp không làm nó trở thành M3 đa lớp.

Mở PowerShell Administrator để capture HTTP demo localhost, dùng log mới:

```powershell
.\.venv\Scripts\python.exe src/detect.py --model $model --iface '\Device\NPF_Loopback' --capture-filter 'host 127.0.0.1 and tcp port 8080' --out logs/windows-multiclass-new --idle 10 --max-age 60
```

Nhãn dự đoán có thể là subtype trong dataset, nhưng chưa chứng minh đúng nhãn lab: feature parity và domain shift vẫn cần đo. Nếu traffic HTTP hợp pháp bị gán attack thì ghi nhận false positive, không gán lại nhãn thật theo model.

## Gói Kali riêng cho model đa lớp CIC

`deliverables/ids-vm-multiclass-cicids2017-seed42.zip` chứa runtime, model, smoke và toàn bộ test CIC có nhãn. Đây là gói riêng, không thay gói M3 nhị phân.

Có gói InSDN riêng `deliverables/ids-vm-multiclass-insdn-seed42.zip`, gồm model 6 lớp và test InSDN. Khi dùng gói đó, đổi tên thư mục/CSV từ cicids2017 thành insdn trong lệnh. Không đưa CSV đa lớp InSDN vào model CIC vì taxonomy khác nhau.

Trên Kali, giải nén vào thư mục mới, vào `ids-vm-multiclass-cicids2017-seed42`, kiểm tra `sha256sum -c SHA256SUMS`. Cài Python 3.14.6 và package theo VM_DEPLOYMENT.md bằng uv, rồi:

```bash
uv venv --python 3.14.6 .venv
uv pip install --python .venv/bin/python -r requirements-vm.in
.venv/bin/python src/check_model.py --model models/stacking_ids.joblib --csv smoke/cicids2017.csv
.venv/bin/python src/evaluate_model.py --model models/stacking_ids.joblib --csv evaluation/cicids2017.csv --out logs/evaluate-cic01
sudo "$(pwd)/.venv/bin/python" src/detect.py --model models/stacking_ids.joblib --iface eth1 --capture-filter 'host 192.168.56.1' --out logs/live-cic01
```

Đổi interface/IP theo mạng lab thật. Cùng scope và timeout với recorder, dùng kịch bản có nhãn độc lập. Không tự gán scan lab thành một nhãn dataset chỉ vì tên gần giống; ghi rõ cách quy đổi nhãn khi đánh giá subtype. Chưa có capture Linux thật trong phiên chuẩn bị.
