## Chú ý lỗi mount file Prometheus khi pull image

Khi mount file `prometheus.yml`, Ubuntu/WSL có thể không phân biệt được giữa **file** và **directory**.

Nếu file chưa tồn tại, Docker có thể tự động tạo thành một directory, dẫn tới lỗi:

```bash
Are you trying to mount a directory onto a file (or vice-versa)?
```

### Kiểm tra
``` bash
ls -l infrastructure/monitoring
```

``` 
drwxr-xr-x prometheus.yml ===> LỖI

-rw-r--r-- prometheus.yml ===> OK
```
===> OK
### Cách xử lý

Xóa path bị tạo sai:

```bash
rm -rf infrastructure/monitoring/prometheus.yml
```

Tạo lại đúng dạng file:

```bash
touch infrastructure/monitoring/prometheus.yml
```