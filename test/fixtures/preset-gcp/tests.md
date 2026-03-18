---
exec: srt
args: [-p, gcp, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl storage.googleapis.com allowed | curl -sf https://storage.googleapis.com | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
