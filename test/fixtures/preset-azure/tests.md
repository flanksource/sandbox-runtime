---
exec: srt
args: [-p, azure, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl portal.azure.com allowed | curl -sf https://portal.azure.com | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
