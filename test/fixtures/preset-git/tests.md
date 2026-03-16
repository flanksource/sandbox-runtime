---
exec: srt
args: [-p, git, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl github.com allowed | curl -sf https://github.com | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
