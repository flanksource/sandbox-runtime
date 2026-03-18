---
exec: srt
args: [-p, python, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl pypi.org allowed | curl -sf https://pypi.org | 0 | |
| curl crates.io denied | curl -sf https://crates.io | != 0 | |
