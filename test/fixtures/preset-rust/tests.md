---
exec: srt
args: [-p, rust, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl crates.io allowed | curl -sf https://crates.io | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
