---
exec: srt
args: [-p, npm, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl registry.npmjs.org allowed | curl -sf https://registry.npmjs.org | 0 | |
| curl crates.io denied | curl -sf https://crates.io | != 0 | |
