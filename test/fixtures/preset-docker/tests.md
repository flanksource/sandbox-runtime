---
exec: srt
args: [-p, docker, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl hub.docker.com allowed | curl -sf https://hub.docker.com | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
