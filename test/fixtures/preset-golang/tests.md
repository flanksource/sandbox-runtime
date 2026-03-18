---
exec: srt
args: [-p, golang, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl proxy.golang.org allowed | curl -sf https://proxy.golang.org | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
| GOPATH env visible | bash -c "echo $GOPATH" | 0 | stdout.trim() != "" |
