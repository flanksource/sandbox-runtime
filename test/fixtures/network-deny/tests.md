---
exec: srt
args: [-s, ./.sandbox.yaml]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl denied domain | [-c, "curl -sf https://github.com"] | != 0 | |
