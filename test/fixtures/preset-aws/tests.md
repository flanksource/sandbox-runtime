---
exec: srt
args: [-p, aws, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| curl sts.amazonaws.com allowed | curl -sf https://sts.amazonaws.com | 0 | |
| curl pypi.org denied | curl -sf https://pypi.org | != 0 | |
| AWS_REGION passthrough | bash -c "echo __${AWS_REGION}__" | 0 | stdout.contains("__us-") || stdout.trim() == "____" |
