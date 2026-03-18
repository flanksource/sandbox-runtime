---
exec: srt
args: [-d, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| read ~/.ssh denied | bash -c "cat ~/.ssh/id_rsa" | != 0 | |
| read /etc/hostname allowed | bash -c "cat /etc/hosts" | 0 | |
