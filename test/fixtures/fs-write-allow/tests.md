---
exec: srt
args: [-d, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| write to cwd allowed | bash -c "touch srt-test-file && rm srt-test-file" | 0 | |
| write to /usr denied | bash -c "touch /usr/srt-test-file" | != 0 | |
