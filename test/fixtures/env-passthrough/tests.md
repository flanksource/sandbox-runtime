---
exec: srt
args: [-d, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| passthrough var visible when set | bash -c "echo __${SRT_TEST_PASSTHROUGH}__" | 0 | |
| non-passthrough var not visible | bash -c "echo __${LANG}__" | 0 | stdout.trim() == "____" |
