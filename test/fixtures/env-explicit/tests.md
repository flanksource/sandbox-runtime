---
exec: srt
args: [-d, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| explicit env var visible | bash -c "echo $SRT_TEST_FOO" | 0 | stdout.contains("bar") |
| host env not leaked | bash -c "echo __${LANG}__" | 0 | stdout.trim() == "____" |
