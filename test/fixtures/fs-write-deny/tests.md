---
exec: srt  -d -c
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| write to /etc denied | bash -c "touch /etc/srt-test-file" | 1 | |
| write to $TMPDIR  allowed | bash -c "touch $TMPDIR/srt-test-file && rm $TMPDIR/srt-test-file" | 0 | |
| write to .tmp allowed | bash -c "touch .tmp/srt-test-file && rm .tmp/srt-test-file" | 0 | |
