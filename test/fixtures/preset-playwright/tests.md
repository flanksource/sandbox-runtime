---
exec: srt
args: [-p, playwright, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| write to test-results allowed | bash -c "mkdir -p test-results && touch test-results/srt-test && rm test-results/srt-test && rmdir test-results" | 0 | |
| PWDEBUG passthrough | bash -c "echo __${PWDEBUG}__" | 0 | |
