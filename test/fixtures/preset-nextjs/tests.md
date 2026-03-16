---
exec: srt
args: [-p, nextjs, -c]
---

| Name | Args | Exit Code | CEL |
|------|------|-----------|-----|
| write to .next allowed | bash -c "mkdir -p .next && touch .next/srt-test && rm .next/srt-test && rmdir .next" | 0 | |
| NODE_ENV passthrough | bash -c "echo __${NODE_ENV}__" | 0 | |
