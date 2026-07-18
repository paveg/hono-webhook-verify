---
"hono-webhook-verify": patch
---

Internal cleanup from the Biome 2 migration: removed unused test imports, reordered module exports, and excluded local editor state from lint. No behavioral change, but bundle module ordering in `dist` differs from the previous release.
