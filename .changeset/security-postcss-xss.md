---
"hono-webhook-verify": patch
---

Refresh `postcss` (transitive dev dependency via `tsup`) from 8.5.6 to 8.5.13 to resolve Dependabot alert GHSA-qx2v-qp2m-jg93 / CVE-2026-41305 (XSS via unescaped `</style>` in CSS stringify output). No runtime or API changes — `postcss` is only used at build time and is not part of the published package.
