---
"hono-webhook-verify": patch
---

Raise the `hono` peerDependency and devDependency floor to `>=4.13.7` / `^4.13.7`. Versions between 4.12.34 and 4.13.6 are affected by four moderate-severity advisories fixed upstream in 4.13.5 and 4.13.7: a query-parser fragment-handling differential (GHSA-crvj-82cr-hjcx), an incomplete `toSSG()` path-traversal fix (GHSA-gqvv-2mrq-wpjv), unbounded dot-notation expansion in `parseBody()` (GHSA-g6gw-c38x-mqfc), and an XSS in `hono/jsx` `Suspense`/`ErrorBoundary`/`Context.Provider` (GHSA-hxh3-vqpv-xpqv). Consumers should upgrade their `hono` dependency to `>=4.13.7`.
