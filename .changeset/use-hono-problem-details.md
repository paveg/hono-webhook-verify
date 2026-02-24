---
"hono-webhook-verify": minor
---

Add hono-problem-details as optional peerDependency and fix Content-Type

- Declare `hono-problem-details` as optional peerDependency for ecosystem compatibility
- Fix Content-Type: default error responses now return `application/problem+json` (was `application/json`)
- `onError` callback signature unchanged (backward-compatible)
