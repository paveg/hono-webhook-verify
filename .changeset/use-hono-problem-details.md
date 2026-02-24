---
"hono-webhook-verify": minor
---

Add hono-problem-details as optional peerDependency with runtime fallback

- Declare `hono-problem-details` as optional peerDependency
- When installed: error responses use `problemDetails().getResponse()` from hono-problem-details
- When not installed: falls back to self-contained `new Response` implementation
- Fix Content-Type: default error responses now return `application/problem+json` (was `application/json`)
- Detection is lazy (first error path only) — no overhead on happy path
- `onError` callback signature unchanged (backward-compatible)
