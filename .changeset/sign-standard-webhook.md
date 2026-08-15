---
"hono-webhook-verify": minor
---

Add `signStandardWebhook()` to `hono-webhook-verify/providers/standard-webhooks`, mirroring `standardWebhooks()`'s verification logic to produce the `webhook-id` / `webhook-timestamp` / `webhook-signature` headers a sender needs. Accepts `secret` or a `secrets` array — the latter emits one space-separated `v1,` signature per secret for key rotation, matching the format the verifier already accepts.
