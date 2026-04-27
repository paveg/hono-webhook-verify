---
"hono-webhook-verify": patch
---

Documentation and metadata refresh:

- Document the `WebhookVerifyError` constructor helpers (`missingSignature`, `invalidSignature`, `timestampExpired`, `bodyReadFailed`) in the README's Error Handling section. These are public exports for users wrapping the middleware or building higher-level handlers.
- Add a `funding` field to `package.json` so npm and GitHub display the project's sponsor link.

No runtime or API changes — all exports and behavior are unchanged.
