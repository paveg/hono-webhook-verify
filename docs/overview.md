# hono-webhook-verify

Webhook signature verification middleware for Hono, covering major SaaS providers.
Absorbs per-provider HMAC differences so you can add verification in one line.

## Why

- Any API that receives webhooks must verify signatures, yet every provider uses different header names, algorithms, encodings, and timestamp formats
- Re-implementing verification from each provider's docs is error-prone and a security risk
- Express has per-provider libraries, but **there is no unified webhook verification middleware for Hono**
- Only `@nakanoaas/hono-linebot-middleware` (LINE-only) existed

## Positioning

> A middleware that lets developers building webhook endpoints with Hono
> complete signature verification just by specifying a provider. Web Crypto API-based, edge-ready.

## Competitive Landscape

| Approach | Hono support | Edge support | Multi-provider | Unified API |
|----------|-------------|-------------|----------------|-------------|
| Provider SDKs | No (Express/Node assumed) | Partial | One at a time | No |
| @nakanoaas/hono-linebot-middleware | Yes | Yes | LINE only | — |
| svix/svix-webhooks | No | No | Standard Webhooks only | Yes |
| **hono-webhook-verify** | **Yes** | **Yes** | **Stripe, GitHub, Slack, Shopify, Twilio, LINE, Discord, Standard Webhooks** | **Yes** |

## Differentiation

1. **Hono-native** — Built on `createMiddleware()` with type-safe context
2. **Edge-first** — Web Crypto API only, no Node.js crypto dependency
3. **Unified API** — Same middleware usage regardless of provider
4. **Zero external dependencies** — Only Hono as a peer dependency
5. **Timing-safe comparison** — Constant-time comparison to prevent side-channel attacks
6. **Easy provider addition** — Just implement the Provider interface

## Inspiration from hono-idempotency

| Practice | hono-idempotency | hono-webhook-verify |
|----------|-----------------|-------------------|
| Web Crypto API | Fingerprint (SHA-256) | HMAC signature verification (SHA-256/SHA-1) |
| Subpath exports | Store adapter separation | Provider adapter separation |
| Zero external deps | Yes | Yes |
| createMiddleware() | Yes | Yes |
| Type-safe context | `c.get('idempotencyKey')` | `c.get('webhookPayload')` |
| RFC 9457 errors | Yes | Yes |
| Tooling | biome + TS strict + vitest + tsup | Same |

## Success Metrics

- 30 days: Published to npm, PR submitted to Hono official third-party middleware list
- 90 days: 100+ GitHub stars, 500+ weekly downloads
- 180 days: 5+ providers supported, community-contributed provider additions
