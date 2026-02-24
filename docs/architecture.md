# Architecture

## Module Structure

```
hono-webhook-verify/
├── src/
│   ├── index.ts              # Entry point, re-exports (webhookVerify, defineProvider)
│   ├── middleware.ts          # createMiddleware()-based middleware core
│   ├── crypto.ts             # Web Crypto API wrappers (HMAC, timingSafeEqual)
│   ├── types.ts              # Shared type definitions
│   ├── errors.ts             # RFC 9457 Problem Details errors
│   ├── detect.ts             # Provider auto-detection from headers
│   └── providers/
│       ├── types.ts           # Provider interface
│       ├── stripe.ts
│       ├── github.ts
│       ├── slack.ts
│       ├── shopify.ts
│       ├── twilio.ts
│       ├── line.ts
│       ├── discord.ts
│       └── standard-webhooks.ts
├── tests/
│   ├── middleware.test.ts     # Middleware integration tests
│   ├── crypto.test.ts
│   ├── detect.test.ts
│   ├── define-provider.test.ts
│   ├── errors.test.ts
│   ├── providers/
│   │   ├── stripe.test.ts
│   │   ├── github.test.ts
│   │   ├── slack.test.ts
│   │   ├── shopify.test.ts
│   │   ├── twilio.test.ts
│   │   ├── line.test.ts
│   │   ├── discord.test.ts
│   │   └── standard-webhooks.test.ts
│   └── helpers/
│       ├── signatures.ts     # Test signature generation utilities
│       └── constants.ts      # Shared test constants
├── biome.json
├── tsconfig.json
├── package.json
└── vitest.config.ts
```

## Provider Interface

The extensibility point equivalent to the Store interface in hono-idempotency.
Absorbs per-provider signature differences.

```ts
/** Provider verification result */
interface VerifyResult {
  valid: boolean
  reason?: string  // Failure reason (used for error messages)
}

/** Context passed to provider's verify method */
interface VerifyContext {
  rawBody: string
  headers: Headers
  url?: string       // For Twilio (URL is part of the signed content)
}

/** Webhook provider definition */
interface WebhookProvider {
  name: string
  verify(ctx: VerifyContext): Promise<VerifyResult>
}

/** Provider factory function type */
type ProviderFactory<T> = (options: T) => WebhookProvider
```

### Why Provider pattern, not Store pattern

hono-idempotency needs to **maintain state** between requests → Store (get/lock/complete/delete).
hono-webhook-verify **completes verification within a single request** → Provider (verify only).
The interface is intentionally kept simple since there is no state management.

## Middleware Flow

```
Request (POST /webhook/stripe)
  │
  ├─ rawBody = await c.req.text()
  │   └─ Read failure → 400 Body Read Failed
  │
  ├─ provider.verify({ rawBody, headers, url })
  │   ├─ { valid: true }
  │   │   ├─ c.set('webhookRawBody', rawBody)
  │   │   ├─ c.set('webhookPayload', JSON.parse(rawBody))  // try-catch
  │   │   ├─ c.set('webhookProvider', provider.name)
  │   │   └─ next()
  │   │
  │   └─ { valid: false, reason }
  │       └─ 401 (mapped to missing-signature / invalid-signature / timestamp-expired)
  │
  └─ Response
```

### Comparison with hono-idempotency

| Aspect | hono-idempotency | hono-webhook-verify |
|--------|-----------------|-------------------|
| Flow complexity | High (lock → next → complete/delete) | Low (verify → next) |
| State management | Yes (Store) | None |
| Error branches | 5 patterns (400/409/422 + 2xx/error) | 3 patterns (400/401) |
| Post-next() processing | Captures and stores response | None |

## Design Decisions

### HMAC Verification with Web Crypto API

Same decision as hono-idempotency's fingerprinting:
Uses `crypto.subtle.importKey()` + `crypto.subtle.sign()`.
Does not use Node.js `crypto.createHmac()` → compatible with Cloudflare Workers / Deno / Bun.

```ts
async function hmac(algorithm: 'SHA-256' | 'SHA-1', secret: string, data: string): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: algorithm },
    false,
    ['sign'],
  )
  return crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
}
```

### Timing-Safe Comparison

Signature comparison must be done in **constant time**. Regular `===` is vulnerable to side-channel attacks.

Delegates to the runtime's native `crypto.subtle.timingSafeEqual` (Node.js >= 19, Deno,
Cloudflare Workers). Falls back to a pure-JS XOR accumulator only as a last resort.

```ts
function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false
  // Use native implementation when available
  if (typeof crypto.subtle.timingSafeEqual === 'function') {
    return crypto.subtle.timingSafeEqual(a, b)
  }
  // XOR fallback
  const viewA = new Uint8Array(a)
  const viewB = new Uint8Array(b)
  let diff = 0
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i]
  }
  return diff === 0
}
```

### Raw Body Retrieval

The biggest pitfall in webhook signature verification:
if a framework parses the body, the signature won't match.

In Hono, `c.req.text()` retrieves the raw body, so this is not a problem.
In Express, `express.raw()` was required — Hono's approach is a natural fit and a differentiation point.

However, **`c.req.text()` can only be called once**.
The middleware stores the consumed raw body via `c.set('webhookRawBody', rawBody)`
so downstream handlers can reuse it.

### Twilio's Special Handling

Twilio differs fundamentally from other providers:
- Algorithm: SHA-1 (others use SHA-256)
- Signed content: URL + sorted POST parameters (others sign raw body)

The `url` field in the Provider interface exists specifically for this.
Only the Twilio provider uses `c.req.url` for signature verification.

### Error Response Granularity

The `reason` field classifies failure causes:
- `missing-signature`: Header is absent → likely a configuration error
- `invalid-signature`: Signature mismatch → wrong secret or tampering
- `timestamp-expired`: Timestamp too old → replay attack or clock skew

This makes debugging easier for developers.

## Package Configuration

### exports (package.json)

```json
{
  "exports": {
    ".": "./dist/index.js",
    "./providers/stripe": "./dist/providers/stripe.js",
    "./providers/github": "./dist/providers/github.js",
    "./providers/slack": "./dist/providers/slack.js",
    "./providers/shopify": "./dist/providers/shopify.js",
    "./providers/twilio": "./dist/providers/twilio.js",
    "./providers/line": "./dist/providers/line.js",
    "./providers/discord": "./dist/providers/discord.js",
    "./providers/standard-webhooks": "./dist/providers/standard-webhooks.js"
  }
}
```

Same subpath export strategy as hono-idempotency:
- Unused providers are not included in the bundle
- Adding new providers does not affect existing code

### Build

- Built with tsup (ESM + CJS dual output)
- Same configuration as hono-idempotency

### peerDependencies

```json
{
  "peerDependencies": {
    "hono": ">=4.0.0"
  }
}
```
