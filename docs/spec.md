# Technical Specification

## Provider Signature Methods

Survey of each provider's signature scheme. This is the basis for the Provider adapter design.

| Provider | Header | Algorithm | Encoding | Timestamp | Signed content | Replay prevention |
|----------|--------|-----------|----------|-----------|---------------|-------------------|
| **Stripe** | `Stripe-Signature` | HMAC-SHA256 | hex | `t=<ts>,v1=<sig>` format in header | `{timestamp}.{rawBody}` | 5 min (default) |
| **GitHub** | `X-Hub-Signature-256` | HMAC-SHA256 | hex (`sha256=` prefix) | None | rawBody | None |
| **Slack** | `X-Slack-Signature` | HMAC-SHA256 | hex (`v0=` prefix) | `X-Slack-Request-Timestamp` | `v0:{timestamp}:{rawBody}` | 5 min |
| **Shopify** | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 | base64 | None | rawBody | None |
| **Twilio** | `X-Twilio-Signature` | HMAC-**SHA1** | base64 | None | URL + sorted POST params | None |

### Pattern Analysis

1. **Algorithm**: Almost all use HMAC-SHA256. Twilio is the exception with SHA-1
2. **Encoding**: Hex (Stripe/GitHub/Slack) and base64 (Shopify/Twilio) are mixed
3. **Timestamp**: Only Stripe and Slack include timestamps for replay attack prevention
4. **Signature format**: Diverse — prefix (`sha256=`, `v0=`), compound header (`t=...,v1=...`), and plain
5. **Twilio's uniqueness**: Signs URL + sorted POST parameters instead of raw body

## Public API Design

### Basic Usage

```ts
import { Hono } from 'hono'
import { webhookVerify } from 'hono-webhook-verify'
import { stripe } from 'hono-webhook-verify/providers/stripe'

const app = new Hono()

app.post('/webhook/stripe', webhookVerify({
  provider: stripe({ secret: 'whsec_...' }),
}), (c) => {
  const payload = c.get('webhookPayload') // Parsed payload
  // ...
})
```

### Providers

```ts
import { github } from 'hono-webhook-verify/providers/github'
import { slack } from 'hono-webhook-verify/providers/slack'
import { shopify } from 'hono-webhook-verify/providers/shopify'
import { twilio } from 'hono-webhook-verify/providers/twilio'

// GitHub
app.post('/webhook/github', webhookVerify({
  provider: github({ secret: 'gh_webhook_secret' }),
}), handler)

// Slack
app.post('/webhook/slack', webhookVerify({
  provider: slack({ signingSecret: 'slack_signing_secret' }),
}), handler)

// Shopify
app.post('/webhook/shopify', webhookVerify({
  provider: shopify({ secret: 'shopify_client_secret' }),
}), handler)

// Twilio
app.post('/webhook/twilio', webhookVerify({
  provider: twilio({ authToken: 'twilio_auth_token' }),
}), handler)
```

### Full Options

```ts
webhookVerify({
  provider: stripe({
    secret: 'whsec_...',
    tolerance: 300,         // Timestamp tolerance in seconds. Default: 300 (5 min)
  }),
  onError: (error, c) => { // Custom error handling
    return c.json({ error: error.message }, 401)
  },
})
```

### Custom Provider

Support for custom webhook signature schemes:

```ts
import { webhookVerify, defineProvider } from 'hono-webhook-verify'

const myProvider = defineProvider({
  name: 'my-service',
  async verify({ rawBody, headers, secret }) {
    const signature = headers.get('X-My-Signature')
    if (!signature) return { valid: false, reason: 'Missing signature header' }

    const expected = await hmacSha256(secret, rawBody)
    const valid = await timingSafeEqual(signature, expected)
    return { valid }
  },
})

app.post('/webhook/custom', webhookVerify({
  provider: myProvider({ secret: 'my_secret' }),
}), handler)
```

### Context Access

```ts
app.post('/webhook/stripe', webhookVerify({ provider: stripe({ secret }) }), (c) => {
  // Verified raw body (string)
  const rawBody = c.get('webhookRawBody')

  // Parsed JSON (when the provider sends JSON)
  const payload = c.get('webhookPayload')

  // Provider name
  const provider = c.get('webhookProvider') // 'stripe'
})
```

## Error Responses

RFC 9457 Problem Details format (consistent with hono-idempotency):

```json
{
  "type": "https://hono-webhook-verify.dev/errors/invalid-signature",
  "title": "Webhook signature verification failed",
  "status": 401,
  "detail": "The signature in the Stripe-Signature header does not match the expected value"
}
```

| Error | Status | Type suffix |
|-------|--------|-------------|
| Missing signature header | 401 | `/errors/missing-signature` |
| Signature mismatch | 401 | `/errors/invalid-signature` |
| Timestamp expired | 401 | `/errors/timestamp-expired` |
| Body read failure | 400 | `/errors/body-read-failed` |

### Why 401, not 403

Webhook signature verification failure is an "authentication failure" — it means the sender
could not prove they are the genuine provider. 403 means "authenticated but insufficient
permissions", which has a different meaning. Stripe and GitHub official docs also recommend
401-class responses.
