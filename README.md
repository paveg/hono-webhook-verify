# hono-webhook-verify

[![npm version](https://img.shields.io/npm/v/hono-webhook-verify)](https://www.npmjs.com/package/hono-webhook-verify)
[![CI](https://github.com/paveg/hono-webhook-verify/actions/workflows/ci.yml/badge.svg)](https://github.com/paveg/hono-webhook-verify/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Webhook signature verification middleware for [Hono](https://hono.dev). Verify webhooks from any provider with one line.

Works on Cloudflare Workers, Deno, Bun, Node.js, and any platform that supports the Web Crypto API.

## Supported Providers

| Provider | Signature Header | Algorithm |
|----------|-----------------|-----------|
| **Stripe** | `Stripe-Signature` | HMAC-SHA256 + timestamp |
| **GitHub** | `X-Hub-Signature-256` | HMAC-SHA256 |
| **Slack** | `X-Slack-Signature` | HMAC-SHA256 + timestamp |
| **Shopify** | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 (base64) |
| **Twilio** | `X-Twilio-Signature` | HMAC-SHA1 + URL + params |
| **LINE** | `X-Line-Signature` | HMAC-SHA256 (base64) |
| **Discord** | `X-Signature-Ed25519` | Ed25519 |
| **Standard Webhooks** | `webhook-signature` | HMAC-SHA256 (svix-compatible) |
| **Custom** | Any | `defineProvider()` |

## Installation

```bash
npm install hono-webhook-verify
# or
pnpm add hono-webhook-verify
# or
bun add hono-webhook-verify
```

## Quick Start

```ts
import { Hono } from "hono";
import { webhookVerify } from "hono-webhook-verify";
import { stripe } from "hono-webhook-verify/providers/stripe";

const app = new Hono();

app.post(
  "/webhooks/stripe",
  webhookVerify({
    provider: stripe({ secret: "whsec_..." }),
  }),
  (c) => {
    const payload = c.get("webhookPayload");
    const rawBody = c.get("webhookRawBody");
    const provider = c.get("webhookProvider"); // "stripe"
    return c.json({ received: true });
  },
);

export default app;
```

## Providers

### Stripe

```ts
import { stripe } from "hono-webhook-verify/providers/stripe";

webhookVerify({
  provider: stripe({
    secret: "whsec_...",
    tolerance: 300, // optional: timestamp tolerance in seconds (default: 300)
  }),
});
```

### GitHub

```ts
import { github } from "hono-webhook-verify/providers/github";

webhookVerify({
  provider: github({ secret: "your-webhook-secret" }),
});
```

### Slack

```ts
import { slack } from "hono-webhook-verify/providers/slack";

webhookVerify({
  provider: slack({
    signingSecret: "your-signing-secret",
    tolerance: 300, // optional: timestamp tolerance in seconds (default: 300)
  }),
});
```

### Shopify

```ts
import { shopify } from "hono-webhook-verify/providers/shopify";

webhookVerify({
  provider: shopify({ secret: "your-webhook-secret" }),
});
```

### Twilio

```ts
import { twilio } from "hono-webhook-verify/providers/twilio";

webhookVerify({
  provider: twilio({ authToken: "your-auth-token" }),
});
```

### LINE

```ts
import { line } from "hono-webhook-verify/providers/line";

webhookVerify({
  provider: line({ channelSecret: "your-channel-secret" }),
});
```

### Discord

```ts
import { discord } from "hono-webhook-verify/providers/discord";

webhookVerify({
  provider: discord({ publicKey: "your-ed25519-public-key-hex" }),
});
```

### Standard Webhooks (svix-compatible)

```ts
import { standardWebhooks } from "hono-webhook-verify/providers/standard-webhooks";

webhookVerify({
  provider: standardWebhooks({
    secret: "whsec_...", // base64-encoded secret with optional whsec_ prefix
    tolerance: 300, // optional: timestamp tolerance in seconds (default: 300)
  }),
});
```

### Custom Provider

Use `defineProvider()` to create a provider for any webhook source:

```ts
import { defineProvider, webhookVerify } from "hono-webhook-verify";

const myProvider = defineProvider<{ secret: string }>((options) => ({
  name: "my-service",
  async verify({ rawBody, headers }) {
    const signature = headers.get("X-My-Signature");
    if (!signature) {
      return { valid: false, reason: "missing-signature" };
    }
    // Your verification logic here
    return { valid: true };
  },
}));

app.post(
  "/webhooks/my-service",
  webhookVerify({ provider: myProvider({ secret: "..." }) }),
  (c) => c.json({ ok: true }),
);
```

## Context Variables

After successful verification, the middleware sets these variables on the Hono context:

| Variable | Type | Description |
|----------|------|-------------|
| `webhookRawBody` | `string` | The raw request body |
| `webhookPayload` | `unknown` | Parsed JSON payload (or `null` if not JSON) |
| `webhookProvider` | `string` | Provider name (e.g., `"stripe"`, `"github"`) |

For TypeScript, use the `WebhookVerifyVariables` type:

```ts
import type { WebhookVerifyVariables } from "hono-webhook-verify";

const app = new Hono<{ Variables: WebhookVerifyVariables }>();
```

## Error Handling

By default, verification failures return a `401` response in [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457) format:

```json
{
  "type": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401",
  "title": "Unauthorized",
  "status": 401,
  "detail": "missing-signature"
}
```

Use the `onError` callback for custom error responses:

```ts
webhookVerify({
  provider: stripe({ secret: "whsec_..." }),
  onError: (error, c) => {
    console.error("Webhook verification failed:", error.detail);
    return c.json({ error: "Invalid webhook" }, 401);
  },
});
```

## Provider Auto-Detection

Use `detectProvider()` to identify the webhook source from request headers:

```ts
import { detectProvider } from "hono-webhook-verify";

const provider = detectProvider(request.headers);
// => "stripe" | "github" | "slack" | "shopify" | "twilio" | "line" | "discord" | "standard-webhooks" | null
```

## Security

- All signature comparisons use constant-time comparison (`crypto.subtle.timingSafeEqual` when available, XOR fallback otherwise)
- Signatures are decoded to raw bytes before comparison to prevent timing leaks from string operations
- Timestamp-based providers (Stripe, Slack, Standard Webhooks) reject expired signatures to prevent replay attacks
- Discord uses Ed25519 asymmetric verification via `crypto.subtle.verify`

## License

[MIT](LICENSE)
