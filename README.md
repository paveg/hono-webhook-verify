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

import type { WebhookVerifyVariables } from "hono-webhook-verify";

const app = new Hono<{ Variables: WebhookVerifyVariables }>();

app.post(
  "/webhooks/stripe",
  webhookVerify({
    provider: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
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

Use `defineProvider()` with the built-in crypto utilities to create a provider for any webhook source:

```ts
import {
  defineProvider,
  webhookVerify,
  hmac,
  fromHex,
  timingSafeEqual,
} from "hono-webhook-verify";

const myProvider = defineProvider<{ secret: string }>((options) => ({
  name: "my-service",
  async verify({ rawBody, headers }) {
    const signature = headers.get("X-My-Signature");
    if (!signature) {
      return { valid: false, reason: "missing-signature" };
    }
    const expected = await hmac("SHA-256", options.secret, rawBody);
    const received = fromHex(signature);
    if (!received || !timingSafeEqual(expected, received)) {
      return { valid: false, reason: "invalid-signature" };
    }
    return { valid: true };
  },
}));

app.post(
  "/webhooks/my-service",
  webhookVerify({ provider: myProvider({ secret: "..." }) }),
  (c) => c.json({ ok: true }),
);
```

Available crypto utilities: `hmac`, `toHex`, `fromHex`, `toBase64`, `fromBase64`, `timingSafeEqual`.

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
  "type": "https://hono-webhook-verify.dev/errors/missing-signature",
  "title": "Missing webhook signature",
  "status": 401,
  "detail": "Required webhook signature header is missing"
}
```

When [hono-problem-details](https://github.com/paveg/hono-problem-details) is installed, error responses are generated using its `problemDetails().getResponse()`. Otherwise, a built-in fallback is used. No configuration needed — detection is automatic.

Use the `onError` callback for custom error responses:

```ts
// Logging
webhookVerify({
  provider: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
  onError: (error, c) => {
    console.error("Webhook verification failed:", error.title, error.detail);
    return c.json({ error: "Invalid webhook" }, 401);
  },
});
```

```ts
// Custom error response with logging
webhookVerify({
  provider: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
  onError: (error, c) => {
    console.error("Webhook verification failed:", error.detail);
    return c.json({ error: error.title }, error.status as 400 | 401);
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

### Multi-Provider Endpoint

Handle multiple webhook providers on a single endpoint:

```ts
import { Hono } from "hono";
import { detectProvider, webhookVerify } from "hono-webhook-verify";
import type { WebhookVerifyVariables } from "hono-webhook-verify";
import { github } from "hono-webhook-verify/providers/github";
import { stripe } from "hono-webhook-verify/providers/stripe";

const providers = {
  stripe: stripe({ secret: process.env.STRIPE_WEBHOOK_SECRET! }),
  github: github({ secret: process.env.GITHUB_WEBHOOK_SECRET! }),
};

const app = new Hono<{ Variables: WebhookVerifyVariables }>();

app.post("/webhooks", async (c, next) => {
  const name = detectProvider(c.req.raw.headers);
  const provider = name ? providers[name as keyof typeof providers] : undefined;
  if (!provider) {
    return c.json({ error: "Unknown webhook provider" }, 400);
  }
  return webhookVerify({ provider })(c, next);
}, (c) => {
  const provider = c.get("webhookProvider");
  const payload = c.get("webhookPayload");
  console.log(`Received ${provider} webhook`);
  return c.json({ received: true });
});
```

## Runtime Examples

### Cloudflare Workers

```ts
import { Hono } from "hono";
import { webhookVerify } from "hono-webhook-verify";
import type { WebhookVerifyVariables } from "hono-webhook-verify";
import { stripe } from "hono-webhook-verify/providers/stripe";

type Bindings = { STRIPE_WEBHOOK_SECRET: string };

const app = new Hono<{ Bindings: Bindings; Variables: WebhookVerifyVariables }>();

app.post("/webhooks/stripe", (c, next) => {
  const middleware = webhookVerify({
    provider: stripe({ secret: c.env.STRIPE_WEBHOOK_SECRET }),
  });
  return middleware(c, next);
}, (c) => {
  return c.json({ received: true });
});

export default app;
```

### Deno

```ts
import { Hono } from "npm:hono";
import { webhookVerify } from "npm:hono-webhook-verify";
import { github } from "npm:hono-webhook-verify/providers/github";

const app = new Hono();

app.post("/webhooks/github",
  webhookVerify({
    provider: github({ secret: Deno.env.get("GITHUB_WEBHOOK_SECRET")! }),
  }),
  (c) => c.json({ received: true }),
);

Deno.serve(app.fetch);
```

### Bun

```ts
import { Hono } from "hono";
import { webhookVerify } from "hono-webhook-verify";
import { github } from "hono-webhook-verify/providers/github";

const app = new Hono();

app.post("/webhooks/github",
  webhookVerify({
    provider: github({ secret: Bun.env.GITHUB_WEBHOOK_SECRET! }),
  }),
  (c) => c.json({ received: true }),
);

export default app;
```

## Troubleshooting

### Signature verification fails

- **Check the secret format**: Stripe uses `whsec_...` prefix. Standard Webhooks secrets are base64-encoded (with optional `whsec_` prefix). Discord requires a hex-encoded Ed25519 public key.
- **Don't read the body before the middleware**: `webhookVerify` reads `c.req.text()` internally. If another middleware consumes the body first, verification will fail because the raw body won't match the signature.
- **Environment variables**: Ensure your secret is loaded correctly. An extra newline or whitespace in `.env` can cause mismatches.

### Timestamp expired

- **Clock skew**: Ensure your server's clock is synchronized (NTP). Providers like Stripe, Slack, and Standard Webhooks include timestamps and reject if the difference exceeds the tolerance (default: 300 seconds).
- **Increase tolerance**: If your processing pipeline has high latency, increase the `tolerance` option:
  ```ts
  stripe({ secret: "whsec_...", tolerance: 600 }) // 10 minutes
  ```

### Empty secret error

All providers validate that the secret is non-empty at construction time. If you see `"<provider>: secret must not be empty"`, check that your environment variable is set and not undefined.

### Twilio verification fails in production

Twilio signs the full request URL including the protocol and host. Behind a reverse proxy, `c.req.url` may report `http://` instead of `https://`. Ensure your proxy sets the correct `X-Forwarded-Proto` header and your app reconstructs the correct URL.

## Security

- All signature comparisons use constant-time comparison (`crypto.subtle.timingSafeEqual` when available, XOR fallback otherwise)
- Signatures are decoded to raw bytes before comparison to prevent timing leaks from string operations
- Timestamp-based providers (Stripe, Slack, Standard Webhooks) reject expired signatures to prevent replay attacks
- Discord uses Ed25519 asymmetric verification via `crypto.subtle.verify`

## License

[MIT](LICENSE)
