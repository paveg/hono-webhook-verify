# Technical Specification

## Provider 署名方式一覧

各プロバイダーの署名方式を調査・整理した結果。これが Provider アダプタ設計の根拠。

| Provider | ヘッダー | アルゴリズム | エンコーディング | タイムスタンプ | 署名対象 | リプレイ防止 |
|----------|---------|------------|----------------|-------------|---------|-------------|
| **Stripe** | `Stripe-Signature` | HMAC-SHA256 | hex | `t=<ts>,v1=<sig>` 形式でヘッダーに含む | `{timestamp}.{rawBody}` | 5分 (default) |
| **GitHub** | `X-Hub-Signature-256` | HMAC-SHA256 | hex (`sha256=` prefix) | なし | rawBody | なし |
| **Slack** | `X-Slack-Signature` | HMAC-SHA256 | hex (`v0=` prefix) | `X-Slack-Request-Timestamp` | `v0:{timestamp}:{rawBody}` | 5分 |
| **Shopify** | `X-Shopify-Hmac-Sha256` | HMAC-SHA256 | base64 | なし | rawBody | なし |
| **Twilio** | `X-Twilio-Signature` | HMAC-**SHA1** | base64 | なし | URL + sorted POST params | なし |

### パターン分析

1. **アルゴリズム**: ほぼ全て HMAC-SHA256。Twilio のみ SHA-1
2. **エンコーディング**: hex (Stripe/GitHub/Slack) と base64 (Shopify/Twilio) が混在
3. **タイムスタンプ**: Stripe と Slack のみ。リプレイ攻撃防止に使用
4. **署名フォーマット**: prefix (`sha256=`, `v0=`)、複合ヘッダー (`t=...,v1=...`)、plain と多様
5. **Twilio の特殊性**: URL + ソート済み POST パラメータが署名対象。他と根本的に異なる

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
  const payload = c.get('webhookPayload') // パース済みペイロード
  // ...
})
```

### 各プロバイダー

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
    tolerance: 300,         // タイムスタンプ許容差（秒）。default: 300 (5分)
  }),
  onError: (error, c) => { // カスタムエラーハンドリング
    return c.json({ error: error.message }, 401)
  },
})
```

### カスタムプロバイダー

独自の Webhook 署名方式にも対応:

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
  // 検証済みの raw body（文字列）
  const rawBody = c.get('webhookRawBody')

  // パース済み JSON（プロバイダーがJSONの場合）
  const payload = c.get('webhookPayload')

  // プロバイダー名
  const provider = c.get('webhookProvider') // 'stripe'
})
```

## Error Responses

RFC 9457 Problem Details 形式（hono-idempotency と統一）:

```json
{
  "type": "https://hono-webhook-verify.dev/errors/invalid-signature",
  "title": "Webhook signature verification failed",
  "status": 401,
  "detail": "The signature in the Stripe-Signature header does not match the expected value"
}
```

| エラー | status | type suffix |
|-------|--------|-------------|
| 署名ヘッダー未指定 | 401 | `/errors/missing-signature` |
| 署名不一致 | 401 | `/errors/invalid-signature` |
| タイムスタンプ期限切れ | 401 | `/errors/timestamp-expired` |
| リクエストボディ読み取り失敗 | 400 | `/errors/body-read-failed` |

### なぜ 403 ではなく 401 か

Webhook 署名検証の失敗は「認証の失敗」。送信元が本物のプロバイダーであることを
証明できなかったことを意味する。403 は「認証済みだが権限不足」であり意味が異なる。
Stripe, GitHub の公式ドキュメントも 401 系のレスポンスを推奨している。
