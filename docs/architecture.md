# Architecture

## Module Structure

```
hono-webhook-verify/
├── src/
│   ├── index.ts              # エントリポイント、re-export (webhookVerify, defineProvider)
│   ├── middleware.ts          # createMiddleware() ベースのミドルウェア本体
│   ├── crypto.ts             # Web Crypto API ラッパー（HMAC, timingSafeEqual）
│   ├── types.ts              # 共通型定義
│   ├── errors.ts             # RFC 9457 Problem Details エラー
│   └── providers/
│       ├── types.ts           # Provider インターフェース
│       ├── stripe.ts
│       ├── github.ts
│       ├── slack.ts
│       ├── shopify.ts
│       └── twilio.ts
├── tests/
│   ├── middleware.test.ts     # ミドルウェア統合テスト
│   ├── crypto.test.ts
│   ├── providers/
│   │   ├── stripe.test.ts
│   │   ├── github.test.ts
│   │   ├── slack.test.ts
│   │   ├── shopify.test.ts
│   │   └── twilio.test.ts
│   └── helpers/
│       └── signatures.ts     # テスト用署名生成ユーティリティ
├── biome.json
├── tsconfig.json
├── package.json
└── vitest.config.ts
```

## Provider Interface

hono-idempotency の Store インターフェースに相当する拡張ポイント。
各プロバイダーの署名差異を吸収する。

```ts
/** プロバイダーの検証結果 */
interface VerifyResult {
  valid: boolean
  reason?: string  // 失敗時の理由（エラーメッセージに使用）
}

/** プロバイダーの verify に渡されるコンテキスト */
interface VerifyContext {
  rawBody: string
  headers: Headers
  secret: string
  url?: string       // Twilio 用（URL が署名対象に含まれるため）
}

/** プロバイダー定義 */
interface WebhookProvider {
  name: string
  verify(ctx: VerifyContext): Promise<VerifyResult>
}

/** プロバイダーファクトリ関数の型 */
type ProviderFactory<T> = (options: T) => WebhookProvider
```

### なぜ Store パターンではなく Provider パターンか

hono-idempotency はリクエスト間で**状態を保持**する必要がある → Store (get/lock/complete/delete)。
hono-webhook-verify はリクエスト単体で**検証が完結**する → Provider (verify のみ)。
状態管理がないため、インターフェースは意図的にシンプルに保つ。

## Middleware Flow

```
Request (POST /webhook/stripe)
  │
  ├─ rawBody = await c.req.text()
  │   └─ 読み取り失敗 → 400 Body Read Failed
  │
  ├─ provider.verify({ rawBody, headers, secret, url })
  │   ├─ { valid: true }
  │   │   ├─ c.set('webhookRawBody', rawBody)
  │   │   ├─ c.set('webhookPayload', JSON.parse(rawBody))  // try-catch
  │   │   ├─ c.set('webhookProvider', provider.name)
  │   │   └─ next()
  │   │
  │   └─ { valid: false, reason }
  │       └─ 401 (reason に応じて missing-signature / invalid-signature / timestamp-expired)
  │
  └─ Response
```

### hono-idempotency との比較

| 観点 | hono-idempotency | hono-webhook-verify |
|-----|-----------------|-------------------|
| フロー複雑度 | 高（lock → next → complete/delete） | 低（verify → next） |
| 状態管理 | あり（Store） | なし |
| エラー分岐 | 5パターン (400/409/422 + 2xx/error) | 3パターン (400/401) |
| next() 後の処理 | レスポンスをキャプチャして保存 | なし |

## Design Decisions

### Web Crypto API で HMAC 検証

hono-idempotency のフィンガープリントと同じ判断:
`crypto.subtle.importKey()` + `crypto.subtle.sign()` を使用。
Node.js の `crypto.createHmac()` は使わない → Cloudflare Workers / Deno / Bun 互換。

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

### タイミングセーフ比較

署名の比較は**定数時間**で行う。通常の `===` はサイドチャネル攻撃に脆弱。

Web Crypto API には `timingSafeEqual` がないため、自前実装が必要:

```ts
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i)
  }
  return result === 0
}
```

Node.js 環境では `crypto.timingSafeEqual()` が使えるが、
Edge 互換性のため Web Standards のみで実装する。

### Raw Body の取得

Webhook 署名検証の最大のハマりポイント。
フレームワークが body をパースすると署名が合わなくなる。

Hono では `c.req.text()` で raw body を取得できるため問題にならない。
Express では `express.raw()` が必要だった箇所が、Hono では自然に動く → 差別化ポイント。

ただし **`c.req.text()` は一度しか呼べない**。
ミドルウェアで消費した raw body を `c.set('webhookRawBody', rawBody)` で
コンテキストに保存し、後続ハンドラーが再利用できるようにする。

### Twilio の特殊処理

Twilio は他のプロバイダーと根本的に異なる:
- アルゴリズム: SHA-1（他は SHA-256）
- 署名対象: URL + ソート済み POST パラメータ（他は raw body）

Provider インターフェースの `url` フィールドはこのために存在する。
Twilio プロバイダーのみ `c.req.url` を使用して署名を検証する。

### エラーレスポンスの粒度

`reason` フィールドで失敗原因を分類:
- `missing-signature`: ヘッダーが存在しない → 設定ミスの可能性
- `invalid-signature`: 署名が不一致 → secret の不一致 or 改竄
- `timestamp-expired`: タイムスタンプ期限切れ → リプレイ攻撃 or クロック差

これにより開発者がデバッグしやすい。

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
    "./providers/twilio": "./dist/providers/twilio.js"
  }
}
```

hono-idempotency と同じサブパスエクスポート戦略:
- 使わないプロバイダーのコードをバンドルに含めない
- プロバイダー追加が既存コードに影響しない

### ビルド

- tsup でビルド（ESM + CJS dual output）
- hono-idempotency と同一構成

### peerDependencies

```json
{
  "peerDependencies": {
    "hono": ">=4.0.0"
  }
}
```
