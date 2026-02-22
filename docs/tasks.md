# Implementation Tasks

## Tooling（hono-idempotency と同一）

- [x] biome (lint + format)
- [x] TypeScript (strict mode)
- [x] vitest (テストランナー)
- [x] tsup (ビルド)
- [x] changesets (バージョニング・リリース)

## Test Guardrails

hono-idempotency とは異なり、参照実装となるライブラリがないため、
各プロバイダー公式ドキュメントの仕様をガードレールとする。

### 各プロバイダー共通テスト (P1〜P7)

**すべてのプロバイダー実装で同じテストパターンを通す**（hono-idempotency の S1〜S6 と同じ思想）。

| # | テストケース | 期待動作 | 優先度 |
|---|-------------|---------|-------|
| P1 | 正しい secret + 正しい body → 検証成功 | `{ valid: true }` | **必須** |
| P2 | 正しい secret + 改竄された body → 検証失敗 | `{ valid: false }` | **必須** |
| P3 | 誤った secret + 正しい body → 検証失敗 | `{ valid: false }` | **必須** |
| P4 | 署名ヘッダー未指定 → 検証失敗 | `{ valid: false, reason: 'missing-signature' }` | **必須** |
| P5 | 空文字列のボディ → 検証成功（署名が正しい場合） | `{ valid: true }` | 中 |
| P6 | マルチバイト文字を含むボディ → 検証成功 | UTF-8 エンコーディング整合性 | 中 |
| P7 | 大きなボディ (1MB) → 検証成功 | パフォーマンス問題なし | 低 |

### タイムスタンプ付きプロバイダー追加テスト (T1〜T3)

Stripe, Slack のみ。

| # | テストケース | 期待動作 | 優先度 |
|---|-------------|---------|-------|
| T1 | 現在時刻のタイムスタンプ → 検証成功 | tolerance 内 | **必須** |
| T2 | 6分前のタイムスタンプ (tolerance=300s) → 検証失敗 | `{ valid: false, reason: 'timestamp-expired' }` | **必須** |
| T3 | カスタム tolerance 設定 → 設定値が反映される | tolerance=60 で 2分前 → 失敗 | **必須** |

### Twilio 固有テスト (TW1〜TW2)

| # | テストケース | 期待動作 | 優先度 |
|---|-------------|---------|-------|
| TW1 | URL + ソート済み POST パラメータで署名検証 | 正しい署名で成功 | **必須** |
| TW2 | パラメータ順序が異なる → ソート後の検証で成功 | ソートロジックの正確性 | **必須** |

### ミドルウェア統合テスト (M1〜M8)

`app.request()` を使った HTTP レベルのテスト。

| # | テストケース | 期待動作 | ステータス | 優先度 |
|---|-------------|---------|----------|-------|
| M1 | 正しい署名 → ハンドラー実行 | 200 + ハンドラーの戻り値 | 200 | **必須** |
| M2 | 不正な署名 → 401 | RFC 9457 エラー | 401 | **必須** |
| M3 | 署名ヘッダーなし → 401 | `missing-signature` | 401 | **必須** |
| M4 | タイムスタンプ期限切れ → 401 | `timestamp-expired` | 401 | **必須** |
| M5 | `c.get('webhookRawBody')` で raw body 取得 | 元の body と一致 | — | **必須** |
| M6 | `c.get('webhookPayload')` で JSON 取得 | パース済みオブジェクト | — | **必須** |
| M7 | `c.get('webhookProvider')` でプロバイダー名取得 | `'stripe'` 等 | — | **必須** |
| M8 | `onError` カスタムエラーハンドリング | カスタムレスポンス | — | 中 |

### crypto ユーティリティテスト (CR1〜CR3)

| # | テストケース | 期待動作 | 優先度 |
|---|-------------|---------|-------|
| CR1 | HMAC-SHA256 の hex 出力が既知値と一致 | RFC テストベクター検証 | **必須** |
| CR2 | HMAC-SHA1 の base64 出力が既知値と一致 | Twilio 用 | **必須** |
| CR3 | timingSafeEqual: 一致 → true、不一致 → false、長さ違い → false | 定数時間比較 | **必須** |

### テスト戦略: 署名生成ヘルパー

テストでは各プロバイダーの「本物の署名」を生成するヘルパーを用意する。
これにより外部サービスへの依存なしでテストが完結する。

```ts
// tests/helpers/signatures.ts
export async function generateStripeSignature(body: string, secret: string, timestamp?: number): Promise<string>
export async function generateGitHubSignature(body: string, secret: string): Promise<string>
export async function generateSlackSignature(body: string, secret: string, timestamp?: number): Promise<string>
export async function generateShopifySignature(body: string, secret: string): Promise<string>
export async function generateTwilioSignature(url: string, params: Record<string, string>, authToken: string): Promise<string>
```

hono-idempotency で学んだこと:
外部サービスのモック（miniflare 等）よりも、最小インターフェースに対するテストの方が
セットアップが軽く、メンテナンスしやすい。
ここでは「署名生成ヘルパー = テスト用の trusted source」として機能する。

## Phase 1: Core + 2 Providers (Week 1)

TDD で進める。テスト → 実装 → リファクタの順。

### 1.1 プロジェクトセットアップ
- [x] リポジトリ作成、package.json、tsconfig.json、biome.json
- [x] vitest + tsup の設定
- [x] CI (GitHub Actions): lint, test, build

### 1.2 型定義・Provider インターフェース
- [x] `src/types.ts` — WebhookVerifyOptions, VerifyResult
- [x] `src/providers/types.ts` — WebhookProvider, ProviderFactory, VerifyContext

### 1.3 crypto ユーティリティ
- [x] `tests/crypto.test.ts` を先に書く (CR1〜CR3)
- [x] `src/crypto.ts` — hmac(), timingSafeEqual(), toHex(), toBase64()
- [x] テスト: RFC テストベクターで検証

### 1.4 Stripe Provider
- [x] `tests/helpers/signatures.ts` — generateStripeSignature()
- [x] `tests/providers/stripe.test.ts` を先に書く (P1〜P6 + T1〜T3)
- [x] `src/providers/stripe.ts`
- [x] Stripe-Signature ヘッダーのパース (`t=...,v1=...`)
- [x] タイムスタンプ付き署名検証

### 1.5 GitHub Provider
- [x] `tests/providers/github.test.ts` を先に書く (P1〜P6)
- [x] `src/providers/github.ts`
- [x] `sha256=` prefix のパース

### 1.6 ミドルウェア本体
- [x] `tests/middleware.test.ts` を先に書く (M1〜M8)
- [x] `src/middleware.ts` — createMiddleware() ベース
- [x] テスト: Stripe + GitHub で M1〜M8 をカバー

### 1.7 エラーレスポンス
- [x] `src/errors.ts` — RFC 9457 Problem Details

## Phase 2: Remaining Providers (Week 2)

プロバイダー追加は P1〜P6 の共通テストスイートで品質担保。

### 2.1 Slack Provider
- [x] `tests/providers/slack.test.ts` (P1〜P6 + T1〜T3)
- [x] `src/providers/slack.ts`
- [x] `v0=` prefix + タイムスタンプ連結

### 2.2 Shopify Provider
- [x] `tests/providers/shopify.test.ts` (P1〜P6)
- [x] `src/providers/shopify.ts`
- [x] base64 エンコーディング

### 2.3 Twilio Provider
- [x] `tests/providers/twilio.test.ts` (P1〜P4 + TW1〜TW2)
- [x] `src/providers/twilio.ts`
- [x] HMAC-SHA1 + URL + sorted params

### 2.4 defineProvider()
- [x] カスタムプロバイダー定義のヘルパー関数
- [x] テスト: カスタムプロバイダーで M1〜M3 が通ること

## Phase 3: Publish & Promote (Week 3)

### 3.1 パッケージング
- [x] README.md (English) — "Verify webhooks from any provider with one line"
- [x] LICENSE (MIT)
- [x] サブパスエクスポート設定
- [x] npm publish (release workflow) + JSR publish (manual)

### 3.2 Hono 公式への PR
- [ ] honojs/middleware リポジトリに third-party 掲載 PR
- [ ] Hono Discord で告知

### 3.3 プロモーション
- [ ] X/Twitter で告知
- [ ] Reddit r/node, r/cloudflare に投稿
- [ ] dev.to / Zenn に解説記事
- [ ] hono-idempotency の README に "See Also" で相互リンク

## Stretch Goals

- [x] LINE Provider
- [x] Discord Provider
- [ ] PayPal Provider
- [x] Standard Webhooks (svix 互換) Provider
- [ ] プロバイダー自動検出（ヘッダーからプロバイダーを推定）
- [x] CONTRIBUTING.md — プロバイダー追加ガイド（コントリビューション誘引）
