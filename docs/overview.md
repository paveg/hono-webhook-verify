# hono-webhook-verify

主要 SaaS の Webhook 署名検証ミドルウェア for Hono。
プロバイダーごとの HMAC 差異を吸収し、1行で導入できる。

## Why

- Webhook を受け取る API は署名検証が必須。しかしプロバイダーごとにヘッダー名、アルゴリズム、エンコーディング、タイムスタンプ形式がすべて異なる
- 毎回公式ドキュメントを読んで実装するのは非効率で、実装ミスによるセキュリティリスクがある
- Express 向けにはプロバイダー個別のライブラリはあるが、**統一的な Webhook 検証ミドルウェアは Hono にゼロ**
- LINE Bot 専用 (`@nakanoaas/hono-linebot-middleware`) のみ存在

## Positioning

> Hono で Webhook エンドポイントを作る開発者が、プロバイダーを指定するだけで
> 署名検証を完了できるミドルウェア。Web Crypto API ベースでエッジ環境対応。

## Competitive Landscape

| アプローチ | Hono対応 | Edge対応 | 複数プロバイダー | 統一API |
|-----------|---------|---------|----------------|---------|
| 各プロバイダー公式SDK | No (Express/Node前提) | 一部のみ | 1つずつ個別 | No |
| @nakanoaas/hono-linebot-middleware | Yes | Yes | LINE のみ | — |
| svix/svix-webhooks | No | No | Standard Webhooks のみ | Yes |
| **hono-webhook-verify** | **Yes** | **Yes** | **Stripe, GitHub, Slack, Shopify, Twilio...** | **Yes** |

## Differentiation

1. **Hono ネイティブ** — `createMiddleware()` ベース、型安全なコンテキスト
2. **Edge-first** — Web Crypto API のみ使用、Node.js crypto 不要
3. **統一 API** — プロバイダーを切り替えてもミドルウェアの使い方は同一
4. **ゼロ外部依存** — Hono 本体以外の依存なし
5. **タイミングセーフ比較** — 定数時間比較でサイドチャネル攻撃を防止
6. **プロバイダー追加が容易** — Provider インターフェース実装のみで対応可能

## hono-idempotency からの横展開

| プラクティス | hono-idempotency | hono-webhook-verify |
|-------------|-----------------|-------------------|
| Web Crypto API | フィンガープリント (SHA-256) | HMAC 署名検証 (SHA-256/SHA-1) |
| サブパスエクスポート | Store アダプタ分離 | Provider アダプタ分離 |
| ゼロ外部依存 | ✓ | ✓ |
| createMiddleware() | ✓ | ✓ |
| 型安全コンテキスト | `c.get('idempotencyKey')` | `c.get('webhookPayload')` |
| RFC 9457 エラー | ✓ | ✓ |
| Tooling | biome + TS strict + vitest + tsup | 同一 |

## Success Metrics

- 30日: npm 公開、Hono 公式 third-party middleware への PR 提出
- 90日: GitHub 100+ stars、週間 500+ DL
- 180日: 5+ プロバイダー対応、コミュニティ PR によるプロバイダー追加
