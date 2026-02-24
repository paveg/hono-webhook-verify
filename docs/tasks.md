# Implementation Tasks

## Tooling (same as hono-idempotency)

- [x] biome (lint + format)
- [x] TypeScript (strict mode)
- [x] vitest (test runner)
- [x] tsup (build)
- [x] changesets (versioning & release)

## Test Guardrails

Unlike hono-idempotency, there is no reference implementation library to test against.
Each provider's official documentation serves as the test guardrail.

### Common Provider Tests (P1-P7)

**All provider implementations must pass the same test patterns** (same philosophy as hono-idempotency's S1-S6).

| # | Test Case | Expected | Priority |
|---|-----------|----------|----------|
| P1 | Correct secret + correct body → verification passes | `{ valid: true }` | **Required** |
| P2 | Correct secret + tampered body → verification fails | `{ valid: false }` | **Required** |
| P3 | Wrong secret + correct body → verification fails | `{ valid: false }` | **Required** |
| P4 | Missing signature header → verification fails | `{ valid: false, reason: 'missing-signature' }` | **Required** |
| P5 | Empty body → verification passes (with correct signature) | `{ valid: true }` | Medium |
| P6 | Multibyte body → verification passes | UTF-8 encoding consistency | Medium |
| P7 | Large body (1MB) → verification passes | No performance issues | Low |

### Timestamp Provider Additional Tests (T1-T3)

For Stripe, Slack, Standard Webhooks.

| # | Test Case | Expected | Priority |
|---|-----------|----------|----------|
| T1 | Current timestamp → verification passes | Within tolerance | **Required** |
| T2 | Timestamp 6 min ago (tolerance=300s) → verification fails | `{ valid: false, reason: 'timestamp-expired' }` | **Required** |
| T3 | Custom tolerance setting → applied correctly | tolerance=60, 2 min ago → fails | **Required** |

### Twilio-Specific Tests (TW1-TW2)

| # | Test Case | Expected | Priority |
|---|-----------|----------|----------|
| TW1 | URL + sorted POST parameters signature verification | Passes with correct signature | **Required** |
| TW2 | Parameters in different order → passes after sort | Sort logic correctness | **Required** |

### Middleware Integration Tests (M1-M8)

HTTP-level tests using `app.request()`.

| # | Test Case | Expected | Status | Priority |
|---|-----------|----------|--------|----------|
| M1 | Valid signature → handler executes | 200 + handler return value | 200 | **Required** |
| M2 | Invalid signature → 401 | RFC 9457 error | 401 | **Required** |
| M3 | No signature header → 401 | `missing-signature` | 401 | **Required** |
| M4 | Timestamp expired → 401 | `timestamp-expired` | 401 | **Required** |
| M5 | `c.get('webhookRawBody')` retrieves raw body | Matches original body | — | **Required** |
| M6 | `c.get('webhookPayload')` retrieves JSON | Parsed object | — | **Required** |
| M7 | `c.get('webhookProvider')` retrieves provider name | `'stripe'` etc. | — | **Required** |
| M8 | `onError` custom error handling | Custom response | — | Medium |

### Crypto Utility Tests (CR1-CR3)

| # | Test Case | Expected | Priority |
|---|-----------|----------|----------|
| CR1 | HMAC-SHA256 hex output matches known value | RFC test vector verification | **Required** |
| CR2 | HMAC-SHA1 base64 output matches known value | For Twilio | **Required** |
| CR3 | timingSafeEqual: match → true, mismatch → false, length diff → false | Constant-time comparison | **Required** |

### Test Strategy: Signature Generation Helpers

Tests use helpers that generate "real" signatures for each provider.
This allows tests to be self-contained without external service dependencies.

```ts
// tests/helpers/signatures.ts
export async function generateStripeSignature(body: string, secret: string, timestamp?: number): Promise<string>
export async function generateGitHubSignature(body: string, secret: string): Promise<string>
export async function generateSlackSignature(body: string, secret: string, timestamp?: number): Promise<string>
export async function generateShopifySignature(body: string, secret: string): Promise<string>
export async function generateTwilioSignature(url: string, params: Record<string, string>, authToken: string): Promise<string>
```

Lesson from hono-idempotency:
Testing against minimal interfaces is lighter and more maintainable than mocking external services (e.g., miniflare).
Here, "signature generation helpers = trusted source for testing" serves that role.

## Phase 1: Core + 2 Providers (Week 1)

TDD approach: test → implement → refactor.

### 1.1 Project Setup
- [x] Repository creation, package.json, tsconfig.json, biome.json
- [x] vitest + tsup configuration
- [x] CI (GitHub Actions): lint, test, build

### 1.2 Type Definitions / Provider Interface
- [x] `src/types.ts` — WebhookVerifyOptions, VerifyResult
- [x] `src/providers/types.ts` — WebhookProvider, ProviderFactory, VerifyContext

### 1.3 Crypto Utilities
- [x] Write `tests/crypto.test.ts` first (CR1-CR3)
- [x] `src/crypto.ts` — hmac(), timingSafeEqual(), toHex(), toBase64()
- [x] Tests: Verify against RFC test vectors

### 1.4 Stripe Provider
- [x] `tests/helpers/signatures.ts` — generateStripeSignature()
- [x] Write `tests/providers/stripe.test.ts` first (P1-P6 + T1-T3)
- [x] `src/providers/stripe.ts`
- [x] Stripe-Signature header parsing (`t=...,v1=...`)
- [x] Timestamp-based signature verification

### 1.5 GitHub Provider
- [x] Write `tests/providers/github.test.ts` first (P1-P6)
- [x] `src/providers/github.ts`
- [x] `sha256=` prefix parsing

### 1.6 Middleware Core
- [x] Write `tests/middleware.test.ts` first (M1-M8)
- [x] `src/middleware.ts` — createMiddleware()-based
- [x] Tests: Cover M1-M8 with Stripe + GitHub

### 1.7 Error Responses
- [x] `src/errors.ts` — RFC 9457 Problem Details

## Phase 2: Remaining Providers (Week 2)

Provider additions are quality-assured by the shared P1-P6 test suite.

### 2.1 Slack Provider
- [x] `tests/providers/slack.test.ts` (P1-P6 + T1-T3)
- [x] `src/providers/slack.ts`
- [x] `v0=` prefix + timestamp concatenation

### 2.2 Shopify Provider
- [x] `tests/providers/shopify.test.ts` (P1-P6)
- [x] `src/providers/shopify.ts`
- [x] base64 encoding

### 2.3 Twilio Provider
- [x] `tests/providers/twilio.test.ts` (P1-P4 + TW1-TW2)
- [x] `src/providers/twilio.ts`
- [x] HMAC-SHA1 + URL + sorted params

### 2.4 defineProvider()
- [x] Custom provider definition helper function
- [x] Tests: Custom provider passes M1-M3

## Phase 3: Publish & Promote (Week 3)

### 3.1 Packaging
- [x] README.md (English) — "Verify webhooks from any provider with one line"
- [x] LICENSE (MIT)
- [x] Subpath export configuration
- [x] npm publish (release workflow) + JSR publish (manual)

### 3.2 Hono Official PR (manual)
- [ ] Submit third-party listing PR to honojs/middleware repository
- [ ] Announce in Hono Discord

### 3.3 Promotion (manual)
- [ ] Announce on X/Twitter
- [ ] Post to Reddit r/node, r/cloudflare
- [ ] Write explanation article on dev.to / Zenn
- [ ] Add "See Also" cross-link in hono-idempotency README

## Stretch Goals

- [x] LINE Provider
- [x] Discord Provider
- [ ] PayPal Provider (requires certificate fetching from PayPal servers — skipped)
- [x] Standard Webhooks (svix-compatible) Provider
- [x] Provider auto-detection (infer provider from headers)
- [x] CONTRIBUTING.md — Provider addition guide (to encourage contributions)
