# hono-webhook-verify

## 0.2.0

### Minor Changes

- [#73](https://github.com/paveg/hono-webhook-verify/pull/73) [`7175859`](https://github.com/paveg/hono-webhook-verify/commit/71758597f15fc5196a361d0d16f537a46071fa3d) Thanks [@paveg](https://github.com/paveg)! - Export crypto utilities and error constructors, fix Discord provider race condition

  ### New Features

  - Export crypto utilities (`hmac`, `toHex`, `fromHex`, `toBase64`, `fromBase64`, `timingSafeEqual`) for custom provider implementations
  - Export error constructors (`missingSignature`, `invalidSignature`, `timestampExpired`, `bodyReadFailed`) for consistent custom error handling

  ### Bug Fixes

  - Fix Discord provider `cachedKey` race condition under concurrent requests (cache Promise instead of resolved value)
  - Validate Discord Ed25519 public key length (32 bytes) at construction time

  ### Performance

  - Optimize `toHex` with pre-computed 256-entry lookup table

## 0.1.1

### Patch Changes

- Refactor Twilio provider to eliminate unreachable branch, achieve 100% test coverage

## 0.1.0

### Minor Changes

- Initial release with webhook signature verification middleware for Hono. Supports Stripe, GitHub, Slack, Shopify, Twilio, LINE, Discord, Standard Webhooks providers and auto-detection.
