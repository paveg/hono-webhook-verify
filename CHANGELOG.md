# hono-webhook-verify

## 0.3.8

### Patch Changes

- [#115](https://github.com/paveg/hono-webhook-verify/pull/115) [`40138b9`](https://github.com/paveg/hono-webhook-verify/commit/40138b99a2a752b06ef04db6b21ee1bcef68de66) Thanks [@paveg](https://github.com/paveg)! - Refresh `postcss` (transitive dev dependency via `tsup`) from 8.5.6 to 8.5.13 to resolve Dependabot alert GHSA-qx2v-qp2m-jg93 / CVE-2026-41305 (XSS via unescaped `</style>` in CSS stringify output). No runtime or API changes — `postcss` is only used at build time and is not part of the published package.

## 0.3.7

### Patch Changes

- [#112](https://github.com/paveg/hono-webhook-verify/pull/112) [`8f61255`](https://github.com/paveg/hono-webhook-verify/commit/8f61255c7b7e5213f407a71d4d7cb93f1182913c) Thanks [@paveg](https://github.com/paveg)! - Documentation and metadata refresh:

  - Document the `WebhookVerifyError` constructor helpers (`missingSignature`, `invalidSignature`, `timestampExpired`, `bodyReadFailed`) in the README's Error Handling section. These are public exports for users wrapping the middleware or building higher-level handlers.
  - Add a `funding` field to `package.json` so npm and GitHub display the project's sponsor link.

  No runtime or API changes — all exports and behavior are unchanged.

## 0.3.6

### Patch Changes

- [#107](https://github.com/paveg/hono-webhook-verify/pull/107) [`060c0f7`](https://github.com/paveg/hono-webhook-verify/commit/060c0f7feb2f7e89e257351addf101919e9005b3) Thanks [@paveg](https://github.com/paveg)! - Refresh dev dependency lockfile to resolve Dependabot security alerts in `vite`, `picomatch`, and `minimatch`. No runtime or API changes — all affected packages are transitive dev dependencies.

## 0.3.5

### Patch Changes

- [#102](https://github.com/paveg/hono-webhook-verify/pull/102) [`562479f`](https://github.com/paveg/hono-webhook-verify/commit/562479fc0f8f42da36825e2b314efa33b6b3b2ae) Thanks [@paveg](https://github.com/paveg)! - Add `typesVersions` field to support subpath imports with `moduleResolution: "node"`

## 0.3.4

### Patch Changes

- [#97](https://github.com/paveg/hono-webhook-verify/pull/97) [`92555f5`](https://github.com/paveg/hono-webhook-verify/commit/92555f5145068bd2ff28e83dbf97979f96654848) Thanks [@paveg](https://github.com/paveg)! - Refactor: extract shared timestamp validation, replace magic numbers with named constants, add boundary value tests

## 0.3.3

### Patch Changes

- [#95](https://github.com/paveg/hono-webhook-verify/pull/95) [`18f0fa1`](https://github.com/paveg/hono-webhook-verify/commit/18f0fa105631826aabbb79fdc2fc1ec6880a77fb) Thanks [@paveg](https://github.com/paveg)! - ### Bug Fixes

  - Add `charset=utf-8` to fallback error response Content-Type for RFC 9457 consistency
  - Update `hono-problem-details` devDependency to 0.1.4 (status validation, safe serialization fixes)

## 0.3.2

### Patch Changes

- [#92](https://github.com/paveg/hono-webhook-verify/pull/92) [`8ae2939`](https://github.com/paveg/hono-webhook-verify/commit/8ae2939425a0309cf17abf1534a8bae09e8fbc2d) Thanks [@paveg](https://github.com/paveg)! - Add type-safe error mapping with VerifyFailureReason, await errorResponse, Slack empty hex edge case test

## 0.3.1

### Patch Changes

- [#87](https://github.com/paveg/hono-webhook-verify/pull/87) [`397f7a1`](https://github.com/paveg/hono-webhook-verify/commit/397f7a1192380e4fae197be8280709f75ebca2ba) Thanks [@paveg](https://github.com/paveg)! - Security hardening: fix fromHex non-ASCII bounds check, require Slack v0= prefix, limit Standard Webhooks signature count, add Discord timestamp tolerance

## 0.3.0

### Minor Changes

- [#76](https://github.com/paveg/hono-webhook-verify/pull/76) [`fb411df`](https://github.com/paveg/hono-webhook-verify/commit/fb411dfde27274ecb7908b170c2c7b55169b2457) Thanks [@paveg](https://github.com/paveg)! - Add hono-problem-details as optional peerDependency with runtime fallback

  - Declare `hono-problem-details` as optional peerDependency
  - When installed: error responses use `problemDetails().getResponse()` from hono-problem-details
  - When not installed: falls back to self-contained `new Response` implementation
  - Fix Content-Type: default error responses now return `application/problem+json` (was `application/json`)
  - Detection is lazy (first error path only) — no overhead on happy path
  - `onError` callback signature unchanged (backward-compatible)

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
