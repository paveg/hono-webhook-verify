---
"hono-webhook-verify": minor
---

Export crypto utilities and error constructors, fix Discord provider race condition

### New Features
- Export crypto utilities (`hmac`, `toHex`, `fromHex`, `toBase64`, `fromBase64`, `timingSafeEqual`) for custom provider implementations
- Export error constructors (`missingSignature`, `invalidSignature`, `timestampExpired`, `bodyReadFailed`) for consistent custom error handling

### Bug Fixes
- Fix Discord provider `cachedKey` race condition under concurrent requests (cache Promise instead of resolved value)
- Validate Discord Ed25519 public key length (32 bytes) at construction time

### Performance
- Optimize `toHex` with pre-computed 256-entry lookup table
