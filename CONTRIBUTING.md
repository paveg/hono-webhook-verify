# Contributing

Thank you for your interest in contributing to hono-webhook-verify!

## Development Setup

```bash
git clone https://github.com/paveg/hono-webhook-verify.git
cd hono-webhook-verify
pnpm install
```

### Commands

| Command | Description |
|---------|-------------|
| `pnpm test` | Run tests |
| `pnpm test:watch` | Run tests in watch mode |
| `pnpm lint` | Lint and format check |
| `pnpm lint:fix` | Auto-fix lint and format issues |
| `pnpm typecheck` | TypeScript type checking |
| `pnpm build` | Build with tsup |

## Adding a New Provider

This is the most common contribution. Follow these steps:

### 1. Create the test helper

Add a signature generation function to `tests/helpers/signatures.ts`:

```ts
export async function generateMyServiceSignature(
  body: string,
  secret: string,
): Promise<string> {
  const mac = await hmac("SHA-256", secret, body);
  return toHex(mac); // or toBase64(mac) depending on the provider
}
```

### 2. Write tests first (TDD)

Create `tests/providers/my-service.test.ts` with at minimum these test cases:

| # | Test Case | Required |
|---|-----------|----------|
| P1 | Valid secret + valid body → `{ valid: true }` | Yes |
| P2 | Valid secret + tampered body → `{ valid: false }` | Yes |
| P3 | Wrong secret + valid body → `{ valid: false }` | Yes |
| P4 | Missing signature header → `{ valid: false, reason: "missing-signature" }` | Yes |
| P5 | Empty body with valid signature → `{ valid: true }` | Yes |
| P6 | Multibyte body (UTF-8) → `{ valid: true }` | Yes |

If the provider uses timestamps, also add:

| # | Test Case | Required |
|---|-----------|----------|
| T1 | Current timestamp → passes | Yes |
| T2 | Expired timestamp (> tolerance) → `{ valid: false, reason: "timestamp-expired" }` | Yes |
| T3 | Custom tolerance setting | Yes |

### 3. Implement the provider

Create `src/providers/my-service.ts`:

```ts
import { fromHex, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface MyServiceOptions {
  secret: string;
}

export function myService(options: MyServiceOptions): WebhookProvider {
  const { secret } = options;

  return {
    name: "my-service",
    async verify({ rawBody, headers }) {
      const header = headers.get("X-My-Service-Signature");
      if (!header) {
        return { valid: false, reason: "missing-signature" };
      }

      const expected = await hmac("SHA-256", secret, rawBody);
      const received = fromHex(header);
      if (received === null || !timingSafeEqual(expected, received)) {
        return { valid: false, reason: "invalid-signature" };
      }

      return { valid: true };
    },
  };
}
```

Key rules:
- Use `fromHex()` or `fromBase64()` to decode attacker-supplied signatures to raw bytes
- Use `timingSafeEqual()` for all signature comparisons — never use `===`
- Return `{ valid: false, reason: "missing-signature" }` when the signature header is absent
- Return `{ valid: false, reason: "invalid-signature" }` when the signature is present but wrong

### 4. Add the subpath export

In `package.json`, add an entry under `"exports"`:

```json
"./providers/my-service": {
  "import": {
    "types": "./dist/providers/my-service.d.ts",
    "default": "./dist/providers/my-service.js"
  },
  "require": {
    "types": "./dist/providers/my-service.d.cts",
    "default": "./dist/providers/my-service.cjs"
  }
}
```

And add the entry point to `tsup.config.ts`.

### 5. Verify

```bash
pnpm typecheck && pnpm lint && pnpm test && pnpm build
```

All four must pass before submitting your PR.

## Code Style

- Formatting and linting are handled by [Biome](https://biomejs.dev/). Run `pnpm lint:fix` to auto-fix.
- No `eslint` or `prettier` — Biome handles both.

## Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Follow the TDD workflow: tests first, then implementation
4. Ensure all checks pass: `pnpm typecheck && pnpm lint && pnpm test && pnpm build`
5. Add a changeset: `pnpm changeset` — select the appropriate bump level
6. Open a PR with a clear description

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
