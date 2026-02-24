import { fromHex, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface GitHubOptions {
	secret: string;
}

export function github(options: GitHubOptions): WebhookProvider {
	const { secret } = options;

	// Reject degenerate secrets at construction time rather than silently
	// computing a valid HMAC that any attacker who knows the empty-secret
	// digest could forge.
	if (!secret) {
		throw new Error("github: secret must not be empty");
	}

	return {
		name: "github",
		async verify({ rawBody, headers }) {
			const header = headers.get("X-Hub-Signature-256");
			if (!header) {
				return { valid: false, reason: "missing-signature" };
			}

			// Distinguish a missing header from a structurally invalid one so
			// that callers can produce accurate error messages and HTTP statuses.
			if (!header.startsWith("sha256=")) {
				return { valid: false, reason: "invalid-signature" };
			}

			const received = fromHex(header.slice(7));
			if (!received) {
				return { valid: false, reason: "invalid-signature" };
			}

			const expected = await hmac("SHA-256", secret, rawBody);

			if (!timingSafeEqual(expected, received)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
