import { hmac, timingSafeEqual, toHex } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface GitHubOptions {
	secret: string;
}

export function github(options: GitHubOptions): WebhookProvider {
	const { secret } = options;

	return {
		name: "github",
		async verify({ rawBody, headers }) {
			const header = headers.get("X-Hub-Signature-256");
			if (!header) {
				return { valid: false, reason: "missing-signature" };
			}

			const signature = header.startsWith("sha256=") ? header.slice(7) : header;
			const expected = toHex(await hmac("SHA-256", secret, rawBody));

			if (!timingSafeEqual(expected, signature)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
