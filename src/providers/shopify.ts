import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface ShopifyOptions {
	secret: string;
}

export function shopify(options: ShopifyOptions): WebhookProvider {
	const { secret } = options;

	return {
		name: "shopify",
		async verify({ rawBody, headers }) {
			const header = headers.get("X-Shopify-Hmac-Sha256");
			if (!header) {
				return { valid: false, reason: "missing-signature" };
			}

			const expected = await hmac("SHA-256", secret, rawBody);

			// Decode the attacker-supplied base64 value to raw bytes so the
			// comparison happens in the byte domain using the native runtime path.
			const received = fromBase64(header);
			if (received === null || !timingSafeEqual(expected, received)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
