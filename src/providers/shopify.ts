import { hmac, timingSafeEqual, toBase64 } from "../crypto.js";
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

			const expected = toBase64(await hmac("SHA-256", secret, rawBody));

			if (!timingSafeEqual(expected, header)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
