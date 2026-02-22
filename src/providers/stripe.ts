import { hmac, timingSafeEqual, toHex } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface StripeOptions {
	secret: string;
	/** Timestamp tolerance in seconds (default: 300 = 5 minutes) */
	tolerance?: number;
}

export function stripe(options: StripeOptions): WebhookProvider {
	const { secret, tolerance = 300 } = options;

	return {
		name: "stripe",
		async verify({ rawBody, headers }) {
			const header = headers.get("Stripe-Signature");
			if (!header) {
				return { valid: false, reason: "missing-signature" };
			}

			const pairs = header.split(",").reduce(
				(acc, pair) => {
					const [key, value] = pair.split("=");
					acc[key.trim()] = value;
					return acc;
				},
				{} as Record<string, string>,
			);

			const timestamp = pairs.t;
			const signature = pairs.v1;

			if (!timestamp || !signature) {
				return { valid: false, reason: "missing-signature" };
			}

			const ts = Number(timestamp);
			const now = Math.floor(Date.now() / 1000);
			if (Math.abs(now - ts) > tolerance) {
				return { valid: false, reason: "timestamp-expired" };
			}

			const payload = `${timestamp}.${rawBody}`;
			const expected = toHex(await hmac("SHA-256", secret, payload));

			if (!timingSafeEqual(expected, signature)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
