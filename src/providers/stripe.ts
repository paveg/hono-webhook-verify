import { fromHex, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface StripeOptions {
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

			const pairs: Record<string, string[]> = {};
			for (const part of header.split(",")) {
				const idx = part.indexOf("=");
				if (idx === -1) continue;
				const key = part.slice(0, idx).trim();
				const value = part.slice(idx + 1).trim();
				if (!pairs[key]) pairs[key] = [];
				pairs[key].push(value);
			}

			const timestamp = pairs.t?.[0];
			const signatures = pairs.v1 ?? [];

			if (!timestamp || signatures.length === 0) {
				return { valid: false, reason: "missing-signature" };
			}

			const ts = Number(timestamp);
			if (!Number.isFinite(ts) || ts <= 0) {
				return { valid: false, reason: "missing-signature" };
			}
			const now = Math.floor(Date.now() / 1000);
			if (Math.abs(now - ts) > tolerance) {
				return { valid: false, reason: "timestamp-expired" };
			}

			const payload = `${timestamp}.${rawBody}`;
			const expected = await hmac("SHA-256", secret, payload);

			// Decode each attacker-supplied hex signature to raw bytes and compare
			// in the byte domain so the runtime's native constant-time path is used.
			const matched = signatures.some((sig) => {
				const received = fromHex(sig);
				return received !== null && timingSafeEqual(expected, received);
			});

			if (!matched) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
