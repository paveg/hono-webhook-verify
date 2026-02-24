import { fromHex, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface SlackOptions {
	signingSecret: string;
	/** Timestamp tolerance in seconds (default: 300 = 5 minutes) */
	tolerance?: number;
}

export function slack(options: SlackOptions): WebhookProvider {
	const { signingSecret, tolerance = 300 } = options;

	return {
		name: "slack",
		async verify({ rawBody, headers }) {
			const signature = headers.get("X-Slack-Signature");
			const timestamp = headers.get("X-Slack-Request-Timestamp");

			if (!signature || !timestamp) {
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

			const sigBasestring = `v0:${timestamp}:${rawBody}`;
			const expected = await hmac("SHA-256", signingSecret, sigBasestring);

			// Slack sends "v0=<hex>". Strip the prefix, decode to raw bytes, and
			// compare in the byte domain for native constant-time safety.
			const receivedHex = signature.startsWith("v0=") ? signature.slice(3) : signature;
			const received = fromHex(receivedHex);
			if (received === null || !timingSafeEqual(expected, received)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
