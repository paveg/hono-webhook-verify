import { hmac, timingSafeEqual, toHex } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface SlackOptions {
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
			const now = Math.floor(Date.now() / 1000);
			if (Math.abs(now - ts) > tolerance) {
				return { valid: false, reason: "timestamp-expired" };
			}

			const sigBasestring = `v0:${timestamp}:${rawBody}`;
			const expectedHex = toHex(await hmac("SHA-256", signingSecret, sigBasestring));
			const expected = `v0=${expectedHex}`;

			const sig = signature.startsWith("v0=") ? signature : `v0=${signature}`;

			if (!timingSafeEqual(expected, sig)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
