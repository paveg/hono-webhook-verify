import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface LineOptions {
	channelSecret: string;
}

export function line(options: LineOptions): WebhookProvider {
	const { channelSecret } = options;

	if (!channelSecret) {
		throw new Error("line: channelSecret must not be empty");
	}

	return {
		name: "line",
		async verify({ rawBody, headers }) {
			const header = headers.get("X-Line-Signature");
			if (!header) {
				return { valid: false, reason: "missing-signature" };
			}

			const expected = await hmac("SHA-256", channelSecret, rawBody);
			const received = fromBase64(header);
			if (received === null || !timingSafeEqual(expected, received)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
