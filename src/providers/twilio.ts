import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface TwilioOptions {
	authToken: string;
}

export function twilio(options: TwilioOptions): WebhookProvider {
	const { authToken } = options;

	if (!authToken) {
		throw new Error("twilio: authToken must not be empty");
	}

	return {
		name: "twilio",
		async verify({ rawBody, headers, url }) {
			const signature = headers.get("X-Twilio-Signature");
			if (!signature) {
				return { valid: false, reason: "missing-signature" };
			}

			if (!url) {
				return { valid: false, reason: "invalid-signature" };
			}

			// Twilio signs: URL + sorted POST parameters
			const params = new URLSearchParams(rawBody);
			const entries: [string, string][] = [];
			params.forEach((value, key) => {
				entries.push([key, value]);
			});
			entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
			let dataToSign = url;
			for (const [key, value] of entries) {
				dataToSign += key + value;
			}

			const expected = await hmac("SHA-1", authToken, dataToSign);

			// Decode the attacker-supplied base64 value to raw bytes so the
			// comparison happens in the byte domain using the native runtime path.
			const received = fromBase64(signature);
			if (received === null || !timingSafeEqual(expected, received)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
