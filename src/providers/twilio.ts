import { hmac, timingSafeEqual, toBase64 } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

interface TwilioOptions {
	authToken: string;
}

export function twilio(options: TwilioOptions): WebhookProvider {
	const { authToken } = options;

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
			const sortedKeys: string[] = [];
			params.forEach((_value, key) => {
				sortedKeys.push(key);
			});
			sortedKeys.sort();
			let dataToSign = url;
			for (const key of sortedKeys) {
				dataToSign += key + (params.get(key) ?? "");
			}

			const expected = toBase64(await hmac("SHA-1", authToken, dataToSign));

			if (!timingSafeEqual(expected, signature)) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
