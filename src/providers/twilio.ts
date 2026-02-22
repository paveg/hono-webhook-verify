import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
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
