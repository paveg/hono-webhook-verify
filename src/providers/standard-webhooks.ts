import { DEFAULT_TOLERANCE_S } from "../constants.js";
import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
import { validateTimestamp } from "../timestamp.js";
import type { WebhookProvider } from "./types.js";

export interface StandardWebhooksOptions {
	secret: string;
	/** Timestamp tolerance in seconds (default: 300 = 5 minutes) */
	tolerance?: number;
}

const WHSEC_PREFIX = "whsec_";
const MAX_SIGNATURES = 10;

export function standardWebhooks(options: StandardWebhooksOptions): WebhookProvider {
	const { tolerance = DEFAULT_TOLERANCE_S } = options;
	const base64Key = options.secret.startsWith(WHSEC_PREFIX)
		? options.secret.slice(WHSEC_PREFIX.length)
		: options.secret;
	const keyBytes = fromBase64(base64Key);
	if (!keyBytes) {
		throw new Error("standard-webhooks: secret must be valid base64 (with optional whsec_ prefix)");
	}

	return {
		name: "standard-webhooks",
		async verify({ rawBody, headers }) {
			const msgId = headers.get("webhook-id");
			const timestamp = headers.get("webhook-timestamp");
			const signatureHeader = headers.get("webhook-signature");

			if (!msgId || !timestamp || !signatureHeader) {
				return { valid: false, reason: "missing-signature" };
			}

			const tsError = validateTimestamp(timestamp, tolerance);
			if (tsError) return tsError;

			const signedContent = `${msgId}.${timestamp}.${rawBody}`;
			const expected = await hmac("SHA-256", keyBytes, signedContent);

			// Support space-separated signatures for key rotation (limit to prevent DoS)
			const signatures = signatureHeader.split(" ").slice(0, MAX_SIGNATURES);
			const matched = signatures.some((sig) => {
				if (!sig.startsWith("v1,")) return false;
				const received = fromBase64(sig.slice("v1,".length));
				return received !== null && timingSafeEqual(expected, received);
			});

			if (!matched) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
