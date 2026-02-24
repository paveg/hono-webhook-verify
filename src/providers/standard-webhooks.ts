import { fromBase64, hmac, timingSafeEqual } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface StandardWebhooksOptions {
	secret: string;
	/** Timestamp tolerance in seconds (default: 300 = 5 minutes) */
	tolerance?: number;
}

export function standardWebhooks(options: StandardWebhooksOptions): WebhookProvider {
	const { tolerance = 300 } = options;
	// Strip whsec_ prefix if present
	const base64Key = options.secret.startsWith("whsec_") ? options.secret.slice(6) : options.secret;
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

			const ts = Number(timestamp);
			if (!Number.isFinite(ts) || ts <= 0) {
				return { valid: false, reason: "missing-signature" };
			}
			const now = Math.floor(Date.now() / 1000);
			if (Math.abs(now - ts) > tolerance) {
				return { valid: false, reason: "timestamp-expired" };
			}

			const signedContent = `${msgId}.${timestamp}.${rawBody}`;
			const expected = await hmac("SHA-256", keyBytes, signedContent);

			// Support space-separated signatures for key rotation
			const signatures = signatureHeader.split(" ");
			const matched = signatures.some((sig) => {
				if (!sig.startsWith("v1,")) return false;
				const received = fromBase64(sig.slice(3));
				return received !== null && timingSafeEqual(expected, received);
			});

			if (!matched) {
				return { valid: false, reason: "invalid-signature" };
			}

			return { valid: true };
		},
	};
}
