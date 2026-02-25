import { fromHex } from "../crypto.js";
import type { WebhookProvider } from "./types.js";

export interface DiscordOptions {
	publicKey: string;
	/** Timestamp tolerance in seconds. When set, rejects signatures with timestamps outside this window. */
	tolerance?: number;
}

const encoder = new TextEncoder();

export function discord(options: DiscordOptions): WebhookProvider {
	const { publicKey, tolerance } = options;

	const rawKey = fromHex(publicKey);
	if (!rawKey) {
		throw new Error("discord: publicKey must be a valid hex string");
	}
	if (rawKey.byteLength !== 32) {
		throw new Error("discord: publicKey must be 32 bytes (64 hex characters)");
	}
	// Store in a typed variable so TypeScript narrows across the closure.
	const keyBytes: ArrayBuffer = rawKey;

	let keyPromise: Promise<CryptoKey> | null = null;

	function getKey(): Promise<CryptoKey> {
		if (!keyPromise) {
			keyPromise = crypto.subtle.importKey("raw", keyBytes, "Ed25519", false, ["verify"]);
		}
		return keyPromise;
	}

	return {
		name: "discord",
		async verify({ rawBody, headers }) {
			const signature = headers.get("X-Signature-Ed25519");
			const timestamp = headers.get("X-Signature-Timestamp");

			if (!signature || !timestamp) {
				return { valid: false, reason: "missing-signature" };
			}

			if (tolerance != null) {
				const ts = Number(timestamp);
				if (!Number.isFinite(ts) || ts <= 0) {
					return { valid: false, reason: "missing-signature" };
				}
				const now = Math.floor(Date.now() / 1000);
				if (Math.abs(now - ts) > tolerance) {
					return { valid: false, reason: "timestamp-expired" };
				}
			}

			const sigBytes = fromHex(signature);
			if (!sigBytes) {
				return { valid: false, reason: "invalid-signature" };
			}

			const message = encoder.encode(timestamp + rawBody);
			const key = await getKey();

			try {
				const valid = await crypto.subtle.verify("Ed25519", key, sigBytes, message);
				if (!valid) {
					return { valid: false, reason: "invalid-signature" };
				}
				return { valid: true };
			} catch {
				return { valid: false, reason: "invalid-signature" };
			}
		},
	};
}
