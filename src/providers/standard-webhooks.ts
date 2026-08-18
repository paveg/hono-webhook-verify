import { DEFAULT_TOLERANCE_S } from "../constants.js";
import { fromBase64, hmac, timingSafeEqual, toBase64 } from "../crypto.js";
import { validateTimestamp } from "../timestamp.js";
import type { WebhookProvider } from "./types.js";

export interface StandardWebhooksOptions {
	secret: string;
	/** Timestamp tolerance in seconds (default: 300 = 5 minutes) */
	tolerance?: number;
}

/**
 * Signing credentials for `signStandardWebhook()`. Exactly one of `secret` or
 * `secrets` is required.
 */
type SignStandardWebhookCredentials =
	| {
			/** Signing secret. Accepts the whsec_ prefix (stripped), same as the verifier. */
			secret: string;
			secrets?: never;
	  }
	| {
			secret?: never;
			/**
			 * Multiple signing secrets for key rotation (max 10). One `v1,` signature is
			 * emitted per secret, space-separated — the same format the verifier already
			 * accepts.
			 */
			secrets: string[];
	  };

export type SignStandardWebhookOptions = SignStandardWebhookCredentials & {
	/** Message id, sent back as the `webhook-id` header. */
	id: string;
	/** Signing timestamp in seconds (default: the current time). */
	timestamp?: number;
	/** Raw request body to sign. */
	body: string;
};

export type StandardWebhookHeaders = {
	"webhook-id": string;
	"webhook-timestamp": string;
	"webhook-signature": string;
};

const WHSEC_PREFIX = "whsec_";
const MAX_SIGNATURES = 10;
const PRINTABLE_ASCII_NO_DOT = /^[\x21-\x7E]+$/;

function decodeSecret(secret: string): ArrayBuffer {
	const base64Key = secret.startsWith(WHSEC_PREFIX) ? secret.slice(WHSEC_PREFIX.length) : secret;
	if (!base64Key) {
		throw new Error("standard-webhooks: secret must not be empty");
	}
	const keyBytes = fromBase64(base64Key);
	if (!keyBytes) {
		throw new Error("standard-webhooks: secret must be valid base64 (with optional whsec_ prefix)");
	}
	return keyBytes;
}

/**
 * Sign a payload in the Standard Webhooks format, mirroring `standardWebhooks()`'s
 * verification logic. Produces the three headers a sender needs to attach to an
 * outbound webhook request.
 */
export async function signStandardWebhook(
	options: SignStandardWebhookOptions,
): Promise<StandardWebhookHeaders> {
	const secrets = options.secrets ?? (options.secret !== undefined ? [options.secret] : []);
	if (secrets.length === 0) {
		throw new Error(
			"standard-webhooks: signStandardWebhook requires `secret` or a non-empty `secrets`",
		);
	}
	if (secrets.length > MAX_SIGNATURES) {
		throw new Error(
			`standard-webhooks: signStandardWebhook supports at most ${MAX_SIGNATURES} secrets`,
		);
	}
	const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
	if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
		throw new Error("standard-webhooks: timestamp must be a positive integer number of seconds");
	}
	// The Standard Webhooks spec forbids '.' in ids because the signed content is
	// `id.timestamp.body`; Headers also rejects whitespace and non-ASCII characters.
	if (!PRINTABLE_ASCII_NO_DOT.test(options.id) || options.id.includes(".")) {
		throw new Error(
			"standard-webhooks: id must be non-empty printable ASCII without whitespace or '.'",
		);
	}
	const signedContent = `${options.id}.${timestamp}.${options.body}`;

	const signatures = await Promise.all(
		secrets.map(async (secret) => {
			const keyBytes = decodeSecret(secret);
			const sig = await hmac("SHA-256", keyBytes, signedContent);
			return `v1,${toBase64(sig)}`;
		}),
	);

	return {
		"webhook-id": options.id,
		"webhook-timestamp": String(timestamp),
		"webhook-signature": signatures.join(" "),
	};
}

export function standardWebhooks(options: StandardWebhooksOptions): WebhookProvider {
	const { tolerance = DEFAULT_TOLERANCE_S } = options;
	const keyBytes = decodeSecret(options.secret);

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
