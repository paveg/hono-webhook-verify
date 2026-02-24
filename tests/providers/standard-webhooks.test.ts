import { describe, expect, it } from "vitest";
import { standardWebhooks } from "../../src/providers/standard-webhooks.js";
import { DEFAULT_TOLERANCE_S, EXPIRED_OFFSET_S } from "../helpers/constants.js";
import { generateStandardWebhooksSignature } from "../helpers/signatures.js";

// Generate a 32-byte key encoded as base64 for testing
const SECRET_BASE64 = btoa(String.fromCharCode(...new Uint8Array(32).fill(42)));
const SECRET = `whsec_${SECRET_BASE64}`;
const WRONG_SECRET_BASE64 = btoa(String.fromCharCode(...new Uint8Array(32).fill(99)));
const WRONG_SECRET = `whsec_${WRONG_SECRET_BASE64}`;
const MSG_ID = "msg_test123";
const BODY = '{"type":"event.created"}';

describe("standard-webhooks provider", () => {
	it("P1: verifies valid signature", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P2: rejects tampered body", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: '{"type":"tampered"}',
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("P3: rejects wrong secret", async () => {
		const provider = standardWebhooks({ secret: WRONG_SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("P4: rejects missing signature header", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": "1700000000",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects missing webhook-id", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects missing timestamp", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature } = await generateStandardWebhooksSignature(BODY, SECRET_BASE64, MSG_ID);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("P5: verifies empty body", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			"",
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P6: verifies multibyte body", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const body = '{"text":"こんにちは"}';
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			body,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("T2: rejects expired timestamp with default tolerance", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const pastTimestamp = Math.floor(Date.now() / 1000) - EXPIRED_OFFSET_S;
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			pastTimestamp,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(pastTimestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("T3: custom tolerance", async () => {
		const provider = standardWebhooks({ secret: SECRET, tolerance: 60 });
		const pastTimestamp = Math.floor(Date.now() / 1000) - 120;
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			pastTimestamp,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(pastTimestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("supports multiple signatures (key rotation)", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature: sig1, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		// Prepend an invalid signature — the valid one should still match
		const combinedSig = `v1,invalid_base64_sig ${sig1}`;
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": combinedSig,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("strips whsec_ prefix from secret", async () => {
		// Also works if someone passes just the base64 without prefix
		const provider = standardWebhooks({ secret: SECRET_BASE64 });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("throws on invalid base64 secret", () => {
		expect(() => standardWebhooks({ secret: "!!invalid!!" })).toThrow(
			"secret must be valid base64",
		);
	});

	it("accepts timestamp at exactly the tolerance boundary", async () => {
		const provider = standardWebhooks({ secret: SECRET, tolerance: 60 });
		const exactlyAtBoundary = Math.floor(Date.now() / 1000) - 60;
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			exactlyAtBoundary,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(exactlyAtBoundary),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects with tolerance: 0 when timestamp is 1 second off", async () => {
		const provider = standardWebhooks({ secret: SECRET, tolerance: 0 });
		const oneSecAgo = Math.floor(Date.now() / 1000) - 1;
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			oneSecAgo,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(oneSecAgo),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("rejects zero timestamp", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		// Generate signature for timestamp 0 to isolate the ts <= 0 guard
		const { signature } = await generateStandardWebhooksSignature(BODY, SECRET_BASE64, MSG_ID, 0);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": "0",
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects negative timestamp", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		// Generate signature for negative timestamp to isolate the ts <= 0 guard
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			-100,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": "-100",
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects non-numeric timestamp", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature } = await generateStandardWebhooksSignature(BODY, SECRET_BASE64, MSG_ID);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": "not-a-number",
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects empty base64 after v1, prefix", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { timestamp } = await generateStandardWebhooksSignature(BODY, SECRET_BASE64, MSG_ID);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": "v1,",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects signatures without v1 prefix", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { timestamp } = await generateStandardWebhooksSignature(BODY, SECRET_BASE64, MSG_ID);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": "v2,somebase64data",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});
});
