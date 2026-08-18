import { describe, expect, it } from "vitest";
import { signStandardWebhook, standardWebhooks } from "../../src/providers/standard-webhooks.js";
import { EXPIRED_OFFSET_S } from "../helpers/constants.js";
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

	it("throws on an empty secret", () => {
		expect(() => standardWebhooks({ secret: "" })).toThrow("secret must not be empty");
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

	it("rejects when valid signature is beyond the 10-signature limit", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		// 10 fake + 1 valid at position 11 — should be rejected (limit is 10)
		const sigs = Array.from({ length: 10 }, (_, i) => `v1,fake${i}`)
			.concat(signature)
			.join(" ");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": sigs,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("accepts valid signature at position 10 (within limit)", async () => {
		const provider = standardWebhooks({ secret: SECRET });
		const { signature, timestamp } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
		);
		// 9 fake + 1 valid = 10 total (within limit)
		const sigs = Array.from({ length: 9 }, (_, i) => `v1,fake${i}`)
			.concat(signature)
			.join(" ");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(timestamp),
				"webhook-signature": sigs,
			}),
		});
		expect(result).toEqual({ valid: true });
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

	it("rejects future timestamp beyond tolerance", async () => {
		const provider = standardWebhooks({ secret: SECRET, tolerance: 60 });
		const future = Math.floor(Date.now() / 1000) + 120;
		const { signature } = await generateStandardWebhooksSignature(
			BODY,
			SECRET_BASE64,
			MSG_ID,
			future,
		);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"webhook-id": MSG_ID,
				"webhook-timestamp": String(future),
				"webhook-signature": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});
});

describe("signStandardWebhook", () => {
	const FIXED_TIMESTAMP = Math.floor(Date.now() / 1000);

	it("S1: round-trips through standardWebhooks().verify()", async () => {
		const headers = await signStandardWebhook({
			secret: SECRET,
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body: BODY,
		});
		expect(headers).toEqual({
			"webhook-id": MSG_ID,
			"webhook-timestamp": String(FIXED_TIMESTAMP),
			"webhook-signature": expect.stringMatching(/^v1,/),
		});

		const provider = standardWebhooks({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(headers),
		});
		expect(result).toEqual({ valid: true });
	});

	it("S2: defaults timestamp to the current time in seconds", async () => {
		const before = Math.floor(Date.now() / 1000);
		const headers = await signStandardWebhook({ secret: SECRET, id: MSG_ID, body: BODY });
		const after = Math.floor(Date.now() / 1000);
		const timestamp = Number(headers["webhook-timestamp"]);
		expect(timestamp).toBeGreaterThanOrEqual(before);
		expect(timestamp).toBeLessThanOrEqual(after);
	});

	it("S3: strips the whsec_ prefix like the verifier", async () => {
		const headers = await signStandardWebhook({
			secret: SECRET_BASE64,
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body: BODY,
		});
		const provider = standardWebhooks({ secret: SECRET });
		const result = await provider.verify({ rawBody: BODY, headers: new Headers(headers) });
		expect(result).toEqual({ valid: true });
	});

	it("S4: round-trips an empty body", async () => {
		const headers = await signStandardWebhook({
			secret: SECRET,
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body: "",
		});
		const provider = standardWebhooks({ secret: SECRET });
		const result = await provider.verify({ rawBody: "", headers: new Headers(headers) });
		expect(result).toEqual({ valid: true });
	});

	it("S5: round-trips a multibyte body", async () => {
		const body = '{"text":"こんにちは"}';
		const headers = await signStandardWebhook({
			secret: SECRET,
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body,
		});
		const provider = standardWebhooks({ secret: SECRET });
		const result = await provider.verify({ rawBody: body, headers: new Headers(headers) });
		expect(result).toEqual({ valid: true });
	});

	it("S6: emits a space-separated signature per secret for key rotation", async () => {
		const headers = await signStandardWebhook({
			secrets: [SECRET, WRONG_SECRET],
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body: BODY,
		});
		const signatures = headers["webhook-signature"].split(" ");
		expect(signatures).toHaveLength(2);

		// Verifies against either secret independently, mirroring the receiver's rotation support.
		for (const secret of [SECRET, WRONG_SECRET]) {
			const provider = standardWebhooks({ secret });
			const result = await provider.verify({ rawBody: BODY, headers: new Headers(headers) });
			expect(result).toEqual({ valid: true });
		}
	});

	it("S7: throws when neither secret nor secrets is provided", async () => {
		await expect(
			// @ts-expect-error exercising the runtime guard for missing options
			signStandardWebhook({ id: MSG_ID, timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("signStandardWebhook requires `secret` or a non-empty `secrets`");
	});

	it("S8: throws on invalid base64 secret", async () => {
		await expect(
			signStandardWebhook({ secret: "!!invalid!!", id: MSG_ID, body: BODY }),
		).rejects.toThrow("secret must be valid base64");
	});

	it("S9: throws when secrets exceeds the verifier's 10-signature limit", async () => {
		const secrets = Array.from({ length: 11 }, () => SECRET);
		await expect(
			signStandardWebhook({ secrets, id: MSG_ID, timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("supports at most 10 secrets");
	});

	it("S10: accepts exactly 10 secrets (at the verifier's limit)", async () => {
		const secrets = Array.from({ length: 10 }, () => SECRET);
		const headers = await signStandardWebhook({
			secrets,
			id: MSG_ID,
			timestamp: FIXED_TIMESTAMP,
			body: BODY,
		});
		expect(headers["webhook-signature"].split(" ")).toHaveLength(10);
	});

	it("S11: throws on a fractional timestamp", async () => {
		await expect(
			signStandardWebhook({ secret: SECRET, id: MSG_ID, timestamp: 1755300000.5, body: BODY }),
		).rejects.toThrow("timestamp must be a positive integer number of seconds");
	});

	it("S12: throws on a non-finite timestamp", async () => {
		await expect(
			signStandardWebhook({
				secret: SECRET,
				id: MSG_ID,
				timestamp: Number.POSITIVE_INFINITY,
				body: BODY,
			}),
		).rejects.toThrow("timestamp must be a positive integer number of seconds");
	});

	it("S13: throws on an unsafe-integer timestamp", async () => {
		await expect(
			signStandardWebhook({
				secret: SECRET,
				id: MSG_ID,
				timestamp: Number.MAX_SAFE_INTEGER + 1,
				body: BODY,
			}),
		).rejects.toThrow("timestamp must be a positive integer number of seconds");
	});

	it("throws on a zero timestamp", async () => {
		await expect(
			signStandardWebhook({ secret: SECRET, id: MSG_ID, timestamp: 0, body: BODY }),
		).rejects.toThrow("timestamp must be a positive integer number of seconds");
	});

	it("throws on a negative timestamp", async () => {
		await expect(
			signStandardWebhook({ secret: SECRET, id: MSG_ID, timestamp: -5, body: BODY }),
		).rejects.toThrow("timestamp must be a positive integer number of seconds");
	});

	it("throws on an empty id", async () => {
		await expect(
			signStandardWebhook({ secret: SECRET, id: "", timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("id must be non-empty printable ASCII without whitespace or '.'");
	});

	it("throws on a whitespace-padded id", async () => {
		await expect(
			signStandardWebhook({
				secret: SECRET,
				id: "  msg_1  ",
				timestamp: FIXED_TIMESTAMP,
				body: BODY,
			}),
		).rejects.toThrow("id must be non-empty printable ASCII without whitespace or '.'");
	});

	it("throws on a non-ASCII id", async () => {
		await expect(
			signStandardWebhook({
				secret: SECRET,
				id: "msg_あ",
				timestamp: FIXED_TIMESTAMP,
				body: BODY,
			}),
		).rejects.toThrow("id must be non-empty printable ASCII without whitespace or '.'");
	});

	it("throws on an id containing a CRLF header injection attempt", async () => {
		await expect(
			signStandardWebhook({
				secret: SECRET,
				id: "a\r\nx: 1",
				timestamp: FIXED_TIMESTAMP,
				body: BODY,
			}),
		).rejects.toThrow("id must be non-empty printable ASCII without whitespace or '.'");
	});

	it("throws on an id containing a '.'", async () => {
		await expect(
			signStandardWebhook({ secret: SECRET, id: "a.b", timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("id must be non-empty printable ASCII without whitespace or '.'");
	});

	it("throws on an empty secret", async () => {
		await expect(
			signStandardWebhook({ secret: "", id: MSG_ID, timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("secret must not be empty");
	});

	it("throws when the secret is only the whsec_ prefix", async () => {
		await expect(
			signStandardWebhook({
				secret: "whsec_",
				id: MSG_ID,
				timestamp: FIXED_TIMESTAMP,
				body: BODY,
			}),
		).rejects.toThrow("secret must not be empty");
	});

	it("throws when secrets is an empty array", async () => {
		await expect(
			signStandardWebhook({ secrets: [], id: MSG_ID, timestamp: FIXED_TIMESTAMP, body: BODY }),
		).rejects.toThrow("signStandardWebhook requires `secret` or a non-empty `secrets`");
	});

	it("S14: matches the reference implementation's signature (known-answer vector)", async () => {
		const headers = await signStandardWebhook({
			secret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
			id: "msg_2b1c3d4e5f",
			timestamp: 1755300000,
			body: '{"event":"ping","n":1}',
		});
		expect(headers["webhook-signature"]).toBe("v1,AKA3rHe5r1ZckfgaJAOjjWQ2J999Qbaqxu4Ekf24A+c=");
	});
});
