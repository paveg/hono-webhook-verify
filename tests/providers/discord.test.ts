import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { discord } from "../../src/providers/discord.js";
import { generateDiscordSignature, generateEd25519KeyPair } from "../helpers/signatures.js";

let PUBLIC_KEY: string;
let PRIVATE_KEY: CryptoKey;
let OTHER_PRIVATE_KEY: CryptoKey;
const BODY = '{"type":1}';
const TIMESTAMP = "1700000000";

beforeAll(async () => {
	const keyPair = await generateEd25519KeyPair();
	PUBLIC_KEY = keyPair.publicKey;
	PRIVATE_KEY = keyPair.privateKey;
	const otherKeyPair = await generateEd25519KeyPair();
	OTHER_PRIVATE_KEY = otherKeyPair.privateKey;
});

describe("discord provider", () => {
	it("P1: verifies valid signature", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature(BODY, TIMESTAMP, PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Ed25519": signature,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P2: rejects tampered body", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature(BODY, TIMESTAMP, PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: '{"type":2}',
			headers: new Headers({
				"X-Signature-Ed25519": signature,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("P3: rejects wrong key", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature(BODY, TIMESTAMP, OTHER_PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Ed25519": signature,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("P4: rejects missing signature header", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects missing timestamp header", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature(BODY, TIMESTAMP, PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Ed25519": signature,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("P5: verifies empty body", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature("", TIMESTAMP, PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({
				"X-Signature-Ed25519": signature,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P6: verifies multibyte body", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const body = '{"content":"こんにちは"}';
		const signature = await generateDiscordSignature(body, TIMESTAMP, PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({
				"X-Signature-Ed25519": signature,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects invalid hex in signature", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Ed25519": "not-valid-hex!!!",
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("uses cached key on second verification", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const sig1 = await generateDiscordSignature(BODY, TIMESTAMP, PRIVATE_KEY);
		await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Signature-Ed25519": sig1,
				"X-Signature-Timestamp": TIMESTAMP,
			}),
		});
		// Second call hits the cachedKey branch
		const sig2 = await generateDiscordSignature("second", "2000000000", PRIVATE_KEY);
		const result = await provider.verify({
			rawBody: "second",
			headers: new Headers({
				"X-Signature-Ed25519": sig2,
				"X-Signature-Timestamp": "2000000000",
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("throws on invalid hex publicKey", () => {
		expect(() => discord({ publicKey: "not-valid-hex!!!" })).toThrow(
			"publicKey must be a valid hex string",
		);
	});

	it("returns invalid-signature when crypto.subtle.verify throws", async () => {
		const provider = discord({ publicKey: PUBLIC_KEY });
		const signature = await generateDiscordSignature(BODY, TIMESTAMP, PRIVATE_KEY);
		const spy = vi.spyOn(crypto.subtle, "verify").mockRejectedValueOnce(new Error("boom"));
		try {
			const result = await provider.verify({
				rawBody: BODY,
				headers: new Headers({
					"X-Signature-Ed25519": signature,
					"X-Signature-Timestamp": TIMESTAMP,
				}),
			});
			expect(result).toEqual({ valid: false, reason: "invalid-signature" });
		} finally {
			spy.mockRestore();
		}
	});
});
