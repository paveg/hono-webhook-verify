import { describe, expect, it } from "vitest";
import { fromBase64, fromHex, hmac, timingSafeEqual, toBase64, toHex } from "../src/crypto.js";

describe("hmac", () => {
	it("computes HMAC-SHA256 and returns correct hex", async () => {
		const result = toHex(await hmac("SHA-256", "secret", "message"));
		// echo -n "message" | openssl dgst -sha256 -hmac "secret"
		expect(result).toBe("8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b");
	});

	it("computes HMAC-SHA1 and returns correct base64", async () => {
		const result = toBase64(await hmac("SHA-1", "secret", "message"));
		// echo -n "message" | openssl dgst -sha1 -hmac "secret" -binary | base64
		expect(result).toBe("DK9kn+7klT2Hv5A6wRdsReAo3xY=");
	});

	it("handles empty data", async () => {
		const hex = toHex(await hmac("SHA-256", "secret", ""));
		expect(hex).toHaveLength(64);
	});

	it("handles UTF-8 data", async () => {
		const hex = toHex(await hmac("SHA-256", "secret", "こんにちは"));
		expect(hex).toHaveLength(64);
	});
});

describe("toHex", () => {
	it("converts ArrayBuffer to hex string", () => {
		const buffer = new Uint8Array([0x00, 0xff, 0x0a, 0xab]).buffer;
		expect(toHex(buffer)).toBe("00ff0aab");
	});

	it("handles empty buffer", () => {
		expect(toHex(new ArrayBuffer(0))).toBe("");
	});
});

describe("fromHex", () => {
	it("decodes a valid hex string", () => {
		const buf = fromHex("00ff0aab") as ArrayBuffer;
		expect(new Uint8Array(buf)).toEqual(new Uint8Array([0x00, 0xff, 0x0a, 0xab]));
	});

	it("returns null for odd-length input", () => {
		expect(fromHex("abc")).toBeNull();
	});

	it("returns null for non-hex characters", () => {
		expect(fromHex("zz")).toBeNull();
	});

	it("handles empty string", () => {
		const buf = fromHex("") as ArrayBuffer;
		expect(buf.byteLength).toBe(0);
	});

	it("round-trips with toHex", async () => {
		const original = await hmac("SHA-256", "secret", "message");
		const hex = toHex(original);
		const decoded = fromHex(hex) as ArrayBuffer;
		expect(new Uint8Array(decoded)).toEqual(new Uint8Array(original));
	});
});

describe("toBase64", () => {
	it("converts ArrayBuffer to base64 string", () => {
		const buffer = new TextEncoder().encode("Hello").buffer;
		expect(toBase64(buffer)).toBe("SGVsbG8=");
	});

	it("handles empty buffer", () => {
		expect(toBase64(new ArrayBuffer(0))).toBe("");
	});
});

describe("fromBase64", () => {
	it("decodes a valid base64 string", () => {
		const buf = fromBase64("SGVsbG8=") as ArrayBuffer;
		expect(new TextDecoder().decode(buf)).toBe("Hello");
	});

	it("returns null for invalid base64", () => {
		expect(fromBase64("!!!")).toBeNull();
	});

	it("handles empty string", () => {
		const buf = fromBase64("") as ArrayBuffer;
		expect(buf.byteLength).toBe(0);
	});

	it("round-trips with toBase64", async () => {
		const original = await hmac("SHA-256", "secret", "message");
		const b64 = toBase64(original);
		const decoded = fromBase64(b64) as ArrayBuffer;
		expect(new Uint8Array(decoded)).toEqual(new Uint8Array(original));
	});
});

describe("timingSafeEqual", () => {
	it("returns true for identical buffers", async () => {
		const a = await hmac("SHA-256", "secret", "message");
		const b = await hmac("SHA-256", "secret", "message");
		expect(timingSafeEqual(a, b)).toBe(true);
	});

	it("returns false for different HMAC outputs", async () => {
		const a = await hmac("SHA-256", "secret", "message");
		const b = await hmac("SHA-256", "secret", "other");
		expect(timingSafeEqual(a, b)).toBe(false);
	});

	it("returns false for different byte lengths", async () => {
		const a = await hmac("SHA-256", "secret", "message");
		const b = await hmac("SHA-1", "secret", "message");
		expect(timingSafeEqual(a, b)).toBe(false);
	});

	it("returns true for empty buffers", () => {
		expect(timingSafeEqual(new ArrayBuffer(0), new ArrayBuffer(0))).toBe(true);
	});

	it("returns false when buffers differ in the last byte only", () => {
		const a = new Uint8Array([0x00, 0x01, 0x02, 0xff]);
		const b = new Uint8Array([0x00, 0x01, 0x02, 0xfe]);
		expect(timingSafeEqual(a.buffer, b.buffer)).toBe(false);
	});

	it("does not short-circuit on length mismatch — returns false without leaking content", () => {
		// Verifies the length guard is present and returns false, not that it
		// runs in constant time (which cannot be asserted in JS).
		const a = new Uint8Array([0xaa, 0xbb]);
		const b = new Uint8Array([0xaa, 0xbb, 0xcc]);
		expect(timingSafeEqual(a.buffer, b.buffer)).toBe(false);
	});
});
