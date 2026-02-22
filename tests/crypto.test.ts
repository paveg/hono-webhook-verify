import { describe, expect, it } from "vitest";
import { hmac, timingSafeEqual, toBase64, toHex } from "../src/crypto.js";

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

describe("toBase64", () => {
	it("converts ArrayBuffer to base64 string", () => {
		const buffer = new TextEncoder().encode("Hello").buffer;
		expect(toBase64(buffer)).toBe("SGVsbG8=");
	});

	it("handles empty buffer", () => {
		expect(toBase64(new ArrayBuffer(0))).toBe("");
	});
});

describe("timingSafeEqual", () => {
	it("returns true for matching strings", () => {
		expect(timingSafeEqual("abc", "abc")).toBe(true);
	});

	it("returns false for mismatching strings", () => {
		expect(timingSafeEqual("abc", "abd")).toBe(false);
	});

	it("returns false for different lengths", () => {
		expect(timingSafeEqual("abc", "ab")).toBe(false);
		expect(timingSafeEqual("ab", "abc")).toBe(false);
	});

	it("returns true for empty strings", () => {
		expect(timingSafeEqual("", "")).toBe(true);
	});

	it("returns false when one string is a prefix of the other", () => {
		expect(timingSafeEqual("abc", "abcd")).toBe(false);
		expect(timingSafeEqual("abcd", "abc")).toBe(false);
	});

	it("handles long strings", () => {
		const a = "a".repeat(10000);
		const b = "a".repeat(10000);
		expect(timingSafeEqual(a, b)).toBe(true);
	});
});
