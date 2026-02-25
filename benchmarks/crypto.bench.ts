import { bench, describe } from "vitest";
import { fromBase64, fromHex, toBase64, toHex } from "../src/crypto.js";

const shortHex = "8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b";
const shortBuffer = new Uint8Array(32).buffer;
const shortBase64 = toBase64(shortBuffer);

describe("fromHex", () => {
	bench("decode SHA-256 hex (64 chars)", () => {
		fromHex(shortHex);
	});

	bench("reject invalid hex", () => {
		fromHex("zzzz");
	});

	bench("reject odd-length hex", () => {
		fromHex("abc");
	});
});

describe("toHex", () => {
	bench("encode 32 bytes", () => {
		toHex(shortBuffer);
	});
});

describe("fromBase64", () => {
	bench("decode 32 bytes base64", () => {
		fromBase64(shortBase64);
	});
});

describe("toBase64", () => {
	bench("encode 32 bytes", () => {
		toBase64(shortBuffer);
	});
});
