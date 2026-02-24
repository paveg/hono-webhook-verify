import { describe, expect, it } from "vitest";
import { line } from "../../src/providers/line.js";
import { generateLineSignature } from "../helpers/signatures.js";

const SECRET = "line_channel_secret";
const BODY = '{"events":[{"type":"message"}]}';

describe("line provider", () => {
	it("P1: verifies valid signature", async () => {
		const provider = line({ channelSecret: SECRET });
		const signature = await generateLineSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Line-Signature": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P2: rejects tampered body", async () => {
		const provider = line({ channelSecret: SECRET });
		const signature = await generateLineSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: '{"events":[{"type":"tampered"}]}',
			headers: new Headers({ "X-Line-Signature": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("throws on empty channelSecret", () => {
		expect(() => line({ channelSecret: "" })).toThrow("channelSecret must not be empty");
	});

	it("P3: rejects wrong secret", async () => {
		const provider = line({ channelSecret: SECRET });
		const signature = await generateLineSignature(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Line-Signature": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("P4: rejects missing signature header", async () => {
		const provider = line({ channelSecret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("P5: verifies empty body", async () => {
		const provider = line({ channelSecret: SECRET });
		const signature = await generateLineSignature("", SECRET);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({ "X-Line-Signature": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("P6: verifies multibyte body", async () => {
		const provider = line({ channelSecret: SECRET });
		const body = '{"text":"こんにちは世界"}';
		const signature = await generateLineSignature(body, SECRET);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({ "X-Line-Signature": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects invalid base64 signature", async () => {
		const provider = line({ channelSecret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Line-Signature": "not-valid-base64!!!" }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});
});
