import { describe, expect, it } from "vitest";
import { slack } from "../../src/providers/slack.js";
import { DEFAULT_TOLERANCE_S, EXPIRED_OFFSET_S } from "../helpers/constants.js";
import { generateSlackSignature } from "../helpers/signatures.js";

const SECRET = "slack_signing_secret";
const BODY = "token=xyzz0WbapA4vBCDEFasx0q6G&command=%2Fweather";

describe("slack provider", () => {
	it("verifies valid signature", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature, timestamp } = await generateSlackSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects tampered body", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature, timestamp } = await generateSlackSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: `${BODY}tampered`,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects wrong secret", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature, timestamp } = await generateSlackSignature(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("throws on empty signingSecret", () => {
		expect(() => slack({ signingSecret: "" })).toThrow("signingSecret must not be empty");
	});

	it("rejects missing signature header", async () => {
		const provider = slack({ signingSecret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects missing timestamp header", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature } = await generateSlackSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Slack-Signature": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("verifies empty body", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature, timestamp } = await generateSlackSignature("", SECRET);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("verifies multibyte body", async () => {
		const provider = slack({ signingSecret: SECRET });
		const body = '{"text":"こんにちは"}';
		const { signature, timestamp } = await generateSlackSignature(body, SECRET);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects expired timestamp", async () => {
		const provider = slack({ signingSecret: SECRET });
		const expired = Math.floor(Date.now() / 1000) - EXPIRED_OFFSET_S;
		const { signature } = await generateSlackSignature(BODY, SECRET, expired);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(expired),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("respects custom tolerance", async () => {
		const provider = slack({ signingSecret: SECRET, tolerance: 60 });
		const twoMinAgo = Math.floor(Date.now() / 1000) - 120;
		const { signature } = await generateSlackSignature(BODY, SECRET, twoMinAgo);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(twoMinAgo),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("accepts timestamp at exactly the tolerance boundary", async () => {
		const provider = slack({ signingSecret: SECRET, tolerance: 60 });
		const exactlyAtBoundary = Math.floor(Date.now() / 1000) - 60;
		const { signature } = await generateSlackSignature(BODY, SECRET, exactlyAtBoundary);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(exactlyAtBoundary),
			}),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects with tolerance: 0 when timestamp is 1 second off", async () => {
		const provider = slack({ signingSecret: SECRET, tolerance: 0 });
		const oneSecAgo = Math.floor(Date.now() / 1000) - 1;
		const { signature } = await generateSlackSignature(BODY, SECRET, oneSecAgo);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(oneSecAgo),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("rejects zero timestamp", async () => {
		const provider = slack({ signingSecret: SECRET });
		// Generate signature for timestamp 0 to isolate the ts <= 0 guard
		const { signature } = await generateSlackSignature(BODY, SECRET, 0);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": "0",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects negative timestamp", async () => {
		const provider = slack({ signingSecret: SECRET });
		// Generate signature for negative timestamp to isolate the ts <= 0 guard
		const { signature } = await generateSlackSignature(BODY, SECRET, -100);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": "-100",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects non-numeric timestamp", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature } = await generateSlackSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": "not-a-number",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects signature without v0= prefix", async () => {
		const provider = slack({ signingSecret: SECRET });
		const { signature, timestamp } = await generateSlackSignature(BODY, SECRET);
		// Strip the v0= prefix — should be rejected even if hex is valid
		const rawHex = signature.slice(3);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": rawHex,
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects v0= prefix with empty hex", async () => {
		const provider = slack({ signingSecret: SECRET });
		const timestamp = Math.floor(Date.now() / 1000);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": "v0=",
				"X-Slack-Request-Timestamp": String(timestamp),
			}),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});
});
