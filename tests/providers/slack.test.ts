import { describe, expect, it } from "vitest";
import { slack } from "../../src/providers/slack.js";
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
		const sixMinAgo = Math.floor(Date.now() / 1000) - 360;
		const { signature } = await generateSlackSignature(BODY, SECRET, sixMinAgo);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Slack-Signature": signature,
				"X-Slack-Request-Timestamp": String(sixMinAgo),
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
});
