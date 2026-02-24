import { describe, expect, it } from "vitest";
import { detectProvider } from "../src/detect.js";

describe("detectProvider", () => {
	it("detects Stripe", () => {
		const headers = new Headers({ "Stripe-Signature": "t=123,v1=abc" });
		expect(detectProvider(headers)).toBe("stripe");
	});

	it("detects GitHub", () => {
		const headers = new Headers({ "X-Hub-Signature-256": "sha256=abc" });
		expect(detectProvider(headers)).toBe("github");
	});

	it("detects Slack", () => {
		const headers = new Headers({
			"X-Slack-Signature": "v0=abc",
			"X-Slack-Request-Timestamp": "123",
		});
		expect(detectProvider(headers)).toBe("slack");
	});

	it("detects Shopify", () => {
		const headers = new Headers({ "X-Shopify-Hmac-Sha256": "abc" });
		expect(detectProvider(headers)).toBe("shopify");
	});

	it("detects Twilio", () => {
		const headers = new Headers({ "X-Twilio-Signature": "abc" });
		expect(detectProvider(headers)).toBe("twilio");
	});

	it("detects LINE", () => {
		const headers = new Headers({ "X-Line-Signature": "abc" });
		expect(detectProvider(headers)).toBe("line");
	});

	it("detects Discord", () => {
		const headers = new Headers({
			"X-Signature-Ed25519": "abc",
			"X-Signature-Timestamp": "123",
		});
		expect(detectProvider(headers)).toBe("discord");
	});

	it("detects Standard Webhooks", () => {
		const headers = new Headers({
			"webhook-id": "msg_123",
			"webhook-signature": "v1,abc",
			"webhook-timestamp": "123",
		});
		expect(detectProvider(headers)).toBe("standard-webhooks");
	});

	it("returns null for unknown headers", () => {
		const headers = new Headers({ "X-Custom-Sig": "abc" });
		expect(detectProvider(headers)).toBeNull();
	});

	it("returns null for empty headers", () => {
		const headers = new Headers();
		expect(detectProvider(headers)).toBeNull();
	});

	it("returns first matching provider when multiple headers are present", () => {
		// Stripe is first in the detector array, so it wins over GitHub
		const headers = new Headers({
			"Stripe-Signature": "t=123,v1=abc",
			"X-Hub-Signature-256": "sha256=abc",
		});
		expect(detectProvider(headers)).toBe("stripe");
	});
});
