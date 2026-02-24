import { describe, expect, it } from "vitest";
import { twilio } from "../../src/providers/twilio.js";
import { generateTwilioSignature } from "../helpers/signatures.js";

const AUTH_TOKEN = "twilio_auth_token";
const URL = "https://example.com/twilio/webhook";
const PARAMS: Record<string, string> = {
	CallSid: "CA1234567890ABCDE",
	Caller: "+14158675310",
	Digits: "1234",
	From: "+14158675310",
	To: "+18005551212",
};

function toUrlEncoded(params: Record<string, string>): string {
	return new URLSearchParams(params).toString();
}

describe("twilio provider", () => {
	it("TW1: verifies valid signature with URL and sorted params", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, PARAMS, AUTH_TOKEN);
		const result = await provider.verify({
			rawBody: toUrlEncoded(PARAMS),
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: true });
	});

	it("TW2: verifies regardless of parameter order in body", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, PARAMS, AUTH_TOKEN);
		// Reverse the key order in the body — sorting should normalize
		const reversedParams: Record<string, string> = {};
		for (const key of Object.keys(PARAMS).reverse()) {
			reversedParams[key] = PARAMS[key];
		}
		const result = await provider.verify({
			rawBody: toUrlEncoded(reversedParams),
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects tampered body", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, PARAMS, AUTH_TOKEN);
		const tampered = { ...PARAMS, Digits: "9999" };
		const result = await provider.verify({
			rawBody: toUrlEncoded(tampered),
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects wrong auth token", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, PARAMS, "wrong_token");
		const result = await provider.verify({
			rawBody: toUrlEncoded(PARAMS),
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("throws on empty authToken", () => {
		expect(() => twilio({ authToken: "" })).toThrow("authToken must not be empty");
	});

	it("rejects missing signature header", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const result = await provider.verify({
			rawBody: toUrlEncoded(PARAMS),
			headers: new Headers(),
			url: URL,
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects missing URL", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, PARAMS, AUTH_TOKEN);
		const result = await provider.verify({
			rawBody: toUrlEncoded(PARAMS),
			headers: new Headers({ "X-Twilio-Signature": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("verifies empty params", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		const signature = await generateTwilioSignature(URL, {}, AUTH_TOKEN);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: true });
	});

	it("handles duplicate parameter keys", async () => {
		const provider = twilio({ authToken: AUTH_TOKEN });
		// URLSearchParams with duplicate keys: "a=1&a=2"
		// forEach yields two entries with key "a", sort comparator returns 0
		const body = "a=1&a=2";
		const signature = await generateTwilioSignature(URL, {}, AUTH_TOKEN, body);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({ "X-Twilio-Signature": signature }),
			url: URL,
		});
		expect(result).toEqual({ valid: true });
	});
});
