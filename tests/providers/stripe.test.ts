import { describe, expect, it } from "vitest";
import { stripe } from "../../src/providers/stripe.js";
import { EXPIRED_OFFSET_S } from "../helpers/constants.js";
import { generateStripeSignature } from "../helpers/signatures.js";

const SECRET = "whsec_test_secret";
const BODY = '{"type":"checkout.session.completed"}';

describe("stripe provider", () => {
	it("verifies valid signature", async () => {
		const provider = stripe({ secret: SECRET });
		const { header } = await generateStripeSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects tampered body", async () => {
		const provider = stripe({ secret: SECRET });
		const { header } = await generateStripeSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: `${BODY}tampered`,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result.valid).toBe(false);
		expect(result.reason).toBe("invalid-signature");
	});

	it("rejects wrong secret", async () => {
		const provider = stripe({ secret: SECRET });
		const { header } = await generateStripeSignature(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result.valid).toBe(false);
		expect(result.reason).toBe("invalid-signature");
	});

	it("rejects missing signature header", async () => {
		const provider = stripe({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("verifies empty body", async () => {
		const provider = stripe({ secret: SECRET });
		const { header } = await generateStripeSignature("", SECRET);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("verifies multibyte body", async () => {
		const provider = stripe({ secret: SECRET });
		const body = '{"message":"こんにちは世界"}';
		const { header } = await generateStripeSignature(body, SECRET);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects expired timestamp", async () => {
		const provider = stripe({ secret: SECRET });
		const expired = Math.floor(Date.now() / 1000) - EXPIRED_OFFSET_S;
		const { header } = await generateStripeSignature(BODY, SECRET, expired);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("accepts timestamp at exactly the tolerance boundary", async () => {
		const provider = stripe({ secret: SECRET, tolerance: 60 });
		const exactlyAtBoundary = Math.floor(Date.now() / 1000) - 60;
		const { header } = await generateStripeSignature(BODY, SECRET, exactlyAtBoundary);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects with tolerance: 0 when timestamp is 1 second off", async () => {
		const provider = stripe({ secret: SECRET, tolerance: 0 });
		const oneSecAgo = Math.floor(Date.now() / 1000) - 1;
		const { header } = await generateStripeSignature(BODY, SECRET, oneSecAgo);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("respects custom tolerance", async () => {
		const provider = stripe({ secret: SECRET, tolerance: 60 });
		const twoMinAgo = Math.floor(Date.now() / 1000) - 120;
		const { header } = await generateStripeSignature(BODY, SECRET, twoMinAgo);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": header }),
		});
		expect(result).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("rejects non-numeric timestamp", async () => {
		const provider = stripe({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"Stripe-Signature": "t=abc,v1=fakesig",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects zero timestamp", async () => {
		const provider = stripe({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"Stripe-Signature": "t=0,v1=fakesig",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("rejects negative timestamp", async () => {
		const provider = stripe({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"Stripe-Signature": "t=-100,v1=fakesig",
			}),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("throws on empty secret", () => {
		expect(() => stripe({ secret: "" })).toThrow("secret must not be empty");
	});

	it("rejects empty signature value (v1=)", async () => {
		const provider = stripe({ secret: SECRET });
		const ts = Math.floor(Date.now() / 1000);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": `t=${ts},v1=` }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects malformed header without t= or v1=", async () => {
		const provider = stripe({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "Stripe-Signature": "invalid_header_format" }),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});
});
