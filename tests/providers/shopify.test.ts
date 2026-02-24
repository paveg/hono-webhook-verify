import { describe, expect, it } from "vitest";
import { shopify } from "../../src/providers/shopify.js";
import { generateShopifySignature } from "../helpers/signatures.js";

const SECRET = "shopify_webhook_secret";
const BODY = '{"id":1,"topic":"orders/create"}';

describe("shopify provider", () => {
	it("verifies valid signature", async () => {
		const provider = shopify({ secret: SECRET });
		const signature = await generateShopifySignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Shopify-Hmac-Sha256": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects tampered body", async () => {
		const provider = shopify({ secret: SECRET });
		const signature = await generateShopifySignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: `${BODY}tampered`,
			headers: new Headers({ "X-Shopify-Hmac-Sha256": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("throws on empty secret", () => {
		expect(() => shopify({ secret: "" })).toThrow("secret must not be empty");
	});

	it("rejects wrong secret", async () => {
		const provider = shopify({ secret: SECRET });
		const signature = await generateShopifySignature(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Shopify-Hmac-Sha256": signature }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects missing signature header", async () => {
		const provider = shopify({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("verifies empty body", async () => {
		const provider = shopify({ secret: SECRET });
		const signature = await generateShopifySignature("", SECRET);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({ "X-Shopify-Hmac-Sha256": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("verifies multibyte body", async () => {
		const provider = shopify({ secret: SECRET });
		const body = '{"name":"こんにちは"}';
		const signature = await generateShopifySignature(body, SECRET);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({ "X-Shopify-Hmac-Sha256": signature }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects invalid base64 signature", async () => {
		const provider = shopify({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Shopify-Hmac-Sha256": "!!!invalid-base64!!!" }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});
});
