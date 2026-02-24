import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { fromHex, hmac, timingSafeEqual, toHex } from "../src/crypto.js";
import { defineProvider } from "../src/define-provider.js";
import { webhookVerify } from "../src/middleware.js";
import type { WebhookVerifyVariables } from "../src/types.js";

// Custom provider that uses a simple "X-Custom-Signature: <hex>" header
const customProvider = defineProvider<{ secret: string }>((options) => ({
	name: "custom",
	async verify({ rawBody, headers }) {
		const header = headers.get("X-Custom-Signature");
		if (!header) {
			return { valid: false, reason: "missing-signature" };
		}
		const expected = await hmac("SHA-256", options.secret, rawBody);
		const received = fromHex(header);
		if (received === null || !timingSafeEqual(expected, received)) {
			return { valid: false, reason: "invalid-signature" };
		}
		return { valid: true };
	},
}));

const SECRET = "custom_secret";
const BODY = '{"custom":"payload"}';

async function sign(body: string, secret: string): Promise<string> {
	return toHex(await hmac("SHA-256", secret, body));
}

describe("defineProvider", () => {
	it("creates a provider that verifies valid signatures", async () => {
		const provider = customProvider({ secret: SECRET });
		expect(provider.name).toBe("custom");
		const sig = await sign(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Custom-Signature": sig }),
		});
		expect(result).toEqual({ valid: true });
	});

	it("creates a provider that rejects invalid signatures", async () => {
		const provider = customProvider({ secret: SECRET });
		const sig = await sign(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Custom-Signature": sig }),
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("creates a provider that detects missing headers", async () => {
		const provider = customProvider({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("M1: works with middleware — valid signature passes", async () => {
		const app = new Hono<{ Variables: WebhookVerifyVariables }>();
		app.post("/webhook", webhookVerify({ provider: customProvider({ secret: SECRET }) }), (c) =>
			c.json({ ok: true }),
		);
		const sig = await sign(BODY, SECRET);
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
			headers: { "X-Custom-Signature": sig },
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
	});

	it("M2: works with middleware — invalid signature returns 401", async () => {
		const app = new Hono<{ Variables: WebhookVerifyVariables }>();
		app.post("/webhook", webhookVerify({ provider: customProvider({ secret: SECRET }) }), (c) =>
			c.json({ ok: true }),
		);
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
			headers: { "X-Custom-Signature": "bad" },
		});
		expect(res.status).toBe(401);
	});

	it("M3: works with middleware — missing signature returns 401", async () => {
		const app = new Hono<{ Variables: WebhookVerifyVariables }>();
		app.post("/webhook", webhookVerify({ provider: customProvider({ secret: SECRET }) }), (c) =>
			c.json({ ok: true }),
		);
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
		});
		expect(res.status).toBe(401);
	});
});
