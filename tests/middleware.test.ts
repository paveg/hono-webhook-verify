import type { Context } from "hono";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { webhookVerify } from "../src/middleware.js";
import { github } from "../src/providers/github.js";
import { stripe } from "../src/providers/stripe.js";
import type { WebhookVerifyVariables } from "../src/types.js";
import { generateGitHubSignature, generateStripeSignature } from "./helpers/signatures.js";

const GITHUB_SECRET = "gh_test_secret";
const STRIPE_SECRET = "whsec_test_secret";
const BODY = '{"event":"test"}';

function createGitHubApp(handler?: (c: Context) => Response | Promise<Response>) {
	const app = new Hono<{ Variables: WebhookVerifyVariables }>();
	app.post(
		"/webhook",
		webhookVerify({ provider: github({ secret: GITHUB_SECRET }) }),
		handler ?? ((c) => c.json({ ok: true })),
	);
	return app;
}

async function githubRequest(
	app: Hono<{ Variables: WebhookVerifyVariables }>,
	headers?: Record<string, string>,
): Promise<Response> {
	const signature = await generateGitHubSignature(BODY, GITHUB_SECRET);
	return app.request("/webhook", {
		method: "POST",
		body: BODY,
		headers: { "X-Hub-Signature-256": signature, ...headers },
	});
}

function createStripeApp() {
	const app = new Hono<{ Variables: WebhookVerifyVariables }>();
	app.post("/webhook", webhookVerify({ provider: stripe({ secret: STRIPE_SECRET }) }), (c) =>
		c.json({ ok: true }),
	);
	return app;
}

describe("webhookVerify middleware", () => {
	it("M1: passes valid signature and returns handler response", async () => {
		const app = createGitHubApp();
		const res = await githubRequest(app);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ ok: true });
	});

	it("M2: rejects invalid signature with 401", async () => {
		const app = createGitHubApp();
		const signature = await generateGitHubSignature(BODY, "wrong_secret");
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
			headers: { "X-Hub-Signature-256": signature },
		});
		expect(res.status).toBe(401);
		const body = await res.json();
		expect(body.title).toBeDefined();
		expect(body.type).toContain("invalid-signature");
	});

	it("M3: rejects missing signature header with 401", async () => {
		const app = createGitHubApp();
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
		});
		expect(res.status).toBe(401);
		const body = await res.json();
		expect(body.type).toContain("missing-signature");
	});

	it("M4: rejects expired timestamp with 401 (Stripe)", async () => {
		const app = createStripeApp();
		const sixMinAgo = Math.floor(Date.now() / 1000) - 360;
		const { header } = await generateStripeSignature(BODY, STRIPE_SECRET, sixMinAgo);
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
			headers: { "Stripe-Signature": header },
		});
		expect(res.status).toBe(401);
		const body = await res.json();
		expect(body.type).toContain("timestamp-expired");
	});

	it("M5: sets webhookRawBody on context", async () => {
		const app = createGitHubApp((c) => c.text(c.get("webhookRawBody")));
		const res = await githubRequest(app);
		expect(res.status).toBe(200);
		expect(await res.text()).toBe(BODY);
	});

	it("M6: sets webhookPayload on context as parsed JSON", async () => {
		const app = createGitHubApp((c) => c.json(c.get("webhookPayload")));
		const res = await githubRequest(app);
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ event: "test" });
	});

	it("M7: sets webhookProvider on context", async () => {
		const app = createGitHubApp((c) => c.text(c.get("webhookProvider")));
		const res = await githubRequest(app);
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("github");
	});

	it("M8: error detail contains human-readable message, not reason code", async () => {
		const app = createGitHubApp();
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
		});
		const body = await res.json();
		expect(body.detail).not.toBe("missing-signature");
		expect(body.detail).toContain("missing");
	});

	it("M9: custom onError returns custom response", async () => {
		const app = new Hono<{ Variables: WebhookVerifyVariables }>();
		app.post(
			"/webhook",
			webhookVerify({
				provider: github({ secret: GITHUB_SECRET }),
				onError: (error, c) => c.json({ custom: true, reason: error.detail }, 403),
			}),
			(c) => c.json({ ok: true }),
		);
		const res = await app.request("/webhook", {
			method: "POST",
			body: BODY,
		});
		expect(res.status).toBe(403);
		const body = await res.json();
		expect(body.custom).toBe(true);
	});
});
