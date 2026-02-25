import { Hono } from "hono";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WebhookProvider } from "../src/types.js";

const rejectingProvider: WebhookProvider = {
	name: "test-reject",
	verify: async () => ({ valid: false, reason: "invalid-signature" }),
};

describe("getHonoProblemDetails", () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it("returns module when hono-problem-details is available", async () => {
		const { getHonoProblemDetails } = await import("../src/compat.js");
		const pd = await getHonoProblemDetails();
		expect(pd).not.toBeNull();
		expect(pd).toHaveProperty("problemDetails");
	});

	it("caches result on subsequent calls", async () => {
		const { getHonoProblemDetails } = await import("../src/compat.js");
		const first = await getHonoProblemDetails();
		const second = await getHonoProblemDetails();
		expect(first).toBe(second);
	});

	it("returns null when hono-problem-details is not installed", async () => {
		vi.doMock("hono-problem-details", () => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		const { getHonoProblemDetails } = await import("../src/compat.js");
		const pd = await getHonoProblemDetails();
		expect(pd).toBeNull();
	});

	it("caches null when module is not available", async () => {
		const factory = vi.fn(() => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		vi.doMock("hono-problem-details", factory);
		const { getHonoProblemDetails } = await import("../src/compat.js");
		await getHonoProblemDetails();
		const second = await getHonoProblemDetails();
		expect(second).toBeNull();
		// import() must be attempted only once — second call uses cached null
		expect(factory).toHaveBeenCalledTimes(1);
	});
});

describe("middleware fallback when hono-problem-details is unavailable", () => {
	beforeEach(() => {
		vi.resetModules();
	});

	it("uses fallback response with application/problem+json", async () => {
		vi.doMock("hono-problem-details", () => {
			throw new Error("Cannot find module 'hono-problem-details'");
		});
		const { webhookVerify } = await import("../src/middleware.js");
		const app = new Hono();
		app.post("/webhook", webhookVerify({ provider: rejectingProvider }), (c) =>
			c.json({ ok: true }),
		);

		const res = await app.request("/webhook", {
			method: "POST",
			body: "{}",
		});
		expect(res.status).toBe(401);
		const body = await res.json();
		expect(body.title).toBe("Webhook signature verification failed");
		expect(res.headers.get("Content-Type")).toBe("application/problem+json; charset=utf-8");
	});
});
