import { createMiddleware } from "hono/factory";
import { bodyReadFailed } from "./errors.js";
import type { WebhookVerifyOptions, WebhookVerifyVariables } from "./types.js";

export function webhookVerify(options: WebhookVerifyOptions) {
	const { provider, onError } = options;

	return createMiddleware<{ Variables: WebhookVerifyVariables }>(async (c, next) => {
		let rawBody: string;
		try {
			rawBody = await c.req.text();
		} catch {
			const error = bodyReadFailed("Could not read the request body");
			if (onError) return onError(error, c);
			return c.json(error, 400);
		}

		const result = await provider.verify({
			rawBody,
			headers: c.req.raw.headers,
			secret: "",
			url: c.req.url,
		});

		if (!result.valid) {
			const errorFactory = await import("./errors.js");
			const reason = result.reason ?? "invalid-signature";
			const errorFn =
				reason === "missing-signature"
					? errorFactory.missingSignature
					: reason === "timestamp-expired"
						? errorFactory.timestampExpired
						: errorFactory.invalidSignature;
			const error = errorFn(result.reason ?? "Signature verification failed");
			if (onError) return onError(error, c);
			return c.json(error, error.status as 400 | 401);
		}

		c.set("webhookRawBody", rawBody);
		c.set("webhookProvider", provider.name);
		try {
			c.set("webhookPayload", JSON.parse(rawBody));
		} catch {
			c.set("webhookPayload", null);
		}

		await next();
	});
}
