import { createMiddleware } from "hono/factory";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { bodyReadFailed, invalidSignature, missingSignature, timestampExpired } from "./errors.js";
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
			url: c.req.url,
		});

		if (!result.valid) {
			const reason = result.reason ?? "invalid-signature";
			const errorFns: Record<string, typeof invalidSignature> = {
				"missing-signature": missingSignature,
				"timestamp-expired": timestampExpired,
			};
			const errorFn = errorFns[reason] ?? invalidSignature;
			const error = errorFn(result.reason ?? "Signature verification failed");
			if (onError) return onError(error, c);
			return c.json(error, error.status as ContentfulStatusCode);
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
