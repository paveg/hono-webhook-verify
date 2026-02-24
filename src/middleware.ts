import { createMiddleware } from "hono/factory";
import { getHonoProblemDetails } from "./compat.js";
import { bodyReadFailed, invalidSignature, missingSignature, timestampExpired } from "./errors.js";
import type { WebhookVerifyError, WebhookVerifyOptions, WebhookVerifyVariables } from "./types.js";

async function errorResponse(error: WebhookVerifyError): Promise<Response> {
	const pd = await getHonoProblemDetails();
	if (pd) {
		return pd
			.problemDetails({
				type: error.type,
				title: error.title,
				status: error.status,
				detail: error.detail,
			})
			.getResponse();
	}
	return new Response(JSON.stringify(error), {
		status: error.status,
		headers: { "Content-Type": "application/problem+json" },
	});
}

export function webhookVerify(options: WebhookVerifyOptions) {
	const { provider, onError } = options;

	return createMiddleware<{ Variables: WebhookVerifyVariables }>(async (c, next) => {
		let rawBody: string;
		try {
			rawBody = await c.req.text();
		} catch {
			const error = bodyReadFailed("Could not read the request body");
			if (onError) return onError(error, c);
			return errorResponse(error);
		}

		const result = await provider.verify({
			rawBody,
			headers: c.req.raw.headers,
			url: c.req.url,
		});

		if (!result.valid) {
			const reason = result.reason ?? "invalid-signature";
			const detailMessages: Record<string, string> = {
				"missing-signature": "Required webhook signature header is missing",
				"invalid-signature": "Signature verification failed",
				"timestamp-expired": "Webhook timestamp is outside the allowed tolerance",
			};
			const errorFns: Record<string, typeof invalidSignature> = {
				"missing-signature": missingSignature,
				"timestamp-expired": timestampExpired,
			};
			const errorFn = errorFns[reason] ?? invalidSignature;
			const error = errorFn(detailMessages[reason] ?? "Signature verification failed");
			if (onError) return onError(error, c);
			return errorResponse(error);
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
