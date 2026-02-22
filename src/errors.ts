import type { WebhookVerifyError } from "./types.js";

const BASE_URL = "https://hono-webhook-verify.dev/errors";

export function missingSignature(detail: string): WebhookVerifyError {
	return {
		type: `${BASE_URL}/missing-signature`,
		title: "Missing webhook signature",
		status: 401,
		detail,
	};
}

export function invalidSignature(detail: string): WebhookVerifyError {
	return {
		type: `${BASE_URL}/invalid-signature`,
		title: "Webhook signature verification failed",
		status: 401,
		detail,
	};
}

export function timestampExpired(detail: string): WebhookVerifyError {
	return {
		type: `${BASE_URL}/timestamp-expired`,
		title: "Webhook timestamp expired",
		status: 401,
		detail,
	};
}

export function bodyReadFailed(detail: string): WebhookVerifyError {
	return {
		type: `${BASE_URL}/body-read-failed`,
		title: "Failed to read request body",
		status: 400,
		detail,
	};
}
