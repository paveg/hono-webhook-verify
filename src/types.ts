import type { Context } from "hono";
import type { WebhookProvider } from "./providers/types.js";

/** Middleware options */
export interface WebhookVerifyOptions {
	provider: WebhookProvider;
	onError?: (error: WebhookVerifyError, c: Context) => Response | Promise<Response>;
}

/** Error object passed to onError callback */
export interface WebhookVerifyError {
	type: string;
	title: string;
	status: number;
	detail: string;
}

/** Context variables set by the middleware */
export interface WebhookVerifyVariables {
	webhookRawBody: string;
	webhookPayload: unknown;
	webhookProvider: string;
}
