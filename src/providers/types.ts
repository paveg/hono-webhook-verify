/** Provider verification result */
export interface VerifyResult {
	valid: boolean;
	reason?: string;
}

/** Context passed to provider's verify method */
export interface VerifyContext {
	rawBody: string;
	headers: Headers;
	/** Required for Twilio (URL is part of the signature payload) */
	url?: string;
}

/** Webhook provider definition */
export interface WebhookProvider {
	name: string;
	verify(ctx: VerifyContext): Promise<VerifyResult>;
}

/** Factory function type for creating providers with options */
export type ProviderFactory<T> = (options: T) => WebhookProvider;
