import type { VerifyContext, VerifyResult, WebhookProvider } from "./providers/types.js";

interface DefineProviderInput {
	name: string;
	verify(ctx: VerifyContext): Promise<VerifyResult>;
}

/** Helper to define a custom webhook provider */
export function defineProvider<T>(
	factory: (options: T) => DefineProviderInput,
): (options: T) => WebhookProvider {
	return (options: T) => {
		const { name, verify } = factory(options);
		return { name, verify };
	};
}
