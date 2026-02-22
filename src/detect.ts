export type ProviderName =
	| "stripe"
	| "github"
	| "slack"
	| "shopify"
	| "twilio"
	| "line"
	| "discord"
	| "standard-webhooks";

const detectors: Array<{ name: ProviderName; detect: (h: Headers) => boolean }> = [
	{ name: "stripe", detect: (h) => h.has("Stripe-Signature") },
	{ name: "github", detect: (h) => h.has("X-Hub-Signature-256") },
	{ name: "slack", detect: (h) => h.has("X-Slack-Signature") },
	{ name: "shopify", detect: (h) => h.has("X-Shopify-Hmac-Sha256") },
	{ name: "twilio", detect: (h) => h.has("X-Twilio-Signature") },
	{ name: "line", detect: (h) => h.has("X-Line-Signature") },
	{ name: "discord", detect: (h) => h.has("X-Signature-Ed25519") },
	{ name: "standard-webhooks", detect: (h) => h.has("webhook-signature") },
];

/** Detect the webhook provider from request headers. Returns null if unknown. */
export function detectProvider(headers: Headers): ProviderName | null {
	for (const { name, detect } of detectors) {
		if (detect(headers)) return name;
	}
	return null;
}
