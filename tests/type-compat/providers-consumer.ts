import { type DiscordOptions, discord } from "../../dist/providers/discord.js";
import { type GitHubOptions, github } from "../../dist/providers/github.js";
import { type LineOptions, line } from "../../dist/providers/line.js";
import { type ShopifyOptions, shopify } from "../../dist/providers/shopify.js";
import { type SlackOptions, slack } from "../../dist/providers/slack.js";
import {
	type SignStandardWebhookOptions,
	type StandardWebhookHeaders,
	type StandardWebhooksOptions,
	signStandardWebhook,
	standardWebhooks,
} from "../../dist/providers/standard-webhooks.js";
import { type StripeOptions, stripe } from "../../dist/providers/stripe.js";
import { type TwilioOptions, twilio } from "../../dist/providers/twilio.js";

const _stripeOpts: StripeOptions = { secret: "whsec_x", tolerance: 300 };
const _githubOpts: GitHubOptions = { secret: "ghs_x" };
const _slackOpts: SlackOptions = { signingSecret: "shh", tolerance: 300 };
const _shopifyOpts: ShopifyOptions = { secret: "shopify_x" };
const _twilioOpts: TwilioOptions = { authToken: "tok_x" };
const _lineOpts: LineOptions = { channelSecret: "line_x" };
const _discordOpts: DiscordOptions = {
	publicKey: "0".repeat(64),
	tolerance: 300,
};
const _swOpts: StandardWebhooksOptions = { secret: "whsec_swh", tolerance: 300 };

const _stripe = stripe(_stripeOpts);
const _github = github(_githubOpts);
const _slack = slack(_slackOpts);
const _shopify = shopify(_shopifyOpts);
const _twilio = twilio(_twilioOpts);
const _line = line(_lineOpts);
const _discord = discord(_discordOpts);
const _sw = standardWebhooks(_swOpts);

// signStandardWebhook: at least one of `secret` / `secrets` is required at the type level.
const _signOptsSecret: SignStandardWebhookOptions = {
	secret: "whsec_swh",
	id: "msg_1",
	body: "{}",
};
const _signOptsSecrets: SignStandardWebhookOptions = {
	secrets: ["whsec_a", "whsec_b"],
	id: "msg_1",
	body: "{}",
};
const _signHeaders: Promise<StandardWebhookHeaders> = signStandardWebhook(_signOptsSecret);
void signStandardWebhook(_signOptsSecrets);

// The returned headers must be directly assignable to HeadersInit.
async function _headersAssignable() {
	const headers = await _signHeaders;
	new Headers(headers);
	await fetch("https://example.com", { method: "POST", headers, body: "{}" });
}
void _headersAssignable;

void _stripe;
void _github;
void _slack;
void _shopify;
void _twilio;
void _line;
void _discord;
void _sw;
