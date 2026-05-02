import { type DiscordOptions, discord } from "../../dist/providers/discord.js";
import { type GitHubOptions, github } from "../../dist/providers/github.js";
import { type LineOptions, line } from "../../dist/providers/line.js";
import { type ShopifyOptions, shopify } from "../../dist/providers/shopify.js";
import { type SlackOptions, slack } from "../../dist/providers/slack.js";
import {
	type StandardWebhooksOptions,
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

void _stripe;
void _github;
void _slack;
void _shopify;
void _twilio;
void _line;
void _discord;
void _sw;
