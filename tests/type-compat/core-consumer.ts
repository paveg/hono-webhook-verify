import type {
	DefineProviderInput,
	ProviderFactory,
	ProviderName,
	VerifyContext,
	VerifyFailureReason,
	VerifyResult,
	WebhookProvider,
	WebhookVerifyError,
	WebhookVerifyOptions,
	WebhookVerifyVariables,
} from "../../dist/index.js";
import {
	bodyReadFailed,
	defineProvider,
	detectProvider,
	fromBase64,
	fromHex,
	hmac,
	invalidSignature,
	missingSignature,
	timestampExpired,
	timingSafeEqual,
	toBase64,
	toHex,
	webhookVerify,
} from "../../dist/index.js";

const _failureReason: VerifyFailureReason = "missing-signature";
const _result: VerifyResult = { valid: true };
const _ctx: VerifyContext = { rawBody: "", headers: new Headers() };

const _provider: WebhookProvider = {
	name: "test",
	async verify(_c) {
		return { valid: true };
	},
};

const _factory: ProviderFactory<{ secret: string }> = (opts) => ({
	name: "custom",
	async verify(_c) {
		void opts.secret;
		return { valid: true };
	},
});

const _detectName: ProviderName | null = detectProvider(new Headers());

const _err: WebhookVerifyError = {
	type: "https://example.com/missing",
	title: "Missing",
	status: 401,
	detail: "...",
};

const _opts: WebhookVerifyOptions = { provider: _provider };
const _vars: WebhookVerifyVariables = {
	webhookRawBody: "",
	webhookPayload: null,
	webhookProvider: "stripe",
};

const _middleware = webhookVerify({ provider: _provider });

const _customFactory = defineProvider<{ secret: string }>((opts) => ({
	name: "x",
	async verify(_c) {
		void opts.secret;
		return { valid: true };
	},
}));
const _custom = _customFactory({ secret: "abc" });

const _input: DefineProviderInput = {
	name: "x",
	async verify(_c) {
		return { valid: true };
	},
};

const _e1 = missingSignature("X-Sig");
const _e2 = invalidSignature("stripe");
const _e3 = timestampExpired("300s exceeded");
const _e4 = bodyReadFailed("read failure");

async function _cryptoCheck() {
	const sig = await hmac("SHA-256", "secret", "payload");
	const hex = toHex(sig);
	const back1 = fromHex(hex);
	const b64 = toBase64(sig);
	const back2 = fromBase64(b64);
	const eq = timingSafeEqual(sig, sig);
	void hex;
	void back1;
	void b64;
	void back2;
	void eq;
}

void _failureReason;
void _result;
void _ctx;
void _provider;
void _factory;
void _detectName;
void _err;
void _opts;
void _vars;
void _middleware;
void _customFactory;
void _custom;
void _input;
void _e1;
void _e2;
void _e3;
void _e4;
void _cryptoCheck;
