import { describe, expect, it } from "vitest";
import { github } from "../../src/providers/github.js";
import { generateGitHubSignature } from "../helpers/signatures.js";

const SECRET = "gh_webhook_secret";
const BODY = '{"action":"opened","number":1}';

describe("github provider", () => {
	it("verifies valid signature", async () => {
		const provider = github({ secret: SECRET });
		const signature = await generateGitHubSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Hub-Signature-256": signature }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: true });
	});

	it("rejects tampered body", async () => {
		const provider = github({ secret: SECRET });
		const signature = await generateGitHubSignature(BODY, SECRET);
		const result = await provider.verify({
			rawBody: `${BODY}tampered`,
			headers: new Headers({ "X-Hub-Signature-256": signature }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects wrong secret", async () => {
		const provider = github({ secret: SECRET });
		const signature = await generateGitHubSignature(BODY, "wrong_secret");
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Hub-Signature-256": signature }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects missing signature header", async () => {
		const provider = github({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers(),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("verifies empty body", async () => {
		const provider = github({ secret: SECRET });
		const signature = await generateGitHubSignature("", SECRET);
		const result = await provider.verify({
			rawBody: "",
			headers: new Headers({ "X-Hub-Signature-256": signature }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: true });
	});

	it("verifies multibyte body", async () => {
		const provider = github({ secret: SECRET });
		const body = '{"message":"こんにちは世界"}';
		const signature = await generateGitHubSignature(body, SECRET);
		const result = await provider.verify({
			rawBody: body,
			headers: new Headers({ "X-Hub-Signature-256": signature }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: true });
	});

	// A header that is present but lacks the sha256= prefix is a malformed
	// signature, not a missing one — the reason code must reflect this so that
	// middleware can return the correct HTTP status.
	it("rejects header without sha256= prefix with invalid-signature reason", async () => {
		const provider = github({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({
				"X-Hub-Signature-256": "not_a_valid_format",
			}),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects a hex value that is too short", async () => {
		const provider = github({ secret: SECRET });
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Hub-Signature-256": "sha256=deadbeef" }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	it("rejects a hex value containing non-hex characters", async () => {
		const provider = github({ secret: SECRET });
		const hex = "z".repeat(64);
		const result = await provider.verify({
			rawBody: BODY,
			headers: new Headers({ "X-Hub-Signature-256": `sha256=${hex}` }),
			secret: SECRET,
		});
		expect(result).toEqual({ valid: false, reason: "invalid-signature" });
	});

	// An empty secret produces a valid but degenerate HMAC. The provider must
	// reject empty secrets at construction time, not at verification time.
	it("throws when constructed with an empty secret", () => {
		expect(() => github({ secret: "" })).toThrow("secret must not be empty");
	});
});
