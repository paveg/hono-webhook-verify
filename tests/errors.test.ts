import { describe, expect, it } from "vitest";
import {
	bodyReadFailed,
	invalidSignature,
	missingSignature,
	timestampExpired,
} from "../src/errors.js";

describe("error constructors", () => {
	it("bodyReadFailed returns RFC 9457 problem detail", () => {
		const error = bodyReadFailed("Could not read the request body");
		expect(error).toEqual({
			type: "https://hono-webhook-verify.dev/errors/body-read-failed",
			title: "Failed to read request body",
			status: 400,
			detail: "Could not read the request body",
		});
	});

	it("missingSignature returns 401 with correct type", () => {
		const error = missingSignature("sig missing");
		expect(error.status).toBe(401);
		expect(error.type).toContain("missing-signature");
	});

	it("invalidSignature returns 401 with correct type", () => {
		const error = invalidSignature("sig invalid");
		expect(error.status).toBe(401);
		expect(error.type).toContain("invalid-signature");
	});

	it("timestampExpired returns 401 with correct type", () => {
		const error = timestampExpired("ts expired");
		expect(error.status).toBe(401);
		expect(error.type).toContain("timestamp-expired");
	});
});
