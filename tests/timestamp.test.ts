import { describe, expect, it } from "vitest";
import { validateTimestamp } from "../src/timestamp.js";

describe("validateTimestamp", () => {
	it("returns null for a valid current timestamp", () => {
		const now = String(Math.floor(Date.now() / 1000));
		expect(validateTimestamp(now, 300)).toBeNull();
	});

	it("returns missing-signature for NaN", () => {
		expect(validateTimestamp("abc", 300)).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("returns missing-signature for zero", () => {
		expect(validateTimestamp("0", 300)).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("returns missing-signature for negative", () => {
		expect(validateTimestamp("-1", 300)).toEqual({ valid: false, reason: "missing-signature" });
	});

	it("returns missing-signature for Infinity", () => {
		expect(validateTimestamp("Infinity", 300)).toEqual({
			valid: false,
			reason: "missing-signature",
		});
	});

	it("returns timestamp-expired for old timestamp", () => {
		const old = String(Math.floor(Date.now() / 1000) - 600);
		expect(validateTimestamp(old, 300)).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("returns timestamp-expired for future timestamp beyond tolerance", () => {
		const future = String(Math.floor(Date.now() / 1000) + 600);
		expect(validateTimestamp(future, 300)).toEqual({ valid: false, reason: "timestamp-expired" });
	});

	it("returns null at exactly the tolerance boundary", () => {
		const boundary = String(Math.floor(Date.now() / 1000) - 300);
		expect(validateTimestamp(boundary, 300)).toBeNull();
	});
});
