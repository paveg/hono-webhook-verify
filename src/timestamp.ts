import type { VerifyResult } from "./providers/types.js";

/**
 * Validate a Unix timestamp string against a tolerance window.
 * Returns a failure result if invalid, or null if the timestamp is acceptable.
 */
export function validateTimestamp(timestamp: string, tolerance: number): VerifyResult | null {
	const ts = Number(timestamp);
	if (!Number.isFinite(ts) || ts <= 0) {
		return { valid: false, reason: "missing-signature" };
	}
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - ts) > tolerance) {
		return { valid: false, reason: "timestamp-expired" };
	}
	return null;
}
