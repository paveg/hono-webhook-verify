const encoder = new TextEncoder();

/** Compute HMAC signature using Web Crypto API */
export async function hmac(
	algorithm: "SHA-256" | "SHA-1",
	secret: string,
	data: string,
): Promise<ArrayBuffer> {
	const key = await crypto.subtle.importKey(
		"raw",
		encoder.encode(secret),
		{ name: "HMAC", hash: algorithm },
		false,
		["sign"],
	);
	return crypto.subtle.sign("HMAC", key, encoder.encode(data));
}

/** Convert ArrayBuffer to hex string */
export function toHex(buffer: ArrayBuffer): string {
	return Array.from(new Uint8Array(buffer))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Convert ArrayBuffer to base64 string */
export function toBase64(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (const byte of bytes) {
		binary += String.fromCharCode(byte);
	}
	return btoa(binary);
}

/** Constant-time string comparison to prevent timing attacks */
export function timingSafeEqual(a: string, b: string): boolean {
	const lenA = a.length;
	const lenB = b.length;
	const len = Math.max(lenA, lenB);
	let result = lenA ^ lenB;
	for (let i = 0; i < len; i++) {
		const ca = i < lenA ? a.charCodeAt(i) : 0;
		const cb = i < lenB ? b.charCodeAt(i) : 0;
		result |= ca ^ cb;
	}
	return result === 0;
}
