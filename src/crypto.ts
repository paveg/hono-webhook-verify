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
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}
