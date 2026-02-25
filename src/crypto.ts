const encoder = new TextEncoder();

/** Compute HMAC signature using Web Crypto API */
export async function hmac(
	algorithm: "SHA-256" | "SHA-1",
	secret: string | ArrayBuffer,
	data: string,
): Promise<ArrayBuffer> {
	const keyData = typeof secret === "string" ? encoder.encode(secret) : secret;
	const key = await crypto.subtle.importKey(
		"raw",
		keyData,
		{ name: "HMAC", hash: algorithm },
		false,
		["sign"],
	);
	return crypto.subtle.sign("HMAC", key, encoder.encode(data));
}

const HEX_TABLE = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));

/** Convert ArrayBuffer to hex string */
export function toHex(buffer: ArrayBuffer): string {
	const bytes = new Uint8Array(buffer);
	let hex = "";
	for (let i = 0; i < bytes.length; i++) {
		hex += HEX_TABLE[bytes[i]];
	}
	return hex;
}

// charCode → nibble value; -1 for invalid characters
const HEX_NIBBLE = new Int8Array(128).fill(-1);
for (let i = 0; i < 10; i++) HEX_NIBBLE[0x30 + i] = i; // '0'-'9'
for (let i = 0; i < 6; i++) {
	HEX_NIBBLE[0x41 + i] = 10 + i; // 'A'-'F'
	HEX_NIBBLE[0x61 + i] = 10 + i; // 'a'-'f'
}

/** Decode a hex string into an ArrayBuffer. Returns null for invalid input. */
export function fromHex(hex: string): ArrayBuffer | null {
	const len = hex.length;
	if (len % 2 !== 0) return null;
	const bytes = new Uint8Array(len >>> 1);
	for (let i = 0; i < len; i += 2) {
		const c1 = hex.charCodeAt(i);
		const c2 = hex.charCodeAt(i + 1);
		if (c1 >= 128 || c2 >= 128) return null;
		const hi = HEX_NIBBLE[c1];
		const lo = HEX_NIBBLE[c2];
		if (hi === -1 || lo === -1) return null;
		bytes[i >>> 1] = (hi << 4) | lo;
	}
	return bytes.buffer;
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

/** Decode a base64 string into an ArrayBuffer. Returns null for invalid input. */
export function fromBase64(b64: string): ArrayBuffer | null {
	try {
		const binary = atob(b64);
		const bytes = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) {
			bytes[i] = binary.charCodeAt(i);
		}
		return bytes.buffer;
	} catch {
		return null;
	}
}

/**
 * Constant-time comparison of two HMAC ArrayBuffers.
 *
 * Delegates to the runtime's native implementation so that the comparison
 * is not subject to JIT optimisation or branch prediction that could leak
 * timing information. Both buffers must be the same byte length (as is
 * always the case when comparing two outputs of the same HMAC algorithm).
 */
export function timingSafeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
	if (a.byteLength !== b.byteLength) {
		return false;
	}
	// crypto.subtle.timingSafeEqual is available in Node.js ≥ 19, Deno, and
	// Cloudflare Workers. Use it when present; fall back to a pure-JS XOR
	// accumulator only as a last resort.
	const subtle = crypto.subtle as typeof crypto.subtle & {
		timingSafeEqual?: (a: ArrayBuffer, b: ArrayBuffer) => boolean;
	};
	if (typeof subtle.timingSafeEqual === "function") {
		return subtle.timingSafeEqual(a, b);
	}
	// Pure-JS fallback: accumulate XOR differences without early exit.
	// This is best-effort; the native path above is strongly preferred.
	const viewA = new Uint8Array(a);
	const viewB = new Uint8Array(b);
	let diff = 0;
	for (let i = 0; i < viewA.length; i++) {
		diff |= viewA[i] ^ viewB[i];
	}
	return diff === 0;
}
