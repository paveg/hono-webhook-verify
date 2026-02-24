import { hmac, toBase64, toHex } from "../../src/crypto.js";

/** Generate an Ed25519 key pair for Discord testing */
export async function generateEd25519KeyPair(): Promise<{
	publicKey: string;
	privateKey: CryptoKey;
}> {
	const keyPair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
	const rawPublicKey = await crypto.subtle.exportKey("raw", keyPair.publicKey);
	const publicKeyHex = Array.from(new Uint8Array(rawPublicKey))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return { publicKey: publicKeyHex, privateKey: keyPair.privateKey };
}

/** Generate a Discord interaction signature */
export async function generateDiscordSignature(
	body: string,
	timestamp: string,
	privateKey: CryptoKey,
): Promise<string> {
	const encoder = new TextEncoder();
	const message = encoder.encode(timestamp + body);
	const signature = await crypto.subtle.sign("Ed25519", privateKey, message);
	return Array.from(new Uint8Array(signature))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function generateStripeSignature(
	body: string,
	secret: string,
	timestamp?: number,
): Promise<{ header: string; timestamp: number }> {
	const ts = timestamp ?? Math.floor(Date.now() / 1000);
	const payload = `${ts}.${body}`;
	const sig = toHex(await hmac("SHA-256", secret, payload));
	return { header: `t=${ts},v1=${sig}`, timestamp: ts };
}

export async function generateGitHubSignature(body: string, secret: string): Promise<string> {
	const sig = toHex(await hmac("SHA-256", secret, body));
	return `sha256=${sig}`;
}

export async function generateSlackSignature(
	body: string,
	secret: string,
	timestamp?: number,
): Promise<{ signature: string; timestamp: number }> {
	const ts = timestamp ?? Math.floor(Date.now() / 1000);
	const sigBasestring = `v0:${ts}:${body}`;
	const sig = toHex(await hmac("SHA-256", secret, sigBasestring));
	return { signature: `v0=${sig}`, timestamp: ts };
}

export async function generateShopifySignature(body: string, secret: string): Promise<string> {
	return toBase64(await hmac("SHA-256", secret, body));
}

export async function generateLineSignature(body: string, channelSecret: string): Promise<string> {
	return toBase64(await hmac("SHA-256", channelSecret, body));
}

export async function generateStandardWebhooksSignature(
	body: string,
	secretBase64: string,
	msgId: string,
	timestamp?: number,
): Promise<{ signature: string; timestamp: number }> {
	const ts = timestamp ?? Math.floor(Date.now() / 1000);
	const signedContent = `${msgId}.${ts}.${body}`;
	// Decode base64 secret to raw bytes
	const binary = atob(secretBase64);
	const keyBytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		keyBytes[i] = binary.charCodeAt(i);
	}
	const sig = toBase64(await hmac("SHA-256", keyBytes.buffer as ArrayBuffer, signedContent));
	return { signature: `v1,${sig}`, timestamp: ts };
}

export async function generateTwilioSignature(
	url: string,
	params: Record<string, string>,
	authToken: string,
	rawBody?: string,
): Promise<string> {
	let dataToSign = url;
	if (rawBody !== undefined) {
		// Replicate the provider's signing logic for raw body
		const p = new URLSearchParams(rawBody);
		const entries: [string, string][] = [];
		p.forEach((value, key) => {
			entries.push([key, value]);
		});
		entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		for (const [key, value] of entries) {
			dataToSign += key + value;
		}
	} else {
		const sortedKeys = Object.keys(params).sort();
		for (const key of sortedKeys) {
			dataToSign += key + params[key];
		}
	}
	return toBase64(await hmac("SHA-1", authToken, dataToSign));
}
