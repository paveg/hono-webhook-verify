import { hmac, toBase64, toHex } from "../../src/crypto.js";

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

export async function generateTwilioSignature(
	url: string,
	params: Record<string, string>,
	authToken: string,
): Promise<string> {
	const sortedKeys = Object.keys(params).sort();
	let dataToSign = url;
	for (const key of sortedKeys) {
		dataToSign += key + params[key];
	}
	return toBase64(await hmac("SHA-1", authToken, dataToSign));
}
