import { defineConfig } from "tsup";

export default defineConfig({
	entry: {
		index: "src/index.ts",
		"providers/stripe": "src/providers/stripe.ts",
		"providers/github": "src/providers/github.ts",
		"providers/slack": "src/providers/slack.ts",
		"providers/shopify": "src/providers/shopify.ts",
		"providers/twilio": "src/providers/twilio.ts",
		"providers/line": "src/providers/line.ts",
	},
	format: ["esm", "cjs"],
	dts: true,
	clean: true,
	sourcemap: true,
	external: ["hono"],
});
