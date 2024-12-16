/** @type {import('next').NextConfig} */
const nextConfig = {
	experimental: {
		turbo: {
			resolveExtensions: [".mdx", ".tsx", ".ts", ".jsx", ".js", ".mjs", ".json"],
		},
	},
	reactStrictMode: true,
	distDir: "dist",
}

module.exports = nextConfig
