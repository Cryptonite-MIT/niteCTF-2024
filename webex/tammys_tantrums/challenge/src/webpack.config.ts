import * as path from "path"

module.exports = {
	target: "node",
	mode: "production",
	entry: "./src/app/page.tsx",
	output: {
		path: path.resolve(__dirname, "dist"),
		filename: "main.js",
	},
	resolve: {
		extensions: [".ts", ".js", ".tsx", ".jsx"],
	},
	stats: {
		errorDetails: true,
	},
	module: {
		rules: [
			{
				use: "ts-loader",
				exclude: /node_modules/,
			},
		],
	},
}
