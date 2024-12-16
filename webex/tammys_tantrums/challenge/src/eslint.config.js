const eslint = require("@eslint/js")
const tseslint = require("@typescript-eslint/eslint-plugin")
const tseslintParser = require("@typescript-eslint/parser")
const nextPlugin = require("@next/eslint-plugin-next")
const prettierConfig = require("eslint-config-prettier")
const prettierPlugin = require("eslint-plugin-prettier")
const simpleImportSort = require("eslint-plugin-simple-import-sort")
const importPlugin = require("eslint-plugin-import")

module.exports = [
	{
		ignores: [
			"dist/**",
			"node_modules/**",
			"types/**",
			".gitignore",
			"LICENSE",
			"package-lock.json",
			"README.md",
			"webpack.config.ts",
			"postcss.config.js",
			"tailwind.config.js",
			"next.config.js",
			"next-env.d.ts",
		],
	},
	{
		files: ["**/*.{js,cjs,mjs}"],
		languageOptions: {
			ecmaVersion: "latest",
			sourceType: "module",
			globals: {
				browser: true,
				commonjs: true,
				es2021: true,
				node: true,
			},
		},
		plugins: {
			prettier: prettierPlugin,
			"simple-import-sort": simpleImportSort,
			import: importPlugin,
		},
		rules: {
			"prettier/prettier": "error",
			"simple-import-sort/imports": "error",
			"simple-import-sort/exports": "error",
			"import/first": "error",
			"import/newline-after-import": "error",
			"import/no-duplicates": "error",
			"no-var": "error",
			"prefer-const": "error",
		},
	},
	{
		files: ["**/*.{ts,tsx}"],
		languageOptions: {
			parser: tseslintParser,
			parserOptions: {
				ecmaVersion: "latest",
				sourceType: "module",
				project: "./tsconfig.json",
			},
			globals: {
				browser: true,
				commonjs: true,
				es2021: true,
				node: true,
			},
		},
		plugins: {
			"@typescript-eslint": tseslint,
			prettier: prettierPlugin,
			"simple-import-sort": simpleImportSort,
			import: importPlugin,
			"@next/next": nextPlugin,
		},
		rules: {
			"prettier/prettier": "error",
			"simple-import-sort/imports": "error",
			"simple-import-sort/exports": "error",
			"import/first": "error",
			"import/newline-after-import": "error",
			"import/no-duplicates": "error",
			"@typescript-eslint/array-type": "error",
			"@typescript-eslint/consistent-type-assertions": "error",
			"@typescript-eslint/consistent-type-definitions": "error",
			"@typescript-eslint/explicit-function-return-type": "error",
			"@typescript-eslint/explicit-module-boundary-types": "error",
			"@typescript-eslint/no-empty-function": "error",
			"@typescript-eslint/no-empty-interface": "error",
			"@typescript-eslint/no-explicit-any": "error",
			"@typescript-eslint/no-inferrable-types": "error",
			"@typescript-eslint/no-misused-new": "error",
			"@typescript-eslint/no-namespace": "error",
			"@typescript-eslint/no-non-null-assertion": "error",
			"@typescript-eslint/no-this-alias": "error",
			"@typescript-eslint/no-unused-vars": "error",
			// "@typescript-eslint/no-var-requires": "error",
			"@typescript-eslint/prefer-namespace-keyword": "error",
			"@typescript-eslint/triple-slash-reference": "error",
			"no-var": "error",
			"prefer-const": "error",
		},
		settings: {
			next: {
				rootDir: ["./"],
			},
		},
	},
	prettierConfig,
]
