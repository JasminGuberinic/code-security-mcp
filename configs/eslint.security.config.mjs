// Flat ESLint config that applies ONLY eslint-plugin-security's rules, to both
// JavaScript and TypeScript. Point KSM_ESLINT_CONFIG at a copy of this file that
// sits next to a node_modules containing `eslint-plugin-security` and
// `typescript-eslint` (so ESLint can resolve them). Setup:
//
//   npm install eslint eslint-plugin-security typescript-eslint
//   # then place this file beside that node_modules
import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";

export default [
  {
    files: ["**/*.{js,mjs,cjs,jsx,ts,tsx,mts,cts}"],
    plugins: { security },
    rules: security.configs.recommended.rules,
  },
  {
    // TypeScript files need the TS parser to produce an analyzable AST.
    files: ["**/*.{ts,tsx,mts,cts}"],
    languageOptions: { parser: tseslint.parser },
  },
];
