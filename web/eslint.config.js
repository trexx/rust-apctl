// Lints the React hooks rules (rules of hooks, effect dependencies and the
// React Compiler's checks). TypeScript is parsed by Babel: typescript-eslint
// doesn't support TypeScript 7 yet, and type checking is tsc's job anyway.
import babelParser from "@babel/eslint-parser";
import reactHooks from "eslint-plugin-react-hooks";
import { defineConfig } from "eslint/config";

/** Babel parsing TypeScript, with JSX in .tsx files only (`<T>(x) =>` is a generic in .ts). */
const typescript = (plugins) => ({
  parser: babelParser,
  parserOptions: {
    requireConfigFile: false,
    babelOptions: { babelrc: false, configFile: false, parserOpts: { plugins } },
  },
});

export default defineConfig([
  { ignores: ["dist/"] },
  {
    files: ["src/**/*.ts", "vite.config.ts"],
    languageOptions: typescript(["typescript"]),
  },
  { files: ["src/**/*.tsx"], languageOptions: typescript(["typescript", "jsx"]) },
  {
    files: ["src/**/*.{ts,tsx}"],
    extends: [reactHooks.configs.flat.recommended],
  },
]);
