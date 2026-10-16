import { defineConfig } from "vite";
import type { Plugin } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";

// The React Compiler leaves a component it can't compile as it is, without a
// word (with Babel 8, even for a default value in destructured props). The
// build lists them and fails, except where a rule is disabled on purpose.
const skipped: string[] = [];
const compiler = reactCompilerPreset({
  logger: {
    logEvent(
      file: string | null,
      e: {
        kind: string;
        fnLoc?: { start?: { line: number } } | null;
        detail?: unknown;
      },
    ) {
      if (e.kind !== "CompileError" && e.kind !== "PipelineError") return;
      const d = e.detail as
        | { reason?: string; options?: { reason?: string } }
        | undefined;
      const why = String(d?.reason ?? d?.options?.reason ?? e.detail);
      if (why.includes("ESLint rules were disabled")) return;
      skipped.push(`${file}:${e.fnLoc?.start?.line ?? "?"}: ${why}`);
    },
  },
});
const compilerCheck: Plugin = {
  name: "react-compiler-check",
  apply: "build",
  buildEnd() {
    if (skipped.length)
      this.error(`React Compiler skipped:\n${skipped.join("\n")}`);
  },
};

export default defineConfig({
  // React Compiler memoises components and hooks (its rules are linted too).
  plugins: [react(), babel({ presets: [compiler] }), compilerCheck],
  build: {
    outDir: "dist",
    sourcemap: false,
    rolldownOptions: {
      output: {
        // React, the router, React Query and uPlot change only with an upgrade:
        // in a chunk of their own, browsers keep them cached across releases.
        codeSplitting: {
          groups: [
            {
              name: "vendor",
              test: /[\\/]node_modules[\\/](react|react-dom|scheduler|react-router|react-router-dom|@tanstack|cookie|set-cookie-parser|uplot)[\\/]/,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8090", ws: true },
    },
  },
});
