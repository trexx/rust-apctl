import { defineConfig } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";

export default defineConfig({
  // React Compiler memoises components and hooks (its rules are linted too).
  plugins: [react(), babel({ presets: [reactCompilerPreset()] })],
  build: {
    outDir: "dist",
    sourcemap: false,
    rolldownOptions: {
      output: {
        // React, the router and React Query change only with an upgrade: in a
        // chunk of their own, browsers keep them cached across releases.
        codeSplitting: {
          groups: [
            {
              name: "vendor",
              test: /[\\/]node_modules[\\/](react|react-dom|scheduler|react-router|react-router-dom|@tanstack|cookie|set-cookie-parser)[\\/]/,
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
