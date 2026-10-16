import { defineConfig } from "vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";
import babel from "@rolldown/plugin-babel";

export default defineConfig({
  // React Compiler memoises components and hooks (its rules are linted too).
  plugins: [react(), babel({ presets: [reactCompilerPreset()] })],
  build: { outDir: "dist", sourcemap: false },
  server: {
    proxy: {
      "/api": { target: "http://127.0.0.1:8090", ws: true },
    },
  },
});
