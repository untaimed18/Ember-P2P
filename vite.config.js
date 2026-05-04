// @ts-nocheck
import { createRequire } from "module";
import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
import { paraglideVitePlugin } from "@inlang/paraglide-js";

const require = createRequire(import.meta.url);
const pkg = require("./package.json");

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [
    // Paraglide compiles `messages/*.json` into a tree-shakeable
    // TypeScript module under `src/lib/paraglide/`. We don't use a
    // URL prefix (Tauri ships as a SPA via adapter-static), so the
    // resolution strategy is purely client-side: read the user's
    // saved choice from localStorage, otherwise sniff
    // `navigator.language`, otherwise fall back to the base locale
    // (English). Cookie/URL strategies are intentionally omitted —
    // they don't help in a Tauri shell and would add noise to the
    // generated runtime.
    paraglideVitePlugin({
      project: "./project.inlang",
      outdir: "./src/lib/paraglide",
      strategy: ["localStorage", "preferredLanguage", "baseLocale"],
    }),
    sveltekit(),
  ],
  define: {
    "import.meta.env.VITE_APP_VERSION": JSON.stringify(pkg.version ?? ""),
    "import.meta.env.VITE_APP_DESCRIPTION": JSON.stringify(pkg.description ?? ""),
    "import.meta.env.VITE_APP_LICENSE": JSON.stringify(pkg.license ?? "MIT"),
  },

  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: false,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
}));
