// @ts-nocheck
import { createRequire } from "module";
import { fileURLToPath } from "url";
import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";
import { paraglideVitePlugin } from "@inlang/paraglide-js";

const require = createRequire(import.meta.url);
const pkg = require("./package.json");

// The browser build `emberd` serves (`npm run build:web`): the Tauri packages
// are replaced by their stand-ins in `src/lib/runtime/web`, which talk to
// `emberd` over HTTP and a WebSocket instead of to a webview's IPC.
const web = process.env.EMBER_WEB === "1";
const webShim = (name) => fileURLToPath(new URL(`./src/lib/runtime/web/${name}.ts`, import.meta.url));
const webAliases = web
  ? [
      { find: /^@tauri-apps\/api\/core$/, replacement: webShim("core") },
      { find: /^@tauri-apps\/api\/event$/, replacement: webShim("event") },
      { find: /^@tauri-apps\/api\/window$/, replacement: webShim("window") },
      { find: /^@tauri-apps\/api\/webview$/, replacement: webShim("webview") },
      { find: /^@tauri-apps\/plugin-process$/, replacement: webShim("process") },
    ]
  : [];

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
  resolve: {
    alias: webAliases,
  },
  define: {
    "import.meta.env.VITE_APP_VERSION": JSON.stringify(pkg.version ?? ""),
    "import.meta.env.VITE_APP_DESCRIPTION": JSON.stringify(pkg.description ?? ""),
    "import.meta.env.VITE_APP_LICENSE": JSON.stringify(pkg.license ?? "MIT"),
    "import.meta.env.VITE_EMBER_WEB": JSON.stringify(web),
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
