// @ts-nocheck
import { createRequire } from "module";
import { defineConfig } from "vite";
import { sveltekit } from "@sveltejs/kit/vite";

const require = createRequire(import.meta.url);
const pkg = require("./package.json");

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [sveltekit()],
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
