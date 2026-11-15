// Tauri doesn't have a Node.js server to do proper SSR
// so we use adapter-static with a fallback to index.html to put the site in SPA mode
// See: https://svelte.dev/docs/kit/single-page-apps
// See: https://v2.tauri.app/start/frontend/sveltekit/ for more info
import adapter from "@sveltejs/adapter-static";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";

// The browser build for emberd (`npm run build:web`) goes to its own folder,
// beside the desktop app's.
const out = process.env.EMBER_WEB === "1" ? "build-web" : "build";

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      pages: out,
      assets: out,
      fallback: "index.html",
    }),
  },
};

export default config;
