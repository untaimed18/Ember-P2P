// @ts-nocheck
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

/**
 * Unit tests for the plain TypeScript under `src/lib`.
 *
 * Deliberately *not* the app's `vite.config.js`. That one loads `sveltekit()`
 * and the Paraglide plugin, which between them want a generated `.svelte-kit`
 * directory and re-run the message compiler on every start — neither of which
 * a test run of a few pure functions should depend on. Only the `$lib` alias
 * is needed here, so only the `$lib` alias is configured.
 *
 * `src/lib/paraglide` is generated and gitignored, and `utils.ts` reaches it
 * transitively through `$lib/i18n`, so `npm run test:unit` compiles the
 * messages before running.
 *
 * Component tests would need a DOM environment and `@sveltejs/vite-plugin-svelte`
 * here; the scope today is the pure logic that had no coverage at all.
 */
export default defineConfig({
  resolve: {
    alias: {
      $lib: fileURLToPath(new URL("./src/lib", import.meta.url)),
    },
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
