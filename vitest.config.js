// @ts-nocheck
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";
import { svelte } from "@sveltejs/vite-plugin-svelte";

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
 * Tests of rune modules (`*.svelte.test.ts`) run as their own project: the
 * Svelte plugin compiles their runes, and they are transformed for the client,
 * with Svelte's client runtime, because compiled for the server an effect
 * never runs. Component tests would still need a DOM environment.
 */
const alias = {
  $lib: fileURLToPath(new URL("./src/lib", import.meta.url)),
};

export default defineConfig({
  test: {
    fsModuleCache: true,
    projects: [
      {
        resolve: { alias },
        test: {
          name: "unit",
          include: ["src/**/*.test.ts"],
          exclude: ["src/**/*.svelte.test.ts"],
          environment: "node",
        },
      },
      {
        plugins: [svelte()],
        resolve: { alias, conditions: ["browser"] },
        test: {
          name: "runes",
          include: ["src/**/*.svelte.test.ts"],
          environment: "./scripts/vitest-client-environment.js",
        },
      },
    ],
  },
});
