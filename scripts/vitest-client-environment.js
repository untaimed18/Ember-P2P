// Node globals, with modules transformed for the client rather than for SSR:
// compiled for the server, a rune module's effects never run. Used by the
// `runes` project in `vitest.config.js`.
export default {
  name: "node-client",
  viteEnvironment: "client",
  setup() {
    return { teardown() {} };
  },
};
