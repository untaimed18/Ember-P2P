/*
 * Which program this UI runs in: the desktop app, or `emberd` in a web
 * browser. The browser build is `npm run build:web`, which aliases the Tauri
 * packages to `./web/*` (`vite.config.js`); this flag is fixed at build time,
 * so each build drops the other's branches.
 */

export const isServer: boolean = import.meta.env.VITE_EMBER_WEB === true;
