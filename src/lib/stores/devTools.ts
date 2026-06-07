import { writable } from 'svelte/store';

/**
 * Whether the Ember developer console (`/dev/ember`) is surfaced in the UI
 * — the sidebar footer link and the "Advanced" button on the Ember Network
 * page. Backed by `AppSettings.ember_dev_tools_enabled`.
 *
 * Seeded once from settings by the root layout, and updated by the Settings
 * page the moment the toggle is saved, so the sidebar link appears/disappears
 * live without a reload. The `/dev/ember` route still works by direct URL
 * regardless; this only governs the links to it.
 */
export const emberDevToolsEnabled = writable(false);
