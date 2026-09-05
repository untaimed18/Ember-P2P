/* Apply the stored (or OS) theme before first paint so dark-mode users
   do not flash the light canvas. Keep in lockstep with
   `src/lib/stores/theme.ts` (`STORAGE_KEY` / `getInitialTheme`). */
(function () {
  try {
    var stored = localStorage.getItem('ember-theme');
    var theme =
      stored === 'light' || stored === 'dark'
        ? stored
        : window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light';
    document.documentElement.setAttribute('data-theme', theme);
  } catch (_) {
    /* localStorage can throw in restricted webviews; initTheme() retries. */
  }
})();
