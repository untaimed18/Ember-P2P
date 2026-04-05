/// <reference types="@sveltejs/kit" />

declare global {
  namespace App {}
}

interface ImportMetaEnv {
  readonly VITE_APP_VERSION: string;
  readonly VITE_APP_DESCRIPTION: string;
  readonly VITE_APP_LICENSE: string;
}

export {};
