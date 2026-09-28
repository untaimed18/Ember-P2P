import { get } from 'svelte/store';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { goto } from '$app/navigation';
import { chatPoppedOut, showChatWindow } from '$lib/chatPopout';
import { restoreSearchFromResume, searchResumeSnapshot } from '$lib/stores/search';

/**
 * The frontend's half of coming back from an update restart the way the user
 * left Ember (`auto_update::resume` in the backend).
 *
 * The backend records the window and the eD2K server itself; only this side
 * knows which page was showing and what the search tabs held. It asks for them
 * just before the update shuts Ember down, and hands them back once to the
 * launch that follows.
 */

/** Sent by the backend when it needs the page and search tabs. */
const REQUEST_EVENT = 'ember:resume-ui-request';

/** Pages a resumed session may land on. The backend checks the same list. */
const ROUTES = new Set([
  '/',
  '/transfers',
  '/search',
  '/library',
  '/friends',
  '/channels',
  '/servers',
  '/kad',
  '/kad-network',
  '/ember',
  '/statistics',
  '/security',
  '/settings',
]);

interface UiResume {
  route: string | null;
  searchTabs: string | null;
  reopenChatWindow: boolean;
}

function currentRoute(): string | null {
  const path = window.location.pathname;
  return ROUTES.has(path) ? path : null;
}

/** Answer the backend's request for the session, for as long as this runs. */
export async function initUpdateResume(): Promise<UnlistenFn> {
  return listen<{ id?: unknown }>(REQUEST_EVENT, (event) => {
    const id = event.payload?.id;
    if (typeof id !== 'number' || !Number.isSafeInteger(id)) return;
    void invoke('submit_resume_ui_snapshot', {
      id,
      route: currentRoute(),
      searchTabs: searchResumeSnapshot(),
    }).catch(() => {});
  });
}

/**
 * Put back what an update restart carried over, if this launch is one. Called
 * once the stores are up, so restored tabs land in a store that is listening.
 */
export async function applyUpdateResume(): Promise<void> {
  let resume: UiResume | null;
  try {
    resume = await invoke<UiResume | null>('take_update_resume_ui');
  } catch {
    return;
  }
  if (!resume) return;
  if (resume.searchTabs) restoreSearchFromResume(resume.searchTabs);
  if (resume.route && ROUTES.has(resume.route) && resume.route !== window.location.pathname) {
    await goto(resume.route).catch((e) => console.warn('update resume: navigation failed', e));
  }
  if (resume.reopenChatWindow && get(chatPoppedOut)) void showChatWindow();
}
