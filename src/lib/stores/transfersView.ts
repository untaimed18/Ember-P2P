import { writable } from 'svelte/store';

const COMPLETED_FIRST_KEY = 'transfers-completed-first';

function loadCompletedFirst(): boolean {
  try {
    return localStorage.getItem(COMPLETED_FIRST_KEY) === '1';
  } catch {
    return false;
  }
}

/** The Completed / Failed section above the downloads still running, for
 *  whoever reads the list for what has just finished. Off unless chosen; set
 *  from the Transfers page's More menu or from Settings. */
export const completedFirst = writable(loadCompletedFirst());

completedFirst.subscribe((value) => {
  try {
    localStorage.setItem(COMPLETED_FIRST_KEY, value ? '1' : '0');
  } catch {
    /* storage disabled: the choice lasts for this session */
  }
});
