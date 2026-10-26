import { goto } from '$app/navigation';

let active = false;

/**
 * Navigate for a deep link the user confirmed. A page guarding unsaved edits
 * cancels this one without asking, so the link waits to be reviewed rather
 * than being run twice: once by its prompt, once by the review.
 */
export async function deepLinkGoto(href: string): Promise<void> {
  active = true;
  try {
    await goto(href);
  } finally {
    active = false;
  }
}

/** Whether the navigation now starting is a deep link's. */
export function navigatingForDeepLink(): boolean {
  return active;
}
