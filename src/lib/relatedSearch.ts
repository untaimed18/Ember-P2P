import { goto } from '$app/navigation';
import { writable } from 'svelte/store';
import {
  planRelatedSearch,
  type RelatedPlan,
  type RelatedSeed,
  type RelationKind,
  type SearchMethod,
} from '$lib/api/search';
import { addToast } from '$lib/stores/toast';
import { translateError } from '$lib/i18n';
import * as m from '$lib/paraglide/messages';

/**
 * "Find related files" — shared entry point for every page that offers it.
 *
 * The search itself has to run on the search page: it owns the tab strip, the
 * timeout watchdogs and the streaming merge, and duplicating any of that for a
 * second caller would be a bug farm. So a related search is started in two
 * steps — the backend plans it here, the plan is parked in
 * [`pendingRelatedSearch`], and the search page picks it up (navigating there
 * first if the user was on Transfers or Library). Planning happens before
 * navigation on purpose: if the file yields nothing searchable we want to say so
 * where the user clicked, rather than dump them on an empty search page.
 */
export type PendingRelatedSearch = {
  plan: RelatedPlan;
};

/**
 * The method a related search runs on, whatever the method dropdown says.
 *
 * eMule's "Search Related Files" is a server-side feature, and this keeps ours
 * one too. The co-share request is a question only the connected eD2k server
 * can answer — it alone has a view of who shares what alongside what, which is
 * the whole point of the feature — and the keyword half of the plan goes to
 * that same server rather than fanning out to Kad, the Ember DHT or the rest
 * of the server list. So the one connection is asked both halves and nothing
 * else is asked anything: a related search is not a general search that
 * happens to have been derived from a file.
 */
export const RELATED_SEARCH_METHOD: SearchMethod = 'server';

/** Set by [`startRelatedSearch`], consumed once by the search page. */
export const pendingRelatedSearch = writable<PendingRelatedSearch | null>(null);

/** Localized name for one relatedness signal, for explaining a related tab. */
export function relationKindLabel(kind: RelationKind): string {
  switch (kind) {
    case 'co_share':
      return m.search_related_kind_co_share();
    case 'series':
      return m.search_related_kind_series();
    case 'album':
      return m.search_related_kind_album();
    case 'volume':
      return m.search_related_kind_volume();
    case 'title':
      return m.search_related_kind_title();
  }
}

/**
 * Plan a related search for `seeds` and hand it to the search page.
 *
 * Returns `true` when a search was started. Failures are reported as a toast
 * (the caller is a context-menu click, which has nowhere else to put an error)
 * and return `false`.
 */
export async function startRelatedSearch(seeds: RelatedSeed[]): Promise<boolean> {
  const usable = seeds.filter((s) => (s.hash ?? '').trim() !== '' || (s.name ?? '').trim() !== '');
  if (usable.length === 0) {
    addToast('warning', m.search_related_nothing_to_search());
    return false;
  }

  let plan: RelatedPlan;
  try {
    plan = await planRelatedSearch(usable);
  } catch (e: unknown) {
    console.error('Failed to plan related search:', e);
    addToast('warning', translateError(e, m.search_related_nothing_to_search()));
    return false;
  }

  pendingRelatedSearch.set({ plan });
  try {
    await goto('/search');
  } catch (e) {
    // Nobody is going to consume the plan if we never get to the search page,
    // and a plan left armed here would fire the next time that page happens to
    // mount — a search the user asked for minutes ago on a file they have moved
    // on from.
    console.error('Navigation to search failed:', e);
    pendingRelatedSearch.set(null);
    addToast('warning', m.search_related_nothing_to_search());
    return false;
  }
  return true;
}
