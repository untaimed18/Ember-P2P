<script lang="ts">
  import type { FeedLinkInfo } from '$lib/api/feedLinks';
  import { openFeedLink } from '$lib/chatPopout';
  import { describeFeed, feedDescriptionsVersion } from '$lib/feedLinks';
  import { plural } from '$lib/plural';
  import * as m from '$lib/paraglide/messages';

  /** A feed link in a message, drawn as a card that follows or opens it.
   *  What it says comes from this device alone: an unknown feed shows as one,
   *  and the Feeds page learns the rest once it is followed. */
  let { link }: { link: string } = $props();

  let info = $state<FeedLinkInfo | null>(null);

  $effect(() => {
    const asked = link;
    void $feedDescriptionsVersion;
    describeFeed(asked)
      .then((found) => {
        if (link === asked) info = found;
      })
      .catch(() => {});
  });

  let title = $derived(info?.title || m.chat_feed_card_untitled());
  let meta = $derived.by(() => {
    if (!info) return m.chat_feed_card_kind();
    if (info.own) return m.chat_feed_card_own();
    const files =
      info.title && info.item_count > 0
        ? plural(info.item_count, {
            one: () => m.chat_feed_card_files_one({ count: info?.item_count ?? 0 }),
            oneShowsCount: true,
            few: () => m.chat_feed_card_files_few({ count: info?.item_count ?? 0 }),
            other: () => m.chat_feed_card_files_other({ count: info?.item_count ?? 0 }),
          })
        : '';
    if (info.following) return files ? m.chat_feed_card_following_files({ files }) : m.chat_feed_card_following();
    return files || m.chat_feed_card_kind();
  });
  let opens = $derived(!!info && (info.own || info.following));
</script>

<div class="feed-card" role="group" aria-label={m.chat_feed_card_label({ title })}>
  <svg class="feed-card-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path d="M4 9a7 7 0 0 1 7 7" />
    <path d="M4 4a12 12 0 0 1 12 12" />
    <circle cx="5" cy="15" r="1.2" fill="currentColor" stroke="none" />
  </svg>
  <div class="feed-card-text">
    <span class="feed-card-title" dir="auto">{title}</span>
    <span class="feed-card-meta">{meta}</span>
  </div>
  <button
    type="button"
    class="feed-card-action"
    class:primary={!opens}
    onclick={() => openFeedLink(info?.link ?? link)}
  >{opens ? m.feeds_discover_open() : m.feeds_follow()}</button>
</div>

<style>
  .feed-card {
    width: min(320px, 100%);
    margin-top: 6px;
    padding: 9px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    background: var(--bg-secondary);
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
    box-shadow: var(--shadow-sm);
  }

  .feed-card-icon {
    flex-shrink: 0;
    width: 22px;
    height: 22px;
    color: var(--accent);
  }

  .feed-card-text {
    display: flex;
    flex-direction: column;
    gap: 1px;
    min-width: 0;
    flex: 1;
  }

  .feed-card-title {
    font-size: var(--font-size-md);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .feed-card-meta {
    font-size: var(--font-size-sm);
    color: var(--text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .feed-card-action {
    flex-shrink: 0;
    font: inherit;
    font-size: var(--font-size-sm);
    font-weight: 600;
    padding: 5px 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--bg-secondary);
    color: var(--text-primary);
    cursor: pointer;
  }

  .feed-card-action:hover {
    background: var(--bg-hover);
  }

  .feed-card-action.primary {
    border-color: var(--accent);
    background: var(--accent);
    color: var(--on-accent);
  }

  .feed-card-action.primary:hover {
    background: var(--accent-hover);
    border-color: var(--accent-hover);
  }
</style>
