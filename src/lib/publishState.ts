import * as m from '$lib/paraglide/messages';

/** Why a shared, hashed file is on no network yet. */
export type UnpublishedReason = 'friends_only' | 'offline' | 'publishing';

/** What is connected that a file can be published to. */
export interface PublishNetworks {
  kad: boolean;
  server: boolean;
  ember: boolean;
}

export function unpublishedReason(friendsOnly: boolean, networks: PublishNetworks): UnpublishedReason {
  if (friendsOnly) return 'friends_only';
  if (!networks.kad && !networks.server && !networks.ember) return 'offline';
  return 'publishing';
}

/** The reason, in words, for a file's Published cell and details. */
export function unpublishedText(friendsOnly: boolean, networks: PublishNetworks): string {
  switch (unpublishedReason(friendsOnly, networks)) {
    case 'friends_only':
      return m.library_unpublished_friends_only();
    case 'offline':
      return m.library_unpublished_offline();
    default:
      return m.library_unpublished_publishing();
  }
}
