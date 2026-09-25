/**
 * Client-side shape checks for what Add Friend accepts. The backend
 * (`parse_friend_code`) is authoritative — it also verifies that a code's
 * public key BLAKE3-binds to its Friend ID — so these only decide what is
 * worth sending and which Friend ID the local self/duplicate checks compare.
 */

const FRIEND_ID_RE = /^[0-9a-f]{32}$/i;
const PUBLIC_KEY_RE = /^[0-9a-f]{64}$/i;
const EMBER3_RE = /^ember3:([0-9a-f]{32}):([0-9a-f]{64}):([0-9a-f]{32})$/i;
const EMBER2_RE = /^ember2:([0-9a-f]{32}):([0-9a-f]{64})$/i;

/** The Friend ID a code names, lowercased, or `null` when it names none
 *  directly. A bare public key names one too, but only the backend can
 *  derive it, so it returns `null` here. */
export function friendHashFromCode(value: string): string | null {
  const trimmed = value.trim();
  if (FRIEND_ID_RE.test(trimmed)) return trimmed.toLowerCase();
  const match = EMBER3_RE.exec(trimmed) ?? EMBER2_RE.exec(trimmed);
  return match?.[1]?.toLowerCase() ?? null;
}

/** A bare Ed25519 key — what "Copy" next to the Ember page's public key and a
 *  room's "Copy member ID" put on the clipboard. */
export function isFriendPublicKey(value: string): boolean {
  return PUBLIC_KEY_RE.test(value.trim());
}

/** Only an `ember3:` code carries the intro secret that lets Ember find
 *  someone on a current build before they have added you back, so pasting
 *  one for an existing friend is an update rather than a duplicate. */
export function carriesIntroSecret(value: string): boolean {
  return EMBER3_RE.test(value.trim());
}

/** Anything Add Friend will send to the backend. */
export function isAcceptedFriendInput(value: string): boolean {
  return friendHashFromCode(value) !== null || isFriendPublicKey(value);
}
