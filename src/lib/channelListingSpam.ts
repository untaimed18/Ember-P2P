/**
 * How much a public room listing looks like spam, from what Discover shows of
 * it: its name and the size the directory reports.
 *
 * Anyone can publish a listing, so Discover would otherwise give a flood of
 * advertising rooms the same footing as real ones. This only decides what is
 * folded away by default on this device; a folded listing is one click from
 * being shown, and nothing here touches a room the user is in.
 *
 * Deliberately conservative: one strong sign (a link in the name) or two
 * weaker ones together, never a single quirk of a real room's name.
 */

/** Listings at or above this are folded away in Discover. */
export const LIKELY_SPAM_SCORE = 3;

/** Listings sharing one name before the copies count as a flood. Two rooms
 *  called "Music" is ordinary; a third is somebody publishing in bulk. */
export const DUPLICATE_NAME_FLOOD = 3;

interface Listing {
  channel_id: string;
  name: string;
  /** Members present right now; null when the directory could not tell. */
  member_count: number | null;
}

/** A web address or an invite to somewhere else, which is what an advert in a
 *  room name is for. */
const LINK =
  /(https?:\/\/|www\.|t\.me\/|discord\.gg|\b[a-z0-9-]{2,}\.(?:com|net|org|io|gg|me|xyz|ru|cn|top|click|link|info|biz|shop|site|online|app|ly|cc|tk)\b)/iu;

/** The same character five or more times running: "FREEEEE", "!!!!!". */
const REPEATED = /(.)\1{4,}/u;

/** A name reduced to what a person would read as the same name: case, width,
 *  spacing and punctuation ignored. */
export function listingNameKey(name: string): string {
  return name.normalize('NFKC').toLowerCase().replace(/[\s\p{P}\p{S}]+/gu, '');
}

function shoutsInCapitals(name: string): boolean {
  const letters = name.match(/\p{L}/gu) ?? [];
  // Scripts without case have no capitals to shout in.
  return letters.length >= 8 && name === name.toUpperCase() && name !== name.toLowerCase();
}

function mostlySymbols(name: string): boolean {
  const chars = [...name.replace(/\s+/gu, '')];
  if (chars.length < 4) return false;
  const symbols = chars.filter((c) => !/[\p{L}\p{N}]/u.test(c)).length;
  return symbols * 2 > chars.length;
}

/** Each listing's score, by room id. */
export function listingSpamScores(listings: readonly Listing[]): Map<string, number> {
  const byName = new Map<string, Listing[]>();
  for (const listing of listings) {
    const key = listingNameKey(listing.name);
    if (!key) continue;
    const group = byName.get(key);
    if (group) group.push(listing);
    else byName.set(key, [listing]);
  }
  const scores = new Map<string, number>();
  for (const listing of listings) {
    const name = listing.name.trim();
    let score = 0;
    if (LINK.test(name)) score += 3;
    if (REPEATED.test(name)) score += 1;
    if (shoutsInCapitals(name)) score += 1;
    if (mostlySymbols(name)) score += 1;
    const group = byName.get(listingNameKey(name));
    if (group && group.length >= DUPLICATE_NAME_FLOOD) {
      // The copy people are actually in is the room the others imitate.
      const largest = Math.max(...group.map((each) => each.member_count ?? 0));
      const isLargest = largest > 0 && (listing.member_count ?? 0) === largest;
      if (!isLargest) score += 2;
    }
    // Empty is weak evidence on its own — every new room starts empty — but
    // it tips a listing that already looks wrong.
    if (listing.member_count === 0) score += 1;
    scores.set(listing.channel_id, score);
  }
  return scores;
}
