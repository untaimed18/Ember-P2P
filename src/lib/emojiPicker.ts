/**
 * The emoji the composer's picker offers, and the ones used most recently.
 *
 * A curated set rather than the full Unicode list: thousands of glyphs need a
 * search to be usable, and a search needs names in nine languages. These are
 * the ones people actually reach for in chat, each a single glyph every
 * platform Ember runs on draws in colour. Default skin tone only, for the same
 * reason.
 */

export type EmojiCategoryId =
  | 'smileys'
  | 'people'
  | 'nature'
  | 'food'
  | 'activities'
  | 'objects'
  | 'symbols';

export interface EmojiCategory {
  id: EmojiCategoryId;
  /** Drawn on the category's tab. */
  icon: string;
  emoji: readonly string[];
}

const split = (list: string) => list.trim().split(/\s+/u);

export const EMOJI_CATEGORIES: readonly EmojiCategory[] = [
  {
    id: 'smileys',
    icon: '😀',
    emoji: split(`
      😀 😃 😄 😁 😆 😅 🤣 😂 🙂 🙃 😉 😊 😇 🥰 😍 🤩 😘 😗 😚 😋 😛 😜 🤪 😝
      🤑 🤗 🤭 🤫 🤔 🤐 🤨 😐 😑 😶 😏 😒 🙄 😬 😌 😔 😪 🤤 😴 😷 🤒 🤕 🤢 🤮
      🥵 🥶 🥴 😵 🤯 🤠 🥳 😎 🤓 🧐 😕 😟 🙁 😮 😯 😲 😳 🥺 😦 😧 😨 😰 😥 😢
      😭 😱 😖 😣 😞 😓 😩 😫 🥱 😤 😡 😠 🤬 😈 👿 💀 💩 🤡 👻 👽 🤖 😺 😸 😹
    `),
  },
  {
    id: 'people',
    icon: '👋',
    emoji: split(`
      👋 🤚 ✋ 🖖 👌 🤌 🤏 ✌️ 🤞 🤟 🤘 🤙 👈 👉 👆 👇 ☝️ 👍 👎 ✊ 👊 🤛 🤜 👏
      🙌 👐 🤲 🤝 🙏 ✍️ 💪 🦾 👀 👁️ 👅 👄 🧠 🫶 👶 🧒 👦 👧 🧑 👨 👩 🧓 👴 👵
      🙋 🙆 🙅 🤷 🤦 🙇 💁 🧏 🙎 🙍 💃 🕺 🧘 🏃 🚶 🧍 👪 👫 👬 👭 💏 💑 🥷 🦸
    `),
  },
  {
    id: 'nature',
    icon: '🐶',
    emoji: split(`
      🐶 🐱 🐭 🐹 🐰 🦊 🐻 🐼 🐨 🐯 🦁 🐮 🐷 🐸 🐵 🙈 🙉 🙊 🐔 🐧 🐦 🐤 🦆 🦅
      🦉 🦇 🐺 🐗 🐴 🦄 🐝 🐛 🦋 🐌 🐞 🐜 🐢 🐍 🦎 🐙 🦑 🦀 🐠 🐟 🐬 🐳 🦈 🐊
      🌵 🎄 🌲 🌳 🌴 🌱 🌿 🍀 🍁 🍂 🌷 🌹 🌺 🌸 🌼 🌻 🌞 🌝 🌚 🌙 ⭐ 🌟 ✨ ⚡
      🔥 🌈 ☀️ 🌤️ ☁️ 🌧️ ⛈️ ❄️ ☃️ 🌊 💧 🌍
    `),
  },
  {
    id: 'food',
    icon: '🍕',
    emoji: split(`
      🍏 🍎 🍐 🍊 🍋 🍌 🍉 🍇 🍓 🫐 🍒 🍑 🥭 🍍 🥥 🥝 🍅 🥑 🍆 🥔 🥕 🌽 🌶️ 🥦
      🍞 🥐 🥖 🧀 🥚 🍳 🥞 🧇 🥓 🍗 🍖 🌭 🍔 🍟 🍕 🥪 🌮 🌯 🥗 🍝 🍜 🍲 🍛 🍣
      🍱 🥟 🍤 🍙 🍚 🍿 🍩 🍪 🎂 🍰 🧁 🍫 🍬 🍭 🍦 ☕ 🍵 🧃 🥤 🍺 🍻 🥂 🍷 🍸
    `),
  },
  {
    id: 'activities',
    icon: '⚽',
    emoji: split(`
      ⚽ 🏀 🏈 ⚾ 🎾 🏐 🏉 🎱 🏓 🏸 🥊 ⛳ 🎣 🎿 🛹 🏆 🥇 🥈 🥉 🏅 🎖️ 🎮 🕹️ 🎲
      ♟️ 🎯 🎳 🎨 🎬 🎤 🎧 🎼 🎹 🥁 🎷 🎺 🎸 🎻 🎉 🎊 🎈 🎁 🎀 🎃 🎆 🎇 🧨 🎟️
      🚗 🚕 🚌 🏎️ 🚓 🚑 🚒 🚲 🛵 🏍️ 🚂 🚀 🛸 ✈️ 🚁 ⛵ 🚢 🗺️ 🏠 🏡 🏰 🗽 🗼 🏖️
    `),
  },
  {
    id: 'objects',
    icon: '💡',
    emoji: split(`
      💡 🔦 🕯️ 📱 💻 🖥️ ⌨️ 🖱️ 💾 💿 📀 📷 📸 🎥 📺 📻 ⏰ ⌛ ⏳ 📡 🔋 🔌 💰 💵
      💳 💎 🔧 🔨 🛠️ ⚙️ 🔩 🧲 🔑 🗝️ 🔒 🔓 🛡️ 🧪 🔬 🔭 💊 🩹 🧸 🧮 ✉️ 📦 📫 📝
      📁 📂 📅 📌 📎 ✂️ 🖊️ ✏️ 📚 📖 🔖 🏷️ 🔔 🔕 📣 📢 💬 💭 🗯️ ☎️ 🧭 ⏱️ 🧩 🪄
    `),
  },
  {
    id: 'symbols',
    icon: '❤️',
    emoji: split(`
      ❤️ 🧡 💛 💚 💙 💜 🖤 🤍 🤎 💔 ❣️ 💕 💞 💓 💗 💖 💘 💝 💟 ♥️ 💯 💢 💥 💫
      💦 💨 🕳️ 💤 ✅ ☑️ ✔️ ❌ ❎ ➕ ➖ ✖️ ➗ ❓ ❔ ❗ ❕ ‼️ ⁉️ ⚠️ 🚫 ⛔ 🔞 ♻️
      🔴 🟠 🟡 🟢 🔵 🟣 ⚫ ⚪ 🟥 🟧 🟨 🟩 🟦 🟪 ⬛ ⬜ 🔶 🔷 🔺 🔻 ➡️ ⬅️ ⬆️ ⬇️
      🆗 🆕 🆒 🆓 🔝 🔜 ♾️ ©️ ®️ ™️ #️⃣ 🎵 🎶 🏳️ 🏴 🏁 🚩 🏳️‍🌈
    `),
  },
];

const RECENT_KEY = 'ember.emoji.recent.v1';
/** One row and a half of the grid: the handful a person keeps reaching for. */
export const RECENT_EMOJI_LIMIT = 16;

type StorageLike = Pick<Storage, 'getItem' | 'setItem'>;

function browserStorage(): StorageLike | null {
  return typeof localStorage === 'undefined' ? null : localStorage;
}

/** Every glyph the picker draws, so a stored list cannot inject anything else. */
const KNOWN = new Set(EMOJI_CATEGORIES.flatMap((category) => category.emoji));

export function loadRecentEmoji(storage: StorageLike | null = browserStorage()): string[] {
  if (!storage) return [];
  try {
    const parsed: unknown = JSON.parse(storage.getItem(RECENT_KEY) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return [...new Set(parsed.filter((e): e is string => typeof e === 'string' && KNOWN.has(e)))].slice(
      0,
      RECENT_EMOJI_LIMIT,
    );
  } catch {
    return [];
  }
}

/** Put `emoji` first in the recent list and store it. Returns the new list. */
export function noteRecentEmoji(
  emoji: string,
  storage: StorageLike | null = browserStorage(),
): string[] {
  const next = [emoji, ...loadRecentEmoji(storage).filter((e) => e !== emoji)].slice(0, RECENT_EMOJI_LIMIT);
  if (storage && KNOWN.has(emoji)) {
    try {
      storage.setItem(RECENT_KEY, JSON.stringify(next));
    } catch {
      // Quota exceeded / private mode. The pick still goes in.
    }
  }
  return next;
}

/**
 * Write `emoji` over the selection in `text`, or at the caret when nothing is
 * selected. Null when the result would pass `maxLength` (UTF-16 units, the
 * same measure the textarea's own limit uses).
 */
export function insertAtSelection(
  text: string,
  start: number,
  end: number,
  emoji: string,
  maxLength: number,
): { text: string; caret: number } | null {
  const from = Math.max(0, Math.min(start, text.length));
  const to = Math.max(from, Math.min(end, text.length));
  const next = text.slice(0, from) + emoji + text.slice(to);
  if (next.length > maxLength) return null;
  return { text: next, caret: from + emoji.length };
}
