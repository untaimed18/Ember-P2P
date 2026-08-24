import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * Three user-facing surfaces used to be driven by matching English sentences
 * the backend produced: a transfer's failure text, its health text, and the
 * spam tooltip. They are driven by stable codes now, which fixes the fragility
 * but moves the risk: a code the frontend has no row for renders the backend's
 * English, silently, in all eight non-English locales. That is exactly how the
 * spam tooltip stayed untranslated for as long as it did — `error-codes.test.mjs`
 * only ever scanned `coded()` construction sites, so this family was invisible
 * to it.
 *
 * This is the ratchet over the new families. Each `*_codes!` table in Rust is
 * the declaration, `src/lib/i18n.ts` holds the code -> message mapping, and the
 * checks below require a bijection between them, a real key behind every
 * message, and the same `{placeholders}` on both sides. Adding a Rust variant
 * without translating it fails `npm test`.
 *
 * Overridable paths so the scan can be pointed at a fixture copy and shown to
 * reject something, rather than assumed to work.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const messagesDir = process.env.EMBER_MESSAGES_DIR ?? join(root, "messages");
const rustRoot = process.env.EMBER_RUST_DIR ?? join(root, "src-tauri", "src");
const i18nPath = process.env.EMBER_I18N_FILE ?? join(root, "src", "lib", "i18n.ts");

const inlang = JSON.parse(
  readFileSync(join(root, "project.inlang", "settings.json"), "utf8"),
);
const locales = inlang.locales;
const messages = new Map(
  locales.map((locale) => [
    locale,
    JSON.parse(readFileSync(join(messagesDir, `${locale}.json`), "utf8")),
  ]),
);
const i18n = readFileSync(i18nPath, "utf8");

/**
 * The families, each pairing one Rust macro table with one frontend map.
 *
 * `composed` names codes the frontend deliberately handles outside its map
 * because their sentence is assembled from more than one message. Listing them
 * here rather than exempting them silently keeps the bijection total.
 */
const FAMILIES = [
  {
    name: "transfer failure",
    rustFile: join(rustRoot, "network", "ed2k", "transfer.rs"),
    macro: "transfer_failure_codes",
    map: "TRANSFER_FAILURE_CODES",
    composed: [],
  },
  {
    name: "transfer health",
    rustFile: join(rustRoot, "sharing", "manager.rs"),
    macro: "transfer_health_codes",
    map: "TRANSFER_HEALTH_CODES",
    // `retrying_after` names the failure being retried, so the UI composes it
    // from `transfers_health_reason_retrying_after` plus the failure's own
    // message instead of holding a single message for it.
    composed: ["retrying_after"],
  },
  {
    name: "spam reason",
    rustFile: join(rustRoot, "search", "spam.rs"),
    macro: "spam_reason_codes",
    map: "SPAM_REASON_CODES",
    composed: [],
  },
];

/** `{name}` placeholders, sorted, as `locales.test.mjs` reads them. */
function placeholders(value) {
  return [...value.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();
}

/** The `Variant => "code", "English {template}";` rows of one macro table. */
function rustCodes(family) {
  const source = readFileSync(family.rustFile, "utf8");
  const open = source.indexOf(`${family.macro}! {`);
  assert.notEqual(
    open,
    -1,
    `${family.rustFile} no longer invokes ${family.macro}!`,
  );
  const close = source.indexOf("\n}\n", open);
  assert.notEqual(close, -1, `unterminated ${family.macro}! table`);
  const table = source.slice(open, close);
  const rows = new Map();
  for (const match of table.matchAll(
    /(\w+)\s*=>\s*"([a-z0-9_]+)",\s*\n?\s*"((?:[^"\\]|\\.)*)"\s*;/g,
  )) {
    rows.set(match[2], { variant: match[1], message: match[3] });
  }
  return rows;
}

/**
 * The `['code', ...m.some_key...]` rows of one frontend map, with the Paraglide
 * keys each row renders. Reading the source rather than importing it is the
 * same compromise `merge-contract.test.mjs` makes: this is Svelte-app
 * TypeScript and there is no bundler on this path.
 *
 * Bracket-matched rather than pattern-matched, because these rows are arrow
 * functions whose bodies contain brackets, commas and quotes of their own — a
 * regex for the row separator reads straight past the short ones into the long
 * ones and silently loses codes.
 */
function frontendCodes(family) {
  const anchor = i18n.indexOf(`const ${family.map} = new Map`);
  assert.notEqual(anchor, -1, `src/lib/i18n.ts no longer defines ${family.map}`);
  const arrayStart = i18n.indexOf("([", anchor);
  assert.notEqual(arrayStart, -1, `${family.map} is not initialised from an array`);

  const rows = [];
  let depth = 0;
  let rowStart = -1;
  let quote = null;
  let closed = false;
  for (let i = arrayStart + 1; i < i18n.length; i++) {
    const char = i18n[i];
    if (quote) {
      if (char === "\\") i++;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === "'" || char === '"' || char === "`") {
      quote = char;
    } else if (char === "[" || char === "(" || char === "{") {
      depth += 1;
      if (depth === 2 && char === "[") rowStart = i + 1;
    } else if (char === "]" || char === ")" || char === "}") {
      if (depth === 2 && char === "]" && rowStart !== -1) {
        rows.push(i18n.slice(rowStart, i));
        rowStart = -1;
      }
      depth -= 1;
      if (depth === 0) {
        closed = true;
        break;
      }
    }
  }
  assert.ok(closed, `unterminated ${family.map}`);

  const keys = new Map();
  for (const row of rows) {
    const code = /^\s*'([a-z0-9_]+)'\s*,/.exec(row);
    assert.ok(code, `a ${family.map} row does not start with a quoted code: ${row.slice(0, 60)}`);
    keys.set(
      code[1],
      [...row.matchAll(/\bm\.([A-Za-z0-9_]+)/g)].map((match) => match[1]),
    );
  }
  return keys;
}

for (const family of FAMILIES) {
  const rust = rustCodes(family);
  const frontend = frontendCodes(family);

  test(`every ${family.name} code Rust declares is translated`, () => {
    const untranslated = [...rust.keys()].filter(
      (code) => !frontend.has(code) && !family.composed.includes(code),
    );
    assert.deepEqual(
      untranslated.map((code) => `${code} (${rust.get(code).variant})`),
      [],
      `add a row to ${family.map} in src/lib/i18n.ts and a message to all ${locales.length} locales`,
    );
  });

  test(`the ${family.name} map has no rows Rust no longer emits`, () => {
    // A stale row is a translation nothing can reach, and it hides the fact
    // that the code it was written for is gone.
    const orphans = [...frontend.keys()].filter((code) => !rust.has(code));
    assert.deepEqual(
      orphans,
      [],
      `these are not in ${family.macro}!; drop them from ${family.map}`,
    );
    const stale = family.composed.filter((code) => !rust.has(code));
    assert.deepEqual(stale, [], `these composed codes are gone from ${family.macro}!`);
  });

  test(`every ${family.name} message exists in all ${locales.length} locales`, () => {
    const missing = [];
    for (const [code, keys] of frontend) {
      assert.ok(keys.length > 0, `${family.map}['${code}'] renders no m.<key>`);
      for (const key of keys) {
        for (const locale of locales) {
          if (typeof messages.get(locale)[key] !== "string") {
            missing.push(`${locale}.json: ${key} (${code})`);
          }
        }
      }
    }
    assert.deepEqual(missing, [], "these messages are missing");
  });

  test(`every ${family.name} message takes the parameters Rust supplies`, () => {
    // Rust's English template declares the numbers it interpolates, so the
    // translated message has to ask for the same ones by the same names.
    // Paraglide renders an unknown placeholder as `undefined`, and drops a
    // number the sentence never mentions — neither is visible to type checking.
    const mismatched = [];
    for (const [code, keys] of frontend) {
      const want = placeholders(rust.get(code).message).join(",");
      for (const key of keys) {
        const got = placeholders(messages.get(inlang.baseLocale)[key] ?? "").join(",");
        if (want !== got) {
          mismatched.push(`${code}: rust [${want}] vs ${key} [${got}]`);
        }
      }
    }
    assert.deepEqual(mismatched, [], "placeholder drift between Rust and en.json");
  });

  test(`the ${family.name} scan actually found the two tables`, () => {
    // Guards the scan itself: a broken pattern would make every check above
    // pass by comparing two empty sets.
    assert.ok(rust.size >= 8, `found only ${rust.size} codes in ${family.macro}!`);
    assert.equal(
      frontend.size + family.composed.length,
      rust.size,
      `${family.map} and ${family.macro}! disagree on how many codes exist`,
    );
  });
}

test("the composed retry notice keeps the slot the UI fills", () => {
  // `retrying_after` is the one code with no message of its own: the frontend
  // puts a translated failure into `transfers_health_reason_retrying_after`.
  // Without the placeholder the row would name no failure at all.
  for (const locale of locales) {
    assert.deepEqual(
      placeholders(messages.get(locale).transfers_health_reason_retrying_after ?? ""),
      ["reason"],
      `${locale}.json: transfers_health_reason_retrying_after lost its {reason} slot`,
    );
  }
  assert.ok(
    i18n.includes("transfers_health_reason_retrying_after({ reason:"),
    "src/lib/i18n.ts no longer composes the retry notice from a translated failure",
  );
});
