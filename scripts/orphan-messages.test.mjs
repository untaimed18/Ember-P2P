import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * Parity is not the same as liveness.
 *
 * `locales.test.mjs` guarantees the nine locale files carry exactly the keys
 * English does, which means a string nothing renders any more is not one dead
 * entry but nine — and translators keep re-reviewing text no user can reach.
 * A UI removal that leaves its strings behind is invisible to every other
 * check in the repo, so this one walks `src/` and requires each English key to
 * have a call site.
 *
 * Overridable paths so the scan can be pointed at a fixture copy and watched
 * to reject something, rather than assumed to work.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const messagesDir = process.env.EMBER_MESSAGES_DIR ?? join(root, "messages");
const sourceDir = process.env.EMBER_SOURCE_DIR ?? join(root, "src");

/**
 * The one family of keys with no literal call site: `translateCode` in
 * `src/lib/i18n.ts` indexes the compiled namespace with `error_${code}`, so
 * these are reached by a runtime string and `error-codes.test.mjs` is what
 * keeps them honest instead.
 */
const DYNAMIC_KEY_PREFIX = "error_";

/** `$schema` and anything else that could not be written as `m.<key>` is
 *  file metadata, not a message. */
const MESSAGE_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Keys that are deliberately unreferenced. Empty on purpose: a string with no
 * call site is dead until someone writes down why it isn't, and the staleness
 * check below makes sure an entry cannot outlive its reason.
 */
const ALLOWED_ORPHANS = new Map();

/** Compiled Paraglide output is generated from these same keys; skip it. */
const SKIP_DIRS = new Set(["paraglide", "node_modules"]);
const SOURCE_EXTENSIONS = [".svelte", ".ts", ".js"];

function sourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path));
    else if (SOURCE_EXTENSIONS.some((ext) => entry.endsWith(ext))) out.push(path);
  }
  return out;
}

/**
 * Every `m.<key>` in the app, whether called (`m.foo()`), passed as a function
 * reference (the lookup tables in `src/lib/i18n.ts` do this), or named in a
 * comment. Comments count deliberately: this check should only ever accuse a
 * key of being dead when nothing at all mentions it.
 */
function referencedKeys() {
  const referenced = new Map();
  for (const file of sourceFiles(sourceDir)) {
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/\bm\.([A-Za-z0-9_]+)/g)) {
      if (!referenced.has(match[1])) referenced.set(match[1], file);
    }
  }
  return referenced;
}

const referenced = referencedKeys();
const englishKeys = Object.keys(
  JSON.parse(readFileSync(join(messagesDir, "en.json"), "utf8")),
).filter((key) => MESSAGE_KEY.test(key));
const localeCount = readdirSync(messagesDir).filter((f) =>
  f.endsWith(".json"),
).length;

function orphans() {
  return englishKeys.filter(
    (key) =>
      !key.startsWith(DYNAMIC_KEY_PREFIX) &&
      !referenced.has(key) &&
      !ALLOWED_ORPHANS.has(key),
  );
}

test("every English message key still has a call site in src/", () => {
  assert.deepEqual(
    orphans(),
    [],
    `these keys are rendered nowhere — delete them from all ${localeCount} locales, or add them to ALLOWED_ORPHANS with a reason`,
  );
});

test("the orphan allow-list has no stale entries", () => {
  const gone = [...ALLOWED_ORPHANS.keys()].filter(
    (key) => !englishKeys.includes(key),
  );
  assert.deepEqual(gone, [], "these keys no longer exist; drop them from ALLOWED_ORPHANS");

  const revived = [...ALLOWED_ORPHANS.keys()].filter((key) => referenced.has(key));
  assert.deepEqual(
    revived,
    [],
    "these keys are referenced now; drop them from ALLOWED_ORPHANS so a later removal is caught",
  );
});

test("the reference scan actually walked the app", () => {
  // Guards the scan itself: a wrong path or a broken pattern would make the
  // orphan check above pass by finding nothing, or fail on everything.
  assert.ok(
    referenced.size > 500,
    `expected to find many m.<key> references, found ${referenced.size}`,
  );
  assert.ok(
    englishKeys.length > 500,
    `expected many English keys, found ${englishKeys.length}`,
  );
});
