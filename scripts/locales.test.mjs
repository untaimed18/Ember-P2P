import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// Overridable so these checks can be pointed at a fixture copy and shown to
// fail on a file that deserves it. A guard nobody has watched reject anything
// is only assumed to work.
const messagesDir = process.env.EMBER_MESSAGES_DIR ?? join(root, "messages");
const baseLocale = "en";
const locales = ["en", "de", "es", "fr", "pt-BR", "zh-CN", "it", "ru", "zh-TW"];

/** Keys in file order, so duplicates survive to be counted. `JSON.parse`
 *  keeps only the last of a repeated key and would hide them. */
function keysInFileOrder(source) {
  return [...source.matchAll(/^\s*"((?:[^"\\]|\\.)+)"\s*:/gm)].map((m) => m[1]);
}

/** `{name}`-style placeholders. A dropped one renders as a blank in the UI
 *  and a misspelled one throws at runtime, neither of which type-checking
 *  or the Paraglide compile step will catch. */
function placeholders(value) {
  return [...value.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
}

function read(locale) {
  const raw = readFileSync(join(messagesDir, `${locale}.json`), "utf8");
  return { raw, data: JSON.parse(raw) };
}

const files = new Map(locales.map((locale) => [locale, read(locale)]));
const base = files.get(baseLocale);
const baseKeys = keysInFileOrder(base.raw);

test("every locale file is valid JSON without a byte-order mark", () => {
  for (const locale of locales) {
    const bytes = readFileSync(join(messagesDir, `${locale}.json`));
    assert.ok(
      !(bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf),
      `${locale}.json starts with a UTF-8 BOM`,
    );
    assert.doesNotThrow(
      () => JSON.parse(bytes.toString("utf8")),
      `${locale}.json is not valid JSON`,
    );
  }
});

test("no locale file repeats a key", () => {
  for (const locale of locales) {
    const seen = new Set();
    const duplicates = [];
    for (const key of keysInFileOrder(files.get(locale).raw)) {
      if (seen.has(key)) duplicates.push(key);
      seen.add(key);
    }
    assert.deepEqual(duplicates, [], `${locale}.json repeats keys`);
  }
});

test("every locale carries exactly the keys English does", () => {
  const expected = new Set(baseKeys);
  for (const locale of locales) {
    if (locale === baseLocale) continue;
    const actual = new Set(keysInFileOrder(files.get(locale).raw));
    const missing = [...expected].filter((key) => !actual.has(key));
    const extra = [...actual].filter((key) => !expected.has(key));
    assert.deepEqual(missing, [], `${locale}.json is missing keys`);
    assert.deepEqual(extra, [], `${locale}.json has keys absent from English`);
  }
});

test("translations keep the placeholders their English source has", () => {
  for (const locale of locales) {
    if (locale === baseLocale) continue;
    const { data } = files.get(locale);
    const mismatches = [];
    for (const key of baseKeys) {
      const source = base.data[key];
      const translated = data[key];
      if (typeof source !== "string" || typeof translated !== "string") continue;
      const want = placeholders(source);
      const got = placeholders(translated);
      if (want.join(",") !== got.join(",")) {
        mismatches.push(`${key}: en [${want}] vs [${got}]`);
      }
    }
    assert.deepEqual(mismatches, [], `${locale}.json placeholder drift`);
  }
});

test("accented and CJK text is stored literally, not as \\u escapes", () => {
  // Both forms parse to the same string, so nothing breaks at runtime and
  // neither the compile step nor svelte-check objects. The cost is to whoever
  // edits the file next: a wall of `D\u00e9bloquer` is unreadable and invites
  // mistakes. Control characters legitimately stay escaped, hence the floor.
  for (const locale of locales) {
    const offenders = [
      ...files.get(locale).raw.matchAll(/\\u([0-9a-fA-F]{4})/g),
    ].filter((m) => Number.parseInt(m[1], 16) >= 0xa0);
    assert.deepEqual(
      offenders.map((m) => m[0]),
      [],
      `${locale}.json escapes printable characters instead of storing them literally`,
    );
  }
});

test("share_ember_text fits the backend caption cap", () => {
  // Must match EMBER_SHARE_TEXT_MAX in src-tauri/src/commands/settings.rs.
  // A longer translation makes every Share Ember button fail at runtime.
  const maxBytes = 280;
  for (const locale of locales) {
    const text = files.get(locale).data.share_ember_text;
    assert.equal(typeof text, "string", `${locale}.json share_ember_text`);
    assert.ok(
      Buffer.byteLength(text) <= maxBytes,
      `${locale}.json share_ember_text is ${Buffer.byteLength(text)} bytes (max ${maxBytes})`,
    );
  }
});
