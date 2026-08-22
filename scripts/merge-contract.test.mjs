import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * The search-result merge contract is implemented twice: `src/lib/stores/search.ts`
 * merges streamed batches per tab, `src-tauri/src/search/merge.rs` merges the
 * lists it emits. Three rules have to agree between them — the dedup key, the
 * origin-label combination, and the plausibility ceiling on peer-reported
 * source counts — and until this test existed only a code comment
 * ("matching MAX_PLAUSIBLE_SOURCES in merge.rs") held them together.
 *
 * `fixtures/merge-contract.json` is the shared source of truth; the `#[cfg(test)]`
 * fixture tests in merge.rs read the same file. A divergence now fails on
 * whichever side moved.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const storePath = join(root, "src", "lib", "stores", "search.ts");
const store = readFileSync(storePath, "utf8");
const rustMergePath = join(root, "src-tauri", "src", "search", "merge.rs");
const fixture = JSON.parse(
  readFileSync(join(root, "scripts", "fixtures", "merge-contract.json"), "utf8"),
);

/**
 * Lift one function body verbatim out of `search.ts`.
 *
 * The store is a Svelte-app module (`$lib`/`$app` imports, TypeScript), so a
 * plain `node --test` process cannot import it and there is no bundler on this
 * path. Both rule functions are pure and their only TypeScript is the
 * signature, so running the extracted body exercises the shipped rule rather
 * than a second copy of it. The functions are closed over nothing, which is
 * why this works — keep them that way.
 *
 * A rename, or a reformat of the signature, fails here loudly. That is the
 * intended outcome: the contract moved and both sides need re-checking.
 */
function bodyFromStore(signature) {
  const start = store.indexOf(signature);
  if (start === -1) {
    throw new Error(
      `could not find \`${signature}\` in src/lib/stores/search.ts — if the rule was renamed or moved, update this test`,
    );
  }
  const bodyStart = start + signature.length;
  // Terminated by the closing brace in column 0; nothing inside these bodies
  // is unindented.
  const end = store.indexOf("\n}\n", bodyStart);
  if (end === -1) throw new Error(`unterminated body for \`${signature}\``);
  return store.slice(bodyStart, end);
}

function ruleFromStore(signature, ...params) {
  return new Function(...params, bodyFromStore(signature));
}

const resultKey = ruleFromStore(
  "function resultKey(result: SearchResult): string {",
  "result",
);
const combineOrigin = ruleFromStore(
  "function combineOrigin(a: string, b: string): string {",
  "a",
  "b",
);
const mergeResultBody = bodyFromStore(
  "function mergeResult(existing: SearchResult, incoming: SearchResult): SearchResult {",
);

const declaredCeiling = /const MAX_PLAUSIBLE_SOURCES = ([0-9_]+);/.exec(store);

test("resultKey derives the key the Rust side derives", () => {
  for (const testCase of fixture.result_key_cases) {
    assert.equal(resultKey({ file: testCase.file }), testCase.key, testCase.name);
  }
});

test("combineOrigin agrees with the shared origin table", () => {
  for (const testCase of fixture.combine_origin_cases) {
    assert.equal(
      combineOrigin(testCase.a, testCase.b),
      testCase.combined,
      `combineOrigin(${JSON.stringify(testCase.a)}, ${JSON.stringify(testCase.b)})`,
    );
  }
});

test("the source-count ceiling matches the fixture and clamps like Rust", () => {
  assert.ok(
    declaredCeiling,
    "MAX_PLAUSIBLE_SOURCES is no longer declared as a literal in src/lib/stores/search.ts",
  );
  const ceiling = Number(declaredCeiling[1].replaceAll("_", ""));
  assert.equal(
    ceiling,
    fixture.max_plausible_sources,
    "the frontend ceiling drifted from the shared contract (u16::MAX on the ed2k wire)",
  );
  for (const testCase of fixture.clamp_source_count_cases) {
    assert.equal(
      Math.min(testCase.count, ceiling),
      testCase.clamped,
      `clamp(${testCase.count})`,
    );
  }
});

test("mergeResult still holds both peer-reported counts to the ceiling", () => {
  // `availability` and `file.complete_sources` arrive straight off the wire, so
  // dropping either clamp is the regression the ceiling exists to prevent —
  // and a dropped clamp is invisible to the pure-rule checks above.
  const clamped = mergeResultBody.match(/MAX_PLAUSIBLE_SOURCES/g) ?? [];
  assert.equal(
    clamped.length,
    2,
    "expected mergeResult to clamp exactly `availability` and `file.complete_sources`",
  );
});

test("the Rust side derives its ceiling from the same wire limit", () => {
  // Cheap cross-check so a divergence is visible to `npm test` too: the Rust
  // fixture tests only run under `cargo test`.
  const rust = readFileSync(rustMergePath, "utf8");
  assert.match(
    rust,
    /const MAX_PLAUSIBLE_SOURCES: u32 = u16::MAX as u32;/,
    "src-tauri/src/search/merge.rs no longer derives MAX_PLAUSIBLE_SOURCES from u16::MAX",
  );
  assert.equal(
    fixture.max_plausible_sources,
    0xffff,
    "the fixture ceiling must stay u16::MAX",
  );
});

test("the source-address cap matches the fixture on both sides", () => {
  assert.equal(fixture.max_source_addrs, 500);
  const rust = readFileSync(rustMergePath, "utf8");
  assert.match(
    rust,
    /const MAX_SOURCE_ADDRS: usize = 500;/,
    "src-tauri/src/search/merge.rs no longer pins MAX_SOURCE_ADDRS at 500",
  );
  const declared = store.match(/const MAX_SOURCE_ADDRS = (\d+)/);
  assert.ok(declared, "MAX_SOURCE_ADDRS is no longer declared in src/lib/stores/search.ts");
  assert.equal(Number(declared[1]), fixture.max_source_addrs);
});

test("the fixture actually carries cases", () => {
  // Guards the loader itself: an empty or renamed section would make every
  // check above pass by iterating nothing.
  assert.ok(fixture.result_key_cases.length >= 5, "too few resultKey cases");
  assert.ok(fixture.combine_origin_cases.length >= 8, "too few combineOrigin cases");
  assert.ok(
    fixture.clamp_source_count_cases.length >= 4,
    "too few source-count clamp cases",
  );
});
