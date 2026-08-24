import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * The "BLAKE3 verify failed" badge on a transfer row is decided twice: Rust
 * classifies the failure in `is_ember_blake3_mismatch` and reduces it to
 * `TransferFailureCode::EmberContentHashMismatch`, and the frontend recognises
 * that verdict again in `isEmberBlake3Mismatch`.
 *
 * What the two sides share is now a code rather than a sentence, so Rust can
 * re-word the English freely. What they must still agree on is the code —
 * re-spelling it in the `transfer_failure_codes!` table compiles fine, passes
 * `cargo test`, passes `svelte-check`, and quietly removes the badge documented
 * in docs/ember-dht.md ("BLAKE3 verify fail is a permanent download failure
 * with a red Ember badge"). `fixtures/ember-integrity.json` is the shared
 * source of truth; a divergence fails here, on whichever side moved.
 *
 * The substring rule Rust still runs is checked too, one level further back: it
 * is what routes a raw anyhow chain to the variant in the first place, so the
 * badge disappears just as thoroughly if the classifier stops consulting it.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixture = JSON.parse(
  readFileSync(join(root, "scripts", "fixtures", "ember-integrity.json"), "utf8"),
);
const helperPath = join(root, "src", "lib", "emberIntegrity.ts");
const helper = readFileSync(helperPath, "utf8");
const rust = readFileSync(join(root, ...fixture.rust.file.split("/")), "utf8");

/**
 * Lift the predicate body verbatim out of `emberIntegrity.ts`.
 *
 * Same technique, and the same reasons, as `merge-contract.test.mjs`: the
 * module is part of a Svelte app and there is no bundler on this path, but the
 * function is pure and its only TypeScript is the signature, so running the
 * extracted body exercises the shipped rule rather than a second copy of it.
 * A rename or a reformatted signature fails loudly here, which is the point.
 */
const SIGNATURE =
  "export function isEmberBlake3Mismatch(code: string | null | undefined): boolean {";

function predicateFromHelper() {
  const start = helper.indexOf(SIGNATURE);
  if (start === -1) {
    throw new Error(
      `could not find \`${SIGNATURE}\` in src/lib/emberIntegrity.ts — if the predicate was renamed or moved, update this test`,
    );
  }
  const bodyStart = start + SIGNATURE.length;
  const end = helper.indexOf("\n}\n", bodyStart);
  if (end === -1) throw new Error("unterminated body for isEmberBlake3Mismatch");
  return new Function("code", helper.slice(bodyStart, end));
}

/** The body of one Rust `fn`, terminated by the closing brace in column 0. */
function rustFnBody(name) {
  const signature = `fn ${name}(`;
  const start = rust.indexOf(signature);
  assert.notEqual(start, -1, `${fixture.rust.file} no longer defines \`${name}\``);
  const end = rust.indexOf("\n}\n", start);
  assert.notEqual(end, -1, `unterminated body for \`${name}\``);
  return rust.slice(start, end);
}

const isEmberBlake3Mismatch = predicateFromHelper();

test("the badge predicate classifies every fixture code", () => {
  for (const testCase of fixture.cases) {
    assert.equal(
      isEmberBlake3Mismatch(testCase.code),
      testCase.mismatch,
      testCase.name,
    );
  }
});

test("Rust still declares the code the badge is keyed off", () => {
  const table = rust.slice(rust.indexOf(`${fixture.rust.macro}! {`));
  assert.ok(
    table.startsWith(`${fixture.rust.macro}! {`),
    `${fixture.rust.file} no longer declares a ${fixture.rust.macro}! table`,
  );
  const declaration = new RegExp(
    `${fixture.rust.variant}\\s*=>\\s*"([a-z0-9_]+)",\\s*\\n?\\s*"([^"]+)"`,
  ).exec(table);
  assert.ok(
    declaration,
    `the ${fixture.rust.macro}! table no longer declares ${fixture.rust.variant}`,
  );
  assert.equal(
    declaration[1],
    fixture.rust.code,
    "the Ember mismatch code was re-spelled; the transfer row would lose its badge",
  );
  assert.equal(
    declaration[2],
    fixture.rust.summary,
    "the canned English changed — harmless now, but the logs and the docs quote it",
  );
  assert.ok(
    isEmberBlake3Mismatch(declaration[1]),
    "the code Rust declares must classify as an Ember pin failure on the frontend too",
  );
});

test("the classifier still routes a pin failure to that variant", () => {
  const body = rustFnBody(fixture.rust.classifier_fn);
  assert.ok(
    body.includes(`${fixture.rust.predicate}(error)`),
    `${fixture.rust.classifier_fn} no longer consults ${fixture.rust.predicate}`,
  );
  assert.ok(
    body.includes(`TransferFailureCode::${fixture.rust.variant}`),
    `${fixture.rust.classifier_fn} no longer returns ${fixture.rust.variant}; nothing would set the badge`,
  );
});

test("the raw failures Rust recognises still reach that classifier branch", () => {
  // The frontend no longer repeats these substrings, but the badge still hangs
  // off them: they are how a raw completion error becomes the variant above.
  const body = rustFnBody(fixture.rust.predicate);
  for (const needle of fixture.rust.match_substrings) {
    assert.ok(
      body.includes(`"${needle}"`),
      `${fixture.rust.predicate} no longer matches ${JSON.stringify(needle)}; those failures would classify as something else`,
    );
  }
  const declaration = new RegExp(
    `${fixture.rust.raw_message_const}: &str =\\s*"([^"]+)"`,
  ).exec(rust);
  assert.ok(
    declaration,
    `${fixture.rust.file} no longer declares ${fixture.rust.raw_message_const} as a string literal`,
  );
  assert.equal(
    declaration[1],
    fixture.rust.raw_message,
    "the shared raw mismatch message was re-worded",
  );
  assert.ok(
    fixture.rust.match_substrings.some((needle) =>
      declaration[1].toLowerCase().includes(needle),
    ),
    "the shared raw message no longer satisfies the predicate it is written for",
  );
});

test("the fixture actually carries cases of both polarities", () => {
  // Guards the loader itself: an empty or renamed section would make the
  // classification check above pass by iterating nothing.
  assert.ok(fixture.cases.length >= 5, "too few classification cases");
  assert.ok(
    fixture.cases.some((c) => c.mismatch),
    "no positive case",
  );
  assert.ok(
    fixture.cases.some((c) => !c.mismatch),
    "no negative case",
  );
});
