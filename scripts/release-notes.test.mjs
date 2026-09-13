import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

import { extractReleaseNotes } from "./release-notes.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const docs = () => readFileSync(join(root, "docs", "index.html"), "utf8");

/** Version being released, or null during ordinary development.
 *
 *  The notes for the *next* version are legitimately unwritten right after a
 *  version bump, so requiring them on every push would leave main red between
 *  a bump and the writing of its changelog. Release tags are the moment they
 *  actually have to exist, and release.yml's no-secret `verify` job runs this
 *  suite with the tag in `GITHUB_REF_NAME` — so the gate still fires before
 *  anything is built or signed. */
const releaseVersion =
  process.env.GITHUB_REF_NAME?.match(/^v(\d+\.\d+\.\d+)$/)?.[1] ?? null;

/** Newest release on the page, which is published newest-first. */
function newestDocumentedVersion(html) {
  const match = html.match(/id="release-(\d+)-(\d+)-(\d+)"/);
  assert.ok(match, "docs/index.html has no release sections at all");
  return `${match[1]}.${match[2]}.${match[3]}`;
}

function assertUsableNotes(notes, version) {
  // The whole point is that the updater stops showing boilerplate.
  assert.ok(
    !notes.includes("See the assets below"),
    "release notes must not be the placeholder body",
  );
  assert.match(notes, /^## /m, "expected at least one section heading");
  assert.match(notes, /^- /m, "expected at least one bullet");
  assert.ok(
    notes.length > 400,
    `notes for ${version} are suspiciously short (${notes.length} chars)`,
  );
  // An entity the decoder has no entry for survives into the release body and
  // the updater's notes as literal text, which is how `Ctrl&minus;` reached
  // users. Asserted against the whole rendered output rather than against a
  // list of the entities we happened to think of, so the next one that gets
  // written on the page fails here instead of shipping.
  const leaked = notes.match(/&[a-zA-Z#][a-zA-Z0-9]*;/g);
  assert.equal(
    leaked,
    null,
    `undecoded HTML entities in the ${version} notes: ${[...new Set(leaked ?? [])].join(", ")}`,
  );
}

test("the version being tagged has notes on the site", {
  skip: releaseVersion ? false : "not building a release tag",
}, () => {
  assertUsableNotes(extractReleaseNotes(docs(), releaseVersion), releaseVersion);
});

test("the newest release documented on the site still renders", () => {
  // Always on, so a structural change to the page is caught immediately
  // instead of at tag time, without requiring notes for an unreleased bump.
  const version = newestDocumentedVersion(docs());
  assertUsableNotes(extractReleaseNotes(docs(), version), version);
});

test("a version with no section on the page is a hard error", () => {
  // Tagging a release whose notes were never written should fail the build
  // rather than publish an empty body to every updater client.
  assert.throws(
    () => extractReleaseNotes(docs(), "99.99.99"),
    /no <article id="release-99-99-99">/,
  );
});

test("headings, bullets and inline markup survive the conversion", () => {
  const html = `
    <article class="release" id="release-9-9-9">
      <div class="release-notes">
        <h4>What&rsquo;s New</h4>
        <ul>
          <li><strong>A thing.</strong> It uses <code>.env</code> &amp; more &mdash; really</li>
        </ul>
        <h5>Transfers</h5>
        <ul><li>Another thing</li></ul>
        <p class="full-changelog"><strong>Full Changelog</strong>
          <a href="https://example.test/compare">https://example.test/compare</a></p>
      </div>
    </article>`;
  const notes = extractReleaseNotes(html, "9.9.9");

  assert.match(notes, /^## What\u2019s New$/m);
  assert.match(notes, /^### Transfers$/m);
  assert.match(
    notes,
    /^- \*\*A thing\.\*\* It uses `\.env` & more \u2014 really$/m,
  );
  assert.match(
    notes,
    /\[https:\/\/example\.test\/compare\]\(https:\/\/example\.test\/compare\)/,
  );
  // Nothing may leak through as raw HTML.
  assert.ok(!/[<>]/.test(notes.replace(/https?:\/\/\S+/g, "")), notes);
});

test("a section that lost its content is rejected rather than published", () => {
  const html = `
    <article class="release" id="release-9-9-9">
      <div class="release-notes"><h4>What&rsquo;s New</h4></div>
    </article>`;
  assert.throws(
    () => extractReleaseNotes(html, "9.9.9"),
    /suspiciously short|characters/,
  );
});

test("an unclosed article is reported instead of silently truncating", () => {
  const html = '<article class="release" id="release-9-9-9"><h4>Hi</h4>';
  assert.throws(() => extractReleaseNotes(html, "9.9.9"), /is not closed/);
});

test("an entity the decoder does not know is caught before it ships", () => {
  // Long enough on its own to clear both the extractor's floor and the
  // usable-notes length guard, so the only thing under test is the entity.
  const body = (entity) => `
    <article class="release" id="release-9-9-9">
      <div class="release-notes">
        <h4>What&rsquo;s New</h4>
        <ul>
          <li><strong>Ctrl+ and Ctrl${entity} zoom the interface,</strong> so a compositor whose
            display scale never reaches the webview can be corrected by hand, which is the whole
            of the reason this exists and is quite enough prose to be a realistic bullet.</li>
          <li><strong>A second bullet, for length.</strong> The usable-notes guard refuses a
            section short enough to look like a structural failure of the page, so a fixture
            testing anything else has to be long enough not to trip it on the way past.</li>
        </ul>
      </div>
    </article>`;

  // `&minus;` has an entry, so the real note passes.
  assertUsableNotes(extractReleaseNotes(body("&minus;"), "9.9.9"), "9.9.9");

  // One that does not is refused rather than published as literal text.
  assert.throws(
    () => assertUsableNotes(extractReleaseNotes(body("&plusmn;"), "9.9.9"), "9.9.9"),
    /undecoded HTML entities.*&plusmn;/s,
  );
});
