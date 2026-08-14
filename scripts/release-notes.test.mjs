import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import assert from "node:assert/strict";

import { extractReleaseNotes } from "./release-notes.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const docs = () => readFileSync(join(root, "docs", "index.html"), "utf8");
const packageVersion = () =>
  JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

test("the release being shipped has notes on the site", () => {
  const version = packageVersion();
  const notes = extractReleaseNotes(docs(), version);

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
