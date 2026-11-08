import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { formatSize, releaseAnchor, replaceBetween, updateWebsite } from "./website-downloads.mjs";

const file = (kind, name, extra = {}) => ({
  kind,
  label: `Label for ${kind}`,
  name,
  size: 19_600_000,
  sha256: "ab".repeat(32),
  ed2k: "00".repeat(16),
  aich: "11".repeat(20),
  url: `https://github.com/untaimed18/Ember-P2P/releases/download/v9.9.9/${name}`,
  link: `ed2k://|file|${name}|19600000|${"00".repeat(16).toUpperCase()}|/`,
  ...extra,
});

const DOWNLOADS = {
  version: "9.9.9",
  tag: "v9.9.9",
  installers: [file("windows-installer", "Ember_9.9.9_x64-setup.exe"), file("linux-deb", "Ember_9.9.9_amd64.deb")],
  collection: file("collection", "Ember_9.9.9.emulecollection"),
};

const PAGE = [
  "<!-- release-notice:start -->old notice<!-- release-notice:end -->",
  "<!-- downloads:start -->old downloads<!-- downloads:end -->",
  '<article class="release" id="release-9-9-9"></article>',
].join("\n");

test("the website offers every file with its size, SHA-256, download and eD2K link", () => {
  const html = updateWebsite(PAGE, DOWNLOADS);
  assert.ok(!html.includes("old downloads") && !html.includes("old notice"));
  assert.ok(html.includes("<h2>Download Ember 9.9.9</h2>"));
  for (const entry of [...DOWNLOADS.installers, DOWNLOADS.collection]) {
    assert.ok(html.includes(`href="${entry.url}"`), entry.name);
    assert.ok(html.includes(`href="${entry.link}"`), entry.name);
    assert.ok(html.includes(entry.sha256), entry.name);
  }
  assert.ok(html.includes('href="#release-9-9-9"'), "the notice and the button reach the notes");
  assert.equal(updateWebsite(html, DOWNLOADS), html, "running it again changes nothing");
});

test("nothing is offered before its notes are written, or into a page without its markers", () => {
  assert.throws(() => updateWebsite(PAGE.replace("release-9-9-9", "release-9-9-8"), DOWNLOADS), /no release notes for 9.9.9/);
  assert.throws(() => updateWebsite(PAGE.replace("<!-- downloads:end -->", ""), DOWNLOADS), /exactly one/);
  assert.throws(() => replaceBetween(`${PAGE}\n<!-- downloads:start --><!-- downloads:end -->`, "downloads", "x"), /exactly one/);
  assert.throws(() => updateWebsite(PAGE, { ...DOWNLOADS, version: "9.9" }), /not a release version/);
});

test("text from the release cannot become markup", () => {
  const hostile = { ...DOWNLOADS, installers: [file("windows-installer", 'a"><script>x</script>.exe')] };
  const html = updateWebsite(PAGE, hostile);
  assert.ok(!html.includes("<script>"));
  assert.ok(html.includes("&lt;script&gt;"));
});

test("sizes and anchors read as the page writes them", () => {
  assert.equal(formatSize(19_600_000), "19.6 MB");
  assert.equal(formatSize(4_321), "4 KB");
  assert.equal(releaseAnchor("1.8.0"), "release-1-8-0");
});

test("the live page carries both markers", () => {
  const html = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  assert.equal(replaceBetween(html, "downloads", "x").includes("x"), true);
  assert.equal(replaceBetween(html, "release-notice", "x").includes("x"), true);
});
