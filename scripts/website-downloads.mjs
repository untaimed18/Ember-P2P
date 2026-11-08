#!/usr/bin/env node
// Refresh the website's download section and its new-release notice from a
// published release, once its notes are in docs/index.html. Publishing a
// release runs this through `.github/workflows/website.yml`; by hand:
//
//   node scripts/website-downloads.mjs v1.8.0
//       reads Ember_1.8.0_downloads.json, which the release workflow attaches
//       (scripts/ed2k-links.mjs), from that release with `gh`
//   node scripts/website-downloads.mjs v1.7.6 --assets <dir>
//       hashes installers already downloaded into <dir>, for a release from
//       before the workflow wrote that file
//
// The download section lists every installer with its size, SHA-256, GitHub
// download and eD2K link, so someone who cannot reach GitHub still has a way
// to the files and a way to check them. It and the notice are rewritten
// between their marker comments and nowhere else.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { INSTALLERS, describeInstallers, ed2kLink, releaseDownloadUrl } from "./ed2k-links.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPOSITORY = "untaimed18/Ember-P2P";

export function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/** Decimal megabytes, as the release page and most download pages show them. */
export function formatSize(bytes) {
  if (bytes < 1_000_000) return `${Math.max(1, Math.round(bytes / 1000))} KB`;
  return `${(bytes / 1_000_000).toFixed(1)} MB`;
}

/** The id of a version's article in the release history. */
export function releaseAnchor(version) {
  return `release-${version.replaceAll(".", "-")}`;
}

/**
 * `link` as a page has to write it for a click to reach the eD2K client.
 * Chrome and Edge 130+ and Firefox 122+ parse `ed2k://` links by the URL
 * Standard, which forbids `|` after the `//`: a raw link is blocked
 * (`about:blank#blocked`) and never leaves the browser. Written as `%7C` it
 * parses, and Ember, eMule and aMule restore the pipes. The web source is
 * encoded whole as well; left as it is, its `https:` reads as an empty port
 * and the browser drops the colon. eMule decodes it with the rest of the link.
 */
export function clickableEd2kLink(link) {
  const fields = link.replace(/^ed2k:\/\//, "").split("|");
  return `ed2k://${fields
    .map((field, index) => (index > 4 && field.startsWith("s=") ? `s=${encodeURIComponent(field.slice(2))}` : field))
    .join("%7C")}`;
}

const DOWNLOAD_ICON =
  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

function fileRow(label, file, { ed2kOnly = false } = {}) {
  const name = ed2kOnly
    ? `<span class="file-name">${escapeHtml(file.name)}</span>`
    : `<a href="${escapeHtml(file.url)}" class="file-name">${escapeHtml(file.name)}</a>`;
  return [
    "            <tr>",
    `              <th scope="row">${escapeHtml(label)}</th>`,
    `              <td>${name}<code class="sha256" title="SHA-256">SHA-256 ${escapeHtml(file.sha256)}</code><details class="ed2k-text"><summary>eD2K link as text</summary><code>${escapeHtml(file.link)}</code></details></td>`,
    `              <td class="size">${formatSize(file.size)}</td>`,
    `              <td><a href="${escapeHtml(clickableEd2kLink(file.link))}" class="ed2k">eD2K link</a></td>`,
    "            </tr>",
  ].join("\n");
}

export function renderDownloads(downloads) {
  const { version, tag } = downloads;
  const rows = downloads.installers.map((file) => fileRow(file.label, file));
  if (downloads.collection) {
    rows.push(fileRow("All of the above and the release notes, as an eMule collection", downloads.collection));
  }
  return [
    `      <h2>Download Ember ${escapeHtml(version)}</h2>`,
    "      <p>Free for Windows 10 and 11, and for x86-64 Linux as a <code>.deb</code> or an AppImage. Every release is signed, and Ember updates itself.</p>",
    '      <div class="btn-group">',
    `        <a href="https://github.com/${REPOSITORY}/releases/tag/${escapeHtml(tag)}" class="btn btn-light" target="_blank" rel="noopener">${DOWNLOAD_ICON}Download from GitHub</a>`,
    `        <a href="#${releaseAnchor(version)}" class="btn btn-ghost">What&rsquo;s new in ${escapeHtml(version)}</a>`,
    "      </div>",
    '      <div class="downloads">',
    "        <table>",
    `          <caption>Every file in Ember ${escapeHtml(version)}. Cannot reach GitHub? An eD2K link opens in Ember, eMule or aMule and fetches the same file from the eD2K network; to paste one into the client instead, copy it from &ldquo;eD2K link as text&rdquo;. Check what you get against its SHA-256.</caption>`,
    '          <thead><tr><th scope="col">For</th><th scope="col">File</th><th scope="col">Size</th><th scope="col">eD2K</th></tr></thead>',
    "          <tbody>",
    ...rows,
    "          </tbody>",
    "        </table>",
    "      </div>",
    '      <p class="meta">Windows 10 or 11, 64-bit &middot; Linux x86-64 with glibc 2.35 or newer (Ubuntu 22.04, Debian 12 and later); the AppImage also needs FUSE 2 &middot; <a href="guide.html#installation">System requirements and updates</a></p>',
  ].join("\n");
}

export function renderNotice(version) {
  return `      <a class="release-notice" href="#${releaseAnchor(version)}"><span class="release-notice-tag">New</span>Ember ${escapeHtml(version)} is out &middot; see what&rsquo;s new</a>`;
}

/** `html` with what lies between `name`'s marker comments replaced. */
export function replaceBetween(html, name, content) {
  const start = `<!-- ${name}:start -->`;
  const end = `<!-- ${name}:end -->`;
  const from = html.indexOf(start);
  const to = html.indexOf(end);
  if (from < 0 || to < from || html.indexOf(start, from + 1) >= 0 || html.indexOf(end, to + 1) >= 0) {
    throw new Error(`docs/index.html needs exactly one ${start} … ${end} pair`);
  }
  // The end marker keeps the indentation its line had.
  const lineStart = html.lastIndexOf("\n", to - 1) + 1;
  const lead = html.slice(lineStart, to);
  const indent = /^[ \t]*$/.test(lead) ? lead : "";
  return `${html.slice(0, from + start.length)}\n${content}\n${indent}${html.slice(to)}`;
}

const hex = (length) => new RegExp(`^[0-9a-f]{${length}}$`, "i");

/**
 * `downloads` as the page may use it. The list is a release asset with no
 * signature of its own, so it is held to what it can only be: the release's
 * own files, named for it, with hashes and sizes of the right form. Every
 * URL and eD2K link on the page is built again from those, never taken as
 * written, and labels are the page's own.
 */
export function checkedDownloads(downloads) {
  const version = downloads?.version;
  if (!/^\d+\.\d+\.\d+$/.test(version ?? "")) throw new Error(`not a release version: ${version}`);
  const tag = `v${version}`;
  if (downloads.tag !== tag) throw new Error(`the downloads list is for ${downloads.tag}, not ${tag}`);
  const ownName = new RegExp(`^Ember_${version.replaceAll(".", "\\.")}[._][A-Za-z0-9_-][A-Za-z0-9._-]*$`);
  const file = (entry, what) => {
    const { name, size, sha256, ed2k, aich } = entry ?? {};
    if (typeof name !== "string" || !ownName.test(name) || name.includes("..")) {
      throw new Error(`${what}: not a file of Ember ${version}: ${JSON.stringify(name)}`);
    }
    if (!Number.isSafeInteger(size) || size <= 0) throw new Error(`${what}: not a size: ${JSON.stringify(size)}`);
    if (!hex(64).test(sha256 ?? "")) throw new Error(`${what}: not a SHA-256: ${JSON.stringify(sha256)}`);
    if (!hex(32).test(ed2k ?? "")) throw new Error(`${what}: not an eD2K hash: ${JSON.stringify(ed2k)}`);
    if (aich != null && !hex(40).test(aich)) throw new Error(`${what}: not an AICH hash: ${JSON.stringify(aich)}`);
    const url = releaseDownloadUrl(REPOSITORY, tag, name);
    return {
      name,
      size,
      sha256: sha256.toLowerCase(),
      url,
      link: ed2kLink({ name, size, ed2k, aich: aich ?? undefined, webSources: [url] }),
    };
  };
  const labels = new Map(INSTALLERS.map((installer) => [installer.kind, installer.label]));
  const installers = (Array.isArray(downloads.installers) ? downloads.installers : []).map((entry, index) => {
    const label = labels.get(entry?.kind);
    if (!label) throw new Error(`installer ${index}: an unknown or repeated kind: ${JSON.stringify(entry?.kind)}`);
    labels.delete(entry.kind);
    return { kind: entry.kind, label, ...file(entry, entry.kind) };
  });
  if (!installers.length) throw new Error("the release lists no installers");
  return {
    version,
    tag,
    installers,
    collection: downloads.collection ? file(downloads.collection, "collection") : undefined,
  };
}

/** The version the page's download section offers now, if it names one. */
export function offeredVersion(html) {
  return html.match(/<h2>Download Ember (\d+\.\d+\.\d+)<\/h2>/)?.[1] ?? null;
}

/** Whether `version` comes before `than`, both `major.minor.patch`. */
export function isOlder(version, than) {
  const parts = (text) => text.split(".").map(Number);
  const [a, b] = [parts(version), parts(than)];
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

export function updateWebsite(html, downloads) {
  const checked = checkedDownloads(downloads);
  if (!html.includes(`id="${releaseAnchor(checked.version)}"`)) {
    throw new Error(
      `docs/index.html has no release notes for ${checked.version} (id="${releaseAnchor(checked.version)}"); write them first`,
    );
  }
  const withDownloads = replaceBetween(html, "downloads", renderDownloads(checked));
  return replaceBetween(withDownloads, "release-notice", renderNotice(checked.version));
}

function downloadsFromRelease(tag) {
  const version = tag.replace(/^v/, "");
  const dir = mkdtempSync(join(tmpdir(), "ember-downloads-"));
  try {
    execFileSync(
      "gh",
      ["release", "download", tag, "--repo", REPOSITORY, "--pattern", `Ember_${version}_downloads.json`, "--dir", dir],
      { stdio: ["ignore", "inherit", "inherit"] },
    );
    return JSON.parse(readFileSync(join(dir, `Ember_${version}_downloads.json`), "utf8"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function main() {
  const [tag, ...rest] = process.argv.slice(2);
  const allowOlder = rest.includes("--allow-older");
  const options = rest.filter((arg) => arg !== "--allow-older");
  const assets = options[0] === "--assets" ? options[1] : undefined;
  if (!/^v\d+\.\d+\.\d+$/.test(tag ?? "") || (options.length > 0 && (options.length !== 2 || !assets))) {
    throw new Error("usage: node scripts/website-downloads.mjs vX.Y.Z [--assets <dir>] [--allow-older]");
  }
  const indexPath = join(root, "docs", "index.html");
  const html = readFileSync(indexPath, "utf8");
  // Republishing an older release must not take the site back to it; a
  // deliberate rollback says so.
  const offered = offeredVersion(html);
  if (offered && isOlder(tag.slice(1), offered) && !allowOlder) {
    console.log(`docs/index.html offers Ember ${offered}, newer than ${tag}; it stays as it is`);
    return;
  }
  const downloads = assets
    ? {
        version: tag.slice(1),
        tag,
        installers: describeInstallers({ bundleDirectories: [resolve(assets)], repository: REPOSITORY, tag }),
      }
    : downloadsFromRelease(tag);
  writeFileSync(indexPath, updateWebsite(html, downloads));
  console.log(`docs/index.html now offers Ember ${downloads.version}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
