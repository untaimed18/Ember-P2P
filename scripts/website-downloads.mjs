#!/usr/bin/env node
// Refresh the website's download section and its new-release notice from a
// published release, once its notes are in docs/index.html.
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

import { describeInstallers } from "./ed2k-links.mjs";

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

const DOWNLOAD_ICON =
  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>';

function fileRow(label, file, { ed2kOnly = false } = {}) {
  const name = ed2kOnly
    ? `<span class="file-name">${escapeHtml(file.name)}</span>`
    : `<a href="${escapeHtml(file.url)}" class="file-name">${escapeHtml(file.name)}</a>`;
  return [
    "            <tr>",
    `              <th scope="row">${escapeHtml(label)}</th>`,
    `              <td>${name}<code class="sha256" title="SHA-256">SHA-256 ${escapeHtml(file.sha256)}</code></td>`,
    `              <td class="size">${formatSize(file.size)}</td>`,
    `              <td><a href="${escapeHtml(file.link)}" class="ed2k">eD2K link</a></td>`,
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
    `          <caption>Every file in Ember ${escapeHtml(version)}. Cannot reach GitHub? An eD2K link opens in Ember, eMule or aMule and fetches the same file from the eD2K network. Check what you get against its SHA-256.</caption>`,
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

export function updateWebsite(html, downloads) {
  if (!/^\d+\.\d+\.\d+$/.test(downloads.version ?? "")) {
    throw new Error(`not a release version: ${downloads.version}`);
  }
  if (!html.includes(`id="${releaseAnchor(downloads.version)}"`)) {
    throw new Error(
      `docs/index.html has no release notes for ${downloads.version} (id="${releaseAnchor(downloads.version)}"); write them first`,
    );
  }
  if (!downloads.installers?.length) throw new Error("the release lists no installers");
  const withDownloads = replaceBetween(html, "downloads", renderDownloads(downloads));
  return replaceBetween(withDownloads, "release-notice", renderNotice(downloads.version));
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
  const [tag, flag, assets] = process.argv.slice(2);
  if (!/^v\d+\.\d+\.\d+$/.test(tag ?? "") || (flag !== undefined && (flag !== "--assets" || !assets))) {
    throw new Error("usage: node scripts/website-downloads.mjs vX.Y.Z [--assets <dir>]");
  }
  const downloads = assets
    ? {
        version: tag.slice(1),
        tag,
        installers: describeInstallers({ bundleDirectories: [resolve(assets)], repository: REPOSITORY, tag }),
      }
    : downloadsFromRelease(tag);
  const indexPath = join(root, "docs", "index.html");
  writeFileSync(indexPath, updateWebsite(readFileSync(indexPath, "utf8"), downloads));
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
