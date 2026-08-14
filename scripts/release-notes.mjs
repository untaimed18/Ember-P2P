#!/usr/bin/env node
// Render the release notes for a version as Markdown, from the release history
// in docs/index.html.
//
// That page is already the canonical changelog — it is what the site serves and
// what we paste into GitHub Releases — so deriving from it keeps one source of
// truth. The workflow feeds the result to tauri-action's `releaseBody`, which
// lands in two places: the draft release body, and the `notes` field of
// latest.json, which the in-app updater shows before a user accepts an update.
// Before this existed both were the string "See the assets below to download
// and install this version."
import { appendFileSync, readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Shortest plausible set of notes. Guards against a structural change to the
 *  page silently producing an empty or near-empty release body. */
const MIN_NOTES_LENGTH = 80;

const ENTITIES = new Map([
  ["&rsquo;", "\u2019"],
  ["&lsquo;", "\u2018"],
  ["&ldquo;", "\u201c"],
  ["&rdquo;", "\u201d"],
  ["&mdash;", "\u2014"],
  ["&ndash;", "\u2013"],
  ["&hellip;", "\u2026"],
  ["&nbsp;", " "],
  ["&quot;", '"'],
  ["&#39;", "'"],
  ["&apos;", "'"],
  ["&lt;", "<"],
  ["&gt;", ">"],
  // Ampersand last: decoding it first would let "&amp;lt;" become "<".
  ["&amp;", "&"],
]);

function decodeEntities(value) {
  let out = value;
  for (const [entity, char] of ENTITIES) {
    out = out.split(entity).join(char);
  }
  return out;
}

/** Inline HTML -> Markdown for the small tag vocabulary these notes use. */
function inlineToMarkdown(html) {
  const text = html
    .replace(/<a\b[^>]*href="([^"]*)"[^>]*>([\s\S]*?)<\/a>/gi, "[$2]($1)")
    .replace(/<strong\b[^>]*>([\s\S]*?)<\/strong>/gi, "**$1**")
    .replace(/<em\b[^>]*>([\s\S]*?)<\/em>/gi, "*$1*")
    .replace(/<code\b[^>]*>([\s\S]*?)<\/code>/gi, "`$1`")
    .replace(/<br\s*\/?>/gi, " ")
    .replace(/<[^>]+>/g, "");
  return decodeEntities(text).replace(/\s+/g, " ").trim();
}

function versionToArticleId(version) {
  return `release-${version.split(".").join("-")}`;
}

/**
 * Extract the notes for `version` from the release-history page.
 *
 * Exported separately from the CLI so the contract is unit-testable: a silent
 * change in the page's shape has to fail a test rather than ship an empty
 * release body to every updater client.
 */
export function extractReleaseNotes(html, version) {
  const id = versionToArticleId(version);
  const startMatch = html.match(
    new RegExp(`<article\\b[^>]*id="${id}"[^>]*>`, "i"),
  );
  if (!startMatch) {
    throw new Error(
      `docs/index.html has no <article id="${id}"> — add the ${version} release section before tagging`,
    );
  }
  const start = startMatch.index + startMatch[0].length;
  const end = html.indexOf("</article>", start);
  if (end === -1) {
    throw new Error(`<article id="${id}"> is not closed in docs/index.html`);
  }
  const article = html.slice(start, end);

  const lines = [];
  // Headings, list items and the trailing changelog link, in document order.
  const blocks = article.matchAll(
    /<(h4|h5|li|p)\b([^>]*)>([\s\S]*?)<\/\1>/gi,
  );
  for (const [, tag, attributes, inner] of blocks) {
    const text = inlineToMarkdown(inner);
    if (!text) continue;
    const name = tag.toLowerCase();
    if (name === "h4") lines.push("", `## ${text}`, "");
    else if (name === "h5") lines.push("", `### ${text}`, "");
    else if (name === "li") lines.push(`- ${text}`);
    else if (/class="[^"]*\bfull-changelog\b[^"]*"/i.test(attributes)) {
      lines.push("", text);
    }
  }

  const notes = lines
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  if (notes.length < MIN_NOTES_LENGTH) {
    throw new Error(
      `extracted release notes for ${version} are only ${notes.length} characters — the page structure probably changed`,
    );
  }
  return notes;
}

function readVersion() {
  const flag = process.argv.indexOf("--version");
  if (flag !== -1 && process.argv[flag + 1]) {
    return process.argv[flag + 1].replace(/^v/, "");
  }
  const tag = process.env.GITHUB_REF_NAME;
  if (tag && /^v\d+\.\d+\.\d+$/.test(tag)) return tag.slice(1);
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
}

function main() {
  const version = readVersion();
  const html = readFileSync(join(root, "docs", "index.html"), "utf8");
  const notes = extractReleaseNotes(html, version);

  if (process.env.GITHUB_OUTPUT) {
    // Random delimiter: the notes are attacker-irrelevant but a fixed sentinel
    // appearing in the text would corrupt every later output in the file.
    const delimiter = `EOF_${randomUUID()}`;
    appendFileSync(
      process.env.GITHUB_OUTPUT,
      `body<<${delimiter}\n${notes}\n${delimiter}\n`,
    );
  }
  process.stdout.write(`${notes}\n`);
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
