#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The Windows installers Ember publishes and the updater key for each.
 *
 * The same keys `tauri-action` wrote while it built and signed in one job:
 * `tauri-plugin-updater` asks for `windows-x86_64-{installer}` first, where the
 * installer comes from a marker the bundler writes into each package, and only
 * then falls back to the bare `windows-x86_64`, which carries the NSIS build
 * (the old `updaterJsonPreferNsis: true`).
 *
 * `createUpdaterArtifacts: true` in tauri.conf.json signs the installers
 * themselves rather than zipping them, so building with it off and running
 * `tauri signer sign` on each installer afterwards produces the same artifact
 * and the same `.sig` — without the signing key ever being present while
 * dependencies, build scripts and proc-macros run.
 */
const WINDOWS_BUNDLES = [
  { bundle: "nsis", suffix: "-setup.exe" },
  { bundle: "msi", suffix: ".msi" },
];
const PREFERRED_BUNDLE = "nsis";

function walkFiles(directory, output = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walkFiles(path, output);
    else if (entry.isFile()) output.push(path);
  }
  return output;
}

/**
 * Pair each Windows installer under `directory` with the detached signature
 * beside it. Exactly one of each kind is required: two means two builds were
 * collected and nothing can say which one a signature belongs to, and none
 * means the manifest would advertise an asset that was never uploaded.
 */
export function collectWindowsBundles({ directory }) {
  if (!existsSync(directory) || !statSync(directory).isDirectory()) {
    throw new Error(`Windows bundle directory ${directory} does not exist`);
  }
  const paths = walkFiles(directory);
  return WINDOWS_BUNDLES.map(({ bundle, suffix }) => {
    const matches = paths.filter((path) =>
      path.toLowerCase().endsWith(suffix),
    );
    if (matches.length !== 1) {
      throw new Error(
        `expected exactly one ${suffix} installer under ${directory}, found ${matches.length}`,
      );
    }
    const path = matches[0];
    const name = basename(path);
    if (!existsSync(`${path}.sig`)) {
      throw new Error(`${name} has no ${name}.sig beside it`);
    }
    const signature = readFileSync(`${path}.sig`, "utf8").trim();
    if (signature === "") {
      throw new Error(`${name}.sig is empty`);
    }
    return { bundle, name, signature };
  });
}

/** Where GitHub serves this release's assets once the draft is published. */
export function releaseAssetBase({ serverUrl, repository, tag }) {
  if (!repository || !/^[\w.-]+\/[\w.-]+$/.test(repository)) {
    throw new Error(`GITHUB_REPOSITORY is not owner/repo: ${String(repository)}`);
  }
  if (!tag) throw new Error("the release tag is required");
  const server = new URL(serverUrl || "https://github.com");
  return `${server.origin}/${repository}/releases/download/${encodeURIComponent(tag)}`;
}

/**
 * A fresh manifest holding the Windows entries. Only `url` and `signature`
 * are set per platform, as `tauri-action` did; `add-linux-platforms.mjs` adds
 * the Linux ones from the same base URL, and `harden-update-manifest.mjs`
 * binds `target`, `sha256` and `size` from the bytes afterwards.
 *
 * Always built from scratch, so a re-run of the signing job cannot carry a
 * previous attempt's signatures forward against this attempt's bytes.
 */
export function composeManifest({ version, notes, pubDate, assetBase, bundles }) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) {
    throw new Error(`version must be exact major.minor.patch, got ${String(version)}`);
  }
  if (typeof notes !== "string" || notes.trim() === "") {
    throw new Error("release notes are required for latest.json");
  }
  const platforms = {};
  for (const { bundle, name, signature } of bundles) {
    platforms[`windows-x86_64-${bundle}`] = {
      url: `${assetBase}/${encodeURIComponent(name)}`,
      signature,
    };
  }
  const preferred = platforms[`windows-x86_64-${PREFERRED_BUNDLE}`];
  if (!preferred) {
    throw new Error(`no ${PREFERRED_BUNDLE} installer to serve as windows-x86_64`);
  }
  return {
    version,
    notes,
    pub_date: pubDate,
    platforms: { "windows-x86_64": { ...preferred }, ...platforms },
  };
}

function main() {
  const manifestPath = resolve(
    root,
    process.env.EMBER_UPDATE_MANIFEST ?? "latest.json",
  );
  const directory = process.env.EMBER_WINDOWS_BUNDLE_DIR;
  if (!directory) {
    throw new Error("EMBER_WINDOWS_BUNDLE_DIR must name the Windows bundle directory");
  }
  const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
  const tag = process.env.GITHUB_REF_NAME;
  if (tag !== `v${version}`) {
    throw new Error(`release tag ${String(tag)} does not match package version ${version}`);
  }

  const manifest = composeManifest({
    version,
    notes: process.env.EMBER_RELEASE_NOTES ?? "",
    pubDate: new Date().toISOString(),
    assetBase: releaseAssetBase({
      serverUrl: process.env.GITHUB_SERVER_URL,
      repository: process.env.GITHUB_REPOSITORY,
      tag,
    }),
    bundles: collectWindowsBundles({ directory: resolve(root, directory) }),
  });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(
    `composed ${Object.keys(manifest.platforms).join(", ")} into ${manifestPath}`,
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
