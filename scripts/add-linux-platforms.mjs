#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The updater targets Ember publishes for Linux, and the bundle behind each.
 *
 * `tauri-plugin-updater` asks for `{os}-{arch}-{installer}` first and only then
 * falls back to a bare `{os}-{arch}`, where `{installer}` comes from a marker
 * the bundler writes into the binary of each package it produces. So a `.deb`
 * install asks for `linux-x86_64-deb` and hands the answer to `dpkg -i`, and an
 * AppImage asks for `linux-x86_64-appimage` and rewrites itself in place. Two
 * keys, two artifacts, and each install updates with the format it was
 * installed from.
 *
 * The bare `linux-x86_64` key that `tauri-action` would also have written is
 * deliberately absent. It is a fallback for installs whose format we cannot
 * identify, and there is no artifact that is right for those: whatever it held,
 * a `.deb` install that reached it would feed an AppImage to `dpkg` and an RPM
 * install would feed one to `rpm`. Leaving it out turns that into
 * `TargetsNotFound`, which `secure_check` already reports on Linux as "no
 * update" — the truth, for an install shape Ember does not publish for.
 */
const LINUX_TARGETS = [
  { target: "linux-x86_64-appimage", extension: ".appimage" },
  { target: "linux-x86_64-deb", extension: ".deb" },
];

/**
 * The release's asset directory, taken from a platform entry already in the
 * manifest rather than rebuilt from the owner, repository and tag.
 *
 * Those entries are written by `tauri-action`, which is the only thing that
 * knows the URL shape it uploaded under, and the hardening step that runs after
 * this one resolves each entry to a local file by reading the last path segment
 * as the asset name. Deriving the Linux URLs from a sibling keeps all four
 * entries in one shape by construction, so a change to that shape cannot leave
 * Windows resolvable and Linux silently broken.
 */
export function releaseAssetBase(manifest) {
  const urls = Object.values(manifest?.platforms ?? {})
    .map((platform) => platform?.url)
    .filter((url) => typeof url === "string" && url !== "");
  if (urls.length === 0) {
    throw new Error(
      "latest.json has no platform entry to take the release asset URL from",
    );
  }

  const bases = new Set(
    urls.map((value) => {
      const url = new URL(value);
      const segments = url.pathname.split("/");
      segments.pop();
      return `${url.origin}${segments.join("/")}`;
    }),
  );
  if (bases.size !== 1) {
    throw new Error(
      `latest.json platforms disagree on their release asset URL: ${[...bases].sort().join(", ")}`,
    );
  }
  return [...bases][0];
}

/** Every file under `directory`, recursively. */
function walkFiles(directory, output = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walkFiles(path, output);
    else if (entry.isFile()) output.push(path);
  }
  return output;
}

/**
 * Pair each Linux target with the one bundle under `directory` that it names,
 * and the detached signature sitting beside it.
 *
 * Recursive because `upload-artifact` keeps the directory structure below the
 * common ancestor of the paths it was given, so the two bundles arrive under
 * `appimage/` and `deb/` rather than side by side.
 *
 * Exactly one match per extension is required. Two AppImages means two builds
 * were collected and nothing here can say which one the signature belongs to;
 * zero means the build produced nothing, and the release would otherwise
 * advertise an asset that was never uploaded.
 */
export function collectLinuxBundles({ directory }) {
  if (!existsSync(directory) || !statSync(directory).isDirectory()) {
    throw new Error(`Linux bundle directory ${directory} does not exist`);
  }
  const paths = walkFiles(directory);

  return LINUX_TARGETS.map(({ target, extension }) => {
    const matches = paths.filter((path) =>
      path.toLowerCase().endsWith(extension),
    );
    if (matches.length !== 1) {
      throw new Error(
        `expected exactly one ${extension} bundle under ${directory}, found ${matches.length}`,
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
    return { target, name, signature };
  });
}

/**
 * Add the Linux entries to a manifest `tauri-action` has already written the
 * Windows ones into.
 *
 * Only `url` and `signature` are set, which is the whole of what `tauri-action`
 * writes for a platform. `target`, `sha256` and `size` are added afterwards by
 * `harden-update-manifest.mjs`, from the artifact bytes themselves, so that
 * every entry in the finished manifest is bound the same way no matter which
 * runner built it.
 */
export function addLinuxPlatforms({ manifest, bundles, assetBase }) {
  // Every `linux-` entry is dropped first, so this rewrites rather than adds.
  //
  // A re-run of the signing job does not start from a clean manifest:
  // `tauri-action` seeds `platforms` from the `latest.json` already attached to
  // the release, so a retry after a failed upload finds the previous attempt's
  // Linux entries carried straight back in. Refusing them — which this did —
  // made a retried release unrecoverable without deleting that asset by hand,
  // and keeping them would leave the previous run's signature against this
  // run's bytes. Clearing the whole prefix also removes a bare `linux-x86_64`
  // if anything ever writes one, which is the key this deliberately omits.
  //
  // The base URL is read after the clear so it can only come from an entry
  // `tauri-action` wrote during this run.
  for (const target of Object.keys(manifest.platforms)) {
    if (target.startsWith("linux-")) delete manifest.platforms[target];
  }
  const base = assetBase ?? releaseAssetBase(manifest);
  for (const { target, name, signature } of bundles) {
    manifest.platforms[target] = {
      url: `${base}/${encodeURIComponent(name)}`,
      signature,
    };
  }
  return manifest;
}

function main() {
  const manifestPath = resolve(
    root,
    process.env.EMBER_UPDATE_MANIFEST ?? "latest.json",
  );
  const directory = process.env.EMBER_LINUX_BUNDLE_DIR;
  if (!directory) {
    throw new Error("EMBER_LINUX_BUNDLE_DIR must name the Linux bundle directory");
  }

  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const bundles = collectLinuxBundles({ directory: resolve(root, directory) });
  addLinuxPlatforms({ manifest, bundles });
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  console.log(
    `added ${bundles.map(({ target }) => target).join(", ")} to ${manifestPath}`,
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
