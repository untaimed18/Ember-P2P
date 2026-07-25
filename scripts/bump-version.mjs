#!/usr/bin/env node
// Bump every release version source that MUST stay in lockstep:
//   - package.json
//   - package-lock.json (top-level and root package metadata)
//   - src-tauri/tauri.conf.json (including Windows WiX's 4-part MSI version)
//   - src-tauri/Cargo.toml  ([package] version only)
//   - src-tauri/Cargo.lock  (root package version only)
//
// The Tauri updater compares the running app's version (baked in from
// tauri.conf.json) against the published manifest, so a release that forgets
// any of these would either never offer the update or offer it in a loop.
//
// Usage: node scripts/bump-version.mjs 1.2.3
import {
  existsSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2];

if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error("Usage: node scripts/bump-version.mjs <major.minor.patch>");
  process.exit(1);
}

function updateJson(original, mutate) {
  const json = JSON.parse(original);
  mutate(json);
  return `${JSON.stringify(json, null, 2)}\n`;
}

function replacePackageVersion(toml, relativePath, packageName = null) {
  const blocks = toml.split(/(?=^\[\[?package\]?\]\s*$)/m);
  let replacements = 0;
  const next = blocks
    .map((block) => {
      const isCargoTomlPackage = /^\[package\]\s*$/m.test(block);
      const name = block.match(/^name\s*=\s*"([^"]+)"\s*$/m)?.[1] ?? null;
      if (!isCargoTomlPackage && name !== packageName) return block;
      const replaced = block.replace(
        /^version\s*=\s*"\d+\.\d+\.\d+"\s*$/m,
        `version = "${version}"`,
      );
      if (
        replaced === block &&
        !new RegExp(
          `^version\\s*=\\s*"${version.replaceAll(".", "\\.")}"\\s*$`,
          "m",
        ).test(block)
      ) {
        throw new Error(`${relativePath}: package version line was not found`);
      }
      replacements += 1;
      return replaced;
    })
    .join("");
  if (replacements !== 1) {
    throw new Error(
      `${relativePath}: expected one root package, found ${replacements}`,
    );
  }
  return next;
}

function atomicWriteAll(files) {
  const staged = [];
  try {
    for (const file of files) {
      const temporary = `${file.path}.tmp-${process.pid}-${Date.now()}-${staged.length}`;
      writeFileSync(temporary, file.next, { flag: "wx" });
      staged.push({ ...file, temporary });
    }
    for (const file of staged) renameSync(file.temporary, file.path);
  } catch (error) {
    // All transformations are validated before this function starts. If an
    // unexpected filesystem failure occurs during replacement, restore every
    // original so the release metadata does not remain partially bumped.
    for (const file of files) {
      try {
        writeFileSync(file.path, file.original);
      } catch {
        // Preserve the first error; the caller still gets a failing exit code.
      }
    }
    throw error;
  } finally {
    for (const file of staged) {
      if (existsSync(file.temporary)) unlinkSync(file.temporary);
    }
  }
}

try {
  const relativePaths = [
    "package.json",
    "package-lock.json",
    "src-tauri/tauri.conf.json",
    "src-tauri/Cargo.toml",
    "src-tauri/Cargo.lock",
  ];
  const originals = new Map(
    relativePaths.map((relativePath) => [
      relativePath,
      readFileSync(join(root, relativePath), "utf8"),
    ]),
  );
  const cargoToml = originals.get("src-tauri/Cargo.toml");
  const cargoName = cargoToml.match(
    /^\[package\]\s*\r?\n(?:(?!^\[)[\s\S])*?^name\s*=\s*"([^"]+)"\s*$/m,
  )?.[1];
  if (!cargoName)
    throw new Error("src-tauri/Cargo.toml: root package name was not found");

  const nextByPath = new Map();
  nextByPath.set(
    "package.json",
    updateJson(originals.get("package.json"), (json) => {
      json.version = version;
    }),
  );
  nextByPath.set(
    "package-lock.json",
    updateJson(originals.get("package-lock.json"), (json) => {
      if (!json.packages?.[""]) {
        throw new Error("package-lock.json: root package metadata is missing");
      }
      json.version = version;
      json.packages[""].version = version;
    }),
  );
  nextByPath.set(
    "src-tauri/tauri.conf.json",
    updateJson(originals.get("src-tauri/tauri.conf.json"), (json) => {
      json.version = version;
      json.bundle ??= {};
      json.bundle.windows ??= {};
      json.bundle.windows.wix ??= {};
      json.bundle.windows.wix.version = `${version}.0`;
    }),
  );
  nextByPath.set(
    "src-tauri/Cargo.toml",
    replacePackageVersion(cargoToml, "src-tauri/Cargo.toml"),
  );
  nextByPath.set(
    "src-tauri/Cargo.lock",
    replacePackageVersion(
      originals.get("src-tauri/Cargo.lock"),
      "src-tauri/Cargo.lock",
      cargoName,
    ),
  );

  atomicWriteAll(
    relativePaths.map((relativePath) => ({
      path: join(root, relativePath),
      original: originals.get(relativePath),
      next: nextByPath.get(relativePath),
    })),
  );

  for (const relativePath of relativePaths)
    console.log(`updated ${relativePath}`);
} catch (error) {
  console.error(
    `error: ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exit(1);
}

console.log(`\nVersion set to ${version}.`);
console.log(
  `Next: git commit, then \`git tag v${version} && git push origin v${version}\`.`,
);
