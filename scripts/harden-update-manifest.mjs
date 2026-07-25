#!/usr/bin/env node
import {
  appendFileSync,
  existsSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MAX_ARTIFACT_BYTES = 512 * 1024 * 1024;

function normalizeAssetName(path) {
  return basename(path)
    .trim()
    .replace(/[ ()[\]{}]/g, ".")
    .replace(/\.\./g, ".")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "");
}

function parseArtifactPaths(raw) {
  if (!raw?.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.map(String);
    if (typeof parsed === "string") return [parsed];
  } catch {
    // Older @actions/core versions expose multiline outputs as plain text.
  }
  return raw
    .split(/\r?\n|;/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function walkFiles(directory, output = []) {
  if (!existsSync(directory)) return output;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      walkFiles(path, output);
    } else if (entry.isFile()) {
      output.push(path);
    }
  }
  return output;
}

function atomicWrite(path, contents) {
  const temporary = `${path}.tmp-${process.pid}-${Date.now()}`;
  try {
    writeFileSync(temporary, contents, { flag: "wx" });
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function locateArtifact(assetName, candidates) {
  const decodedName = decodeURIComponent(assetName);
  const matches = candidates.filter(
    (path) =>
      basename(path) === decodedName ||
      normalizeAssetName(path) === decodedName,
  );
  if (matches.length !== 1) {
    throw new Error(
      `expected exactly one local artifact for ${decodedName}, found ${matches.length}`,
    );
  }
  return matches[0];
}

export function hardenManifest({
  manifestPath,
  artifactPaths,
  securityEpoch,
} = {}) {
  if (!Number.isSafeInteger(securityEpoch) || securityEpoch < 1) {
    throw new Error(
      "EMBER_UPDATE_SECURITY_EPOCH must be a positive safe integer",
    );
  }

  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (
    typeof manifest.version !== "string" ||
    !/^\d+\.\d+\.\d+$/.test(manifest.version) ||
    !manifest.platforms ||
    typeof manifest.platforms !== "object" ||
    Array.isArray(manifest.platforms) ||
    Object.keys(manifest.platforms).length === 0
  ) {
    throw new Error(
      "latest.json is missing an exact version or platform entries",
    );
  }

  const byArtifact = new Map();
  for (const [target, platform] of Object.entries(manifest.platforms)) {
    if (
      !platform ||
      typeof platform !== "object" ||
      typeof platform.url !== "string" ||
      typeof platform.signature !== "string" ||
      platform.signature.trim() === ""
    ) {
      throw new Error(
        `latest.json platform ${target} is missing its URL or artifact signature`,
      );
    }
    const url = new URL(platform.url);
    if (url.protocol !== "https:" || url.username || url.password || url.hash) {
      throw new Error(
        `latest.json platform ${target} has an unsafe artifact URL`,
      );
    }

    const assetName = url.pathname.split("/").at(-1);
    if (!assetName)
      throw new Error(`latest.json platform ${target} has no asset filename`);
    const artifactPath = locateArtifact(assetName, artifactPaths);
    let metadata = byArtifact.get(artifactPath);
    if (!metadata) {
      const size = statSync(artifactPath).size;
      if (
        !Number.isSafeInteger(size) ||
        size <= 0 ||
        size > MAX_ARTIFACT_BYTES
      ) {
        throw new Error(`artifact ${artifactPath} has invalid size ${size}`);
      }
      const sha256 = createHash("sha256")
        .update(readFileSync(artifactPath))
        .digest("hex");
      metadata = { size, sha256 };
      byArtifact.set(artifactPath, metadata);
    }

    platform.target = target;
    platform.sha256 = metadata.sha256;
    platform.size = metadata.size;
  }

  manifest.security_epoch = securityEpoch;
  atomicWrite(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

function main() {
  const manifestPath = resolve(
    root,
    process.env.EMBER_UPDATE_MANIFEST ?? "latest.json",
  );
  const suppliedPaths = parseArtifactPaths(process.env.TAURI_ARTIFACT_PATHS);
  const discoveredPaths = walkFiles(join(root, "src-tauri", "target"));
  const artifactPaths = [
    ...new Set([...suppliedPaths, ...discoveredPaths].map(resolve)),
  ].filter((path) => existsSync(path) && statSync(path).isFile());
  const securityEpoch = Number(process.env.EMBER_UPDATE_SECURITY_EPOCH);

  hardenManifest({ manifestPath, artifactPaths, securityEpoch });
  console.log(`hardened ${manifestPath} with security epoch ${securityEpoch}`);

  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `manifest=${manifestPath}\n`);
  }
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
