import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { addLinuxPlatforms, collectLinuxBundles } from "./add-linux-platforms.mjs";
import {
  collectWindowsBundles,
  composeManifest,
  releaseAssetBase,
} from "./compose-update-manifest.mjs";
import { hardenManifest } from "./harden-update-manifest.mjs";

const base = "https://github.com/untaimed18/Ember-P2P/releases/download/v1.2.3";
const setup = "Ember_1.2.3_x64-setup.exe";
const msi = "Ember_1.2.3_x64_en-US.msi";

/**
 * The bundle directories as `sign-publish` sees them after download and
 * signing: `upload-artifact` keeps the structure below the common ancestor, so
 * the installers arrive under `nsis/` and `msi/`.
 */
function releaseFixture() {
  const fixture = mkdtempSync(join(tmpdir(), "ember-compose-manifest-"));
  const windowsDir = join(fixture, "windows-bundles");
  const linuxDir = join(fixture, "linux-bundles");
  const artifacts = [];
  for (const [dir, sub, name] of [
    [windowsDir, "nsis", setup],
    [windowsDir, "msi", msi],
    [linuxDir, "appimage", "Ember_1.2.3_amd64.AppImage"],
    [linuxDir, "deb", "Ember_1.2.3_amd64.deb"],
  ]) {
    mkdirSync(join(dir, sub), { recursive: true });
    const path = join(dir, sub, name);
    writeFileSync(path, `${name} bytes`);
    writeFileSync(`${path}.sig`, `signature for ${name}\n`);
    artifacts.push(path);
  }
  return { fixture, windowsDir, linuxDir, artifacts };
}

function compose(windowsDir) {
  return composeManifest({
    version: "1.2.3",
    notes: "## What's New\n- Things",
    pubDate: "2026-09-25T00:00:00.000Z",
    assetBase: base,
    bundles: collectWindowsBundles({ directory: windowsDir }),
  });
}

test("the Windows targets match what tauri-action wrote", () => {
  const { fixture, windowsDir } = releaseFixture();
  try {
    const manifest = compose(windowsDir);
    assert.equal(manifest.version, "1.2.3");
    assert.equal(manifest.notes, "## What's New\n- Things");
    assert.equal(manifest.pub_date, "2026-09-25T00:00:00.000Z");
    const nsis = { url: `${base}/${setup}`, signature: `signature for ${setup}` };
    assert.deepEqual(manifest.platforms, {
      // The fallback key carries NSIS, as `updaterJsonPreferNsis` did.
      "windows-x86_64": nsis,
      "windows-x86_64-nsis": nsis,
      "windows-x86_64-msi": { url: `${base}/${msi}`, signature: `signature for ${msi}` },
    });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("the composed manifest takes the Linux targets and hardens end to end", () => {
  const { fixture, windowsDir, linuxDir, artifacts } = releaseFixture();
  try {
    const manifest = compose(windowsDir);
    addLinuxPlatforms({ manifest, bundles: collectLinuxBundles({ directory: linuxDir }) });
    assert.equal(
      manifest.platforms["linux-x86_64-deb"].url,
      `${base}/Ember_1.2.3_amd64.deb`,
      "Linux entries share the Windows asset base",
    );
    const manifestPath = join(fixture, "latest.json");
    writeFileSync(manifestPath, JSON.stringify(manifest));
    const hardened = hardenManifest({ manifestPath, artifactPaths: artifacts, securityEpoch: 1 });
    assert.equal(Object.keys(hardened.platforms).length, 5);
    for (const [target, platform] of Object.entries(hardened.platforms)) {
      assert.equal(platform.target, target);
      assert.match(platform.sha256, /^[0-9a-f]{64}$/);
      assert.ok(platform.size > 0);
    }
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("an installer with no signature beside it fails the release", () => {
  const { fixture, windowsDir } = releaseFixture();
  try {
    rmSync(join(windowsDir, "msi", `${msi}.sig`));
    assert.throws(
      () => collectWindowsBundles({ directory: windowsDir }),
      /Ember_1\.2\.3_x64_en-US\.msi has no .* beside it/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("two builds of one installer cannot be collected into a release", () => {
  const { fixture, windowsDir } = releaseFixture();
  try {
    writeFileSync(join(windowsDir, "nsis", "Ember_1.2.2_x64-setup.exe"), "older");
    assert.throws(
      () => collectWindowsBundles({ directory: windowsDir }),
      /expected exactly one -setup\.exe installer .*, found 2/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("the release asset base is built from the repository and tag", () => {
  assert.equal(
    releaseAssetBase({
      serverUrl: "https://github.com",
      repository: "untaimed18/Ember-P2P",
      tag: "v1.2.3",
    }),
    base,
  );
  assert.throws(
    () => releaseAssetBase({ repository: "not a repo", tag: "v1.2.3" }),
    /owner\/repo/,
  );
});

test("a manifest without notes or an exact version is refused", () => {
  const { fixture, windowsDir } = releaseFixture();
  try {
    const bundles = collectWindowsBundles({ directory: windowsDir });
    assert.throws(
      () => composeManifest({ version: "1.2.3", notes: " ", pubDate: "x", assetBase: base, bundles }),
      /release notes are required/,
    );
    assert.throws(
      () => composeManifest({ version: "v1.2.3", notes: "n", pubDate: "x", assetBase: base, bundles }),
      /exact major\.minor\.patch/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
