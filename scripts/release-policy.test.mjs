import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { hardenManifest } from "./harden-update-manifest.mjs";
import {
  verifyReleasePolicy,
  verifySecurityEpoch,
  verifyVersions,
  verifyWorkflow,
} from "./verify-release-policy.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageVersion = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
).version;
const policyFiles = [
  "package.json",
  "package-lock.json",
  "src-tauri/tauri.conf.json",
  "src-tauri/Cargo.toml",
  "src-tauri/Cargo.lock",
  ".github/workflows/release.yml",
  "src-tauri/src/commands/updater.rs",
];

function policyFixture() {
  const fixture = mkdtempSync(join(tmpdir(), "ember-release-policy-"));
  for (const relativePath of policyFiles) {
    const destination = join(fixture, relativePath);
    mkdirSync(dirname(destination), { recursive: true });
    copyFileSync(join(root, relativePath), destination);
  }
  return fixture;
}

function writeManifestFixture(fixture, platformUrl) {
  const artifactPath = join(fixture, "Ember_1.2.3_x64-setup.nsis.zip");
  const artifact = Buffer.from("safe local updater fixture");
  writeFileSync(artifactPath, artifact);
  const manifestPath = join(fixture, "latest.json");
  writeFileSync(
    manifestPath,
    `${JSON.stringify({
      version: "1.2.3",
      notes: "fixture",
      pub_date: "2026-07-24T00:00:00Z",
      platforms: {
        "windows-x86_64-nsis": {
          url: platformUrl,
          signature: "signed-artifact-fixture",
        },
      },
    })}\n`,
  );
  return { artifactPath, artifact, manifestPath };
}

test("repository release versions and workflow policy agree", () => {
  const result = verifyReleasePolicy({
    root,
    tag: `v${packageVersion}`,
    requireTag: true,
  });
  assert.equal(result.version, packageVersion);
  assert.equal(result.securityEpoch, 1);
  assert.ok(result.actions > 0);
});

test("security epoch stays aligned between workflow and updater", () => {
  assert.equal(verifySecurityEpoch({ root }), 1);

  const fixture = policyFixture();
  try {
    const updaterPath = join(fixture, "src-tauri/src/commands/updater.rs");
    const updater = readFileSync(updaterPath, "utf8").replace(
      /const CURRENT_SECURITY_EPOCH:\s*u64\s*=\s*\d+\s*;/,
      "const CURRENT_SECURITY_EPOCH: u64 = 9;",
    );
    writeFileSync(updaterPath, updater);
    assert.throws(
      () => verifySecurityEpoch({ root: fixture }),
      /security epoch mismatch/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("version policy rejects stale package-lock root metadata", () => {
  const fixture = policyFixture();
  try {
    const lockPath = join(fixture, "package-lock.json");
    const lock = JSON.parse(readFileSync(lockPath, "utf8"));
    lock.packages[""].version = "0.0.1";
    writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
    assert.throws(
      () =>
        verifyVersions({
          root: fixture,
          tag: `v${packageVersion}`,
          requireTag: true,
        }),
      /package-lock\.json root package/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("workflow policy rejects mutable action references", () => {
  const fixture = policyFixture();
  try {
    const workflowPath = join(fixture, ".github/workflows/release.yml");
    const workflow = readFileSync(workflowPath, "utf8").replace(
      /actions\/checkout@[0-9a-f]{40}/,
      "actions/checkout@v4",
    );
    writeFileSync(workflowPath, workflow);
    assert.throws(
      () => verifyWorkflow({ root: fixture }),
      /not pinned to a full lowercase commit SHA/,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("manifest hardening binds target, size, hash, and security epoch", () => {
  const fixture = mkdtempSync(join(tmpdir(), "ember-update-manifest-"));
  try {
    const { artifactPath, artifact, manifestPath } = writeManifestFixture(
      fixture,
      `https://example.invalid/${encodeURIComponent(
        "Ember_1.2.3_x64-setup.nsis.zip",
      )}`,
    );

    const hardened = hardenManifest({
      manifestPath,
      artifactPaths: [artifactPath],
      securityEpoch: 1,
    });
    const platform = hardened.platforms["windows-x86_64-nsis"];
    assert.equal(hardened.security_epoch, 1);
    assert.equal(platform.target, "windows-x86_64-nsis");
    assert.equal(platform.size, artifact.length);
    assert.equal(
      platform.sha256,
      createHash("sha256").update(artifact).digest("hex"),
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("manifest hardening rejects unsafe artifact URLs", () => {
  for (const platformUrl of [
    `http://example.invalid/${encodeURIComponent("Ember_1.2.3_x64-setup.nsis.zip")}`,
    `https://user:pass@example.invalid/${encodeURIComponent("Ember_1.2.3_x64-setup.nsis.zip")}`,
    `https://example.invalid/${encodeURIComponent("Ember_1.2.3_x64-setup.nsis.zip")}#frag`,
  ]) {
    const fixture = mkdtempSync(join(tmpdir(), "ember-update-manifest-unsafe-"));
    try {
      const { artifactPath, manifestPath } = writeManifestFixture(
        fixture,
        platformUrl,
      );
      assert.throws(
        () =>
          hardenManifest({
            manifestPath,
            artifactPaths: [artifactPath],
            securityEpoch: 1,
          }),
        /unsafe artifact URL/,
      );
    } finally {
      rmSync(fixture, { recursive: true, force: true });
    }
  }
});
