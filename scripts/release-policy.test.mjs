import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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

import {
  collectArtifactPaths,
  hardenManifest,
  parseArtifactPaths,
} from "./harden-update-manifest.mjs";
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

/**
 * A policy fixture in a throwaway git repository carrying exactly `tags`.
 *
 * The version-ahead ratchet reads `git tag` from the root it is handed, so a
 * test that runs it against the real checkout gets opposite answers depending
 * on where that checkout sits: on `main` the version is ahead of the newest
 * tag, while the release workflow builds from the tag itself, where the version
 * equals it. Owning the tags keeps both situations reachable from either one.
 */
function taggedFixture(tags) {
  const fixture = policyFixture();
  const git = (...args) =>
    execFileSync("git", args, { cwd: fixture, stdio: "ignore" });
  git("init", "--quiet");
  git("add", "--all");
  git(
    "-c",
    "user.email=tests@ember.invalid",
    "-c",
    "user.name=Ember policy tests",
    "-c",
    "commit.gpgsign=false",
    "commit",
    "--quiet",
    "--message",
    "policy fixture",
  );
  for (const tag of tags) git("tag", tag);
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
  assert.equal(result.versionAdvanced, false);
  assert.equal(result.securityEpoch, 1);
  assert.ok(result.actions > 0);
});

test("a branch ref is not mistaken for a release tag", () => {
  // CI runs these gates on `main` and on pull requests, where GITHUB_REF_NAME
  // is a branch name or `<number>/merge`. Reading either as a tag failed every
  // non-release run with "expected vX.Y.Z, got main", which is why the
  // version-ahead ratchet had never actually run anywhere.
  const original = process.env.GITHUB_REF_NAME;
  const fixture = taggedFixture(["v0.0.1"]);
  try {
    for (const ref of ["main", "42/merge", `release-${packageVersion}`]) {
      process.env.GITHUB_REF_NAME = ref;
      const result = verifyReleasePolicy({ root: fixture });
      assert.equal(result.version, packageVersion);
      assert.equal(result.latestTag, "0.0.1");
      assert.equal(
        result.versionAdvanced,
        true,
        `${ref} must leave the version-ahead comparison switched on`,
      );
    }

    // A real tag still selects release semantics: the version has to equal it,
    // so the ahead-of comparison is skipped rather than run against itself.
    process.env.GITHUB_REF_NAME = `v${packageVersion}`;
    assert.equal(
      verifyReleasePolicy({ root: fixture }).versionAdvanced,
      false,
    );

    // And a tag-shaped ref that disagrees with the manifests is still caught.
    process.env.GITHUB_REF_NAME = "v0.0.1";
    assert.throws(
      () => verifyReleasePolicy({ root: fixture }),
      /release tag: expected/,
    );
  } finally {
    if (original === undefined) delete process.env.GITHUB_REF_NAME;
    else process.env.GITHUB_REF_NAME = original;
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("a release build is not failed by the tag it is releasing", () => {
  // The release workflow checks out `vX.Y.Z`, so the declared version equals
  // the newest tag. Asserting branch semantics against the live checkout meant
  // this suite demanded the version be *ahead* of the tag being cut, and the
  // v1.5.6 verify job failed here before a build or a signature ever started.
  const original = process.env.GITHUB_REF_NAME;
  const fixture = taggedFixture([`v${packageVersion}`]);
  try {
    process.env.GITHUB_REF_NAME = `v${packageVersion}`;
    const result = verifyReleasePolicy({ root: fixture });
    assert.equal(result.latestTag, packageVersion);
    assert.equal(result.versionAdvanced, false);

    // Off the tag the very same tree is a version that was already released,
    // which is exactly what the ratchet exists to stop.
    process.env.GITHUB_REF_NAME = "main";
    assert.throws(
      () => verifyReleasePolicy({ root: fixture }),
      /is not ahead of the latest release tag/,
    );
  } finally {
    if (original === undefined) delete process.env.GITHUB_REF_NAME;
    else process.env.GITHUB_REF_NAME = original;
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("the real checkout passes in whichever context CI runs it", () => {
  // Both CI workflows run this suite: `main` and pull requests off a tag, the
  // release workflow on one. Neither may be a checkout the suite fails on.
  const result = verifyReleasePolicy({ root });
  assert.equal(result.version, packageVersion);
  assert.equal(result.securityEpoch, 1);
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

test("version policy requires Linux bundle targets alongside Windows", () => {
  const fixture = policyFixture();
  try {
    const configPath = join(fixture, "src-tauri/tauri.conf.json");
    const config = JSON.parse(readFileSync(configPath, "utf8"));
    config.bundle.targets = ["nsis", "msi"];
    writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
    assert.throws(
      () =>
        verifyVersions({
          root: fixture,
          tag: `v${packageVersion}`,
          requireTag: true,
        }),
      /bundle\.targets must include deb/,
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

test("artifact collection resolves supplied and discovered paths", () => {
  // The release job reaches this through main(), which the hardening tests
  // below bypass by passing artifactPaths directly. A `.map(resolve)` here once
  // failed the signing job on every release while those tests stayed green.
  const fixture = mkdtempSync(join(tmpdir(), "ember-artifact-paths-"));
  try {
    const bundle = join(fixture, "src-tauri/target/release/bundle/nsis");
    mkdirSync(bundle, { recursive: true });
    const discovered = join(bundle, "Ember_1.2.3_x64-setup.nsis.zip");
    writeFileSync(discovered, "discovered");
    const supplied = join(fixture, "Ember_1.2.3_x64-setup.exe");
    writeFileSync(supplied, "supplied");

    const collected = collectArtifactPaths({
      root: fixture,
      suppliedPaths: [supplied, discovered, join(fixture, "absent.zip")],
    });

    assert.deepEqual([...collected].sort(), [discovered, supplied].sort());
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("artifact path parsing accepts JSON and newline-separated output", () => {
  assert.deepEqual(parseArtifactPaths('["/a/one.zip","/b/two.exe"]'), [
    "/a/one.zip",
    "/b/two.exe",
  ]);
  assert.deepEqual(parseArtifactPaths("/a/one.zip\n/b/two.exe"), [
    "/a/one.zip",
    "/b/two.exe",
  ]);
  assert.deepEqual(parseArtifactPaths("  "), []);
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
