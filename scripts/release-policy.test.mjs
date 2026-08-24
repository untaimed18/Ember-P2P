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

import {
  collectArtifactPaths,
  hardenManifest,
  parseArtifactPaths,
} from "./harden-update-manifest.mjs";
import {
  verifyEmberDhtVersion,
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
  "src-tauri/src/network/ember/dht/mod.rs",
  "docs/index.html",
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
  try {
    for (const ref of ["main", "42/merge", "release-1.5.6"]) {
      process.env.GITHUB_REF_NAME = ref;
      const result = verifyReleasePolicy({ root });
      assert.equal(result.version, packageVersion);
      if (result.latestTag) {
        assert.equal(
          result.versionAdvanced,
          true,
          `${ref} must leave the version-ahead comparison switched on`,
        );
      }
    }

    // A real tag still selects release semantics: the version has to equal it,
    // so the ahead-of comparison is skipped rather than run against itself.
    process.env.GITHUB_REF_NAME = `v${packageVersion}`;
    assert.equal(verifyReleasePolicy({ root }).versionAdvanced, false);

    // And a tag-shaped ref that disagrees with the manifests is still caught.
    process.env.GITHUB_REF_NAME = "v0.0.1";
    assert.throws(() => verifyReleasePolicy({ root }), /release tag: expected/);
  } finally {
    if (original === undefined) delete process.env.GITHUB_REF_NAME;
    else process.env.GITHUB_REF_NAME = original;
  }
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

const articleId = `release-${packageVersion.split(".").join("-")}`;

function notesArticle(bullets) {
  return `
    <article class="release" id="${articleId}">
      <div class="release-notes">
        <h4>What&rsquo;s New</h4>
        <ul>${bullets.map((text) => `<li>${text}</li>`).join("")}</ul>
      </div>
    </article>`;
}

/**
 * A policy fixture whose `v1.0.0` tag speaks Ember DHT `previous` while the
 * working tree speaks `current`, with the declared version's release notes
 * replaced by `bullets` (or removed entirely when it is `null`).
 *
 * Owning both sides matters: the real checkout only ever exhibits one of these
 * situations at a time, and the interesting one — a bump whose notes forgot to
 * mention it — is by definition not a state the repository should be left in.
 */
function emberDhtFixture({ previous, current, bullets = null }) {
  const fixture = policyFixture();
  const dhtPath = join(fixture, "src-tauri/src/network/ember/dht/mod.rs");
  const setWireVersion = (value) =>
    writeFileSync(
      dhtPath,
      readFileSync(dhtPath, "utf8").replace(
        /pub const EMBER_DHT_VERSION:\s*u8\s*=\s*\d+\s*;/,
        `pub const EMBER_DHT_VERSION: u8 = ${value};`,
      ),
    );

  const docsPath = join(fixture, "docs/index.html");
  const stripped = readFileSync(docsPath, "utf8").replace(
    new RegExp(`<article\\b[^>]*id="${articleId}"[\\s\\S]*?</article>`, "i"),
    "",
  );
  writeFileSync(docsPath, bullets ? stripped + notesArticle(bullets) : stripped);

  setWireVersion(previous);
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
    "ember dht fixture",
  );
  git("tag", "v1.0.0");
  setWireVersion(current);
  return fixture;
}

test("an Ember DHT wire bump has to be stated in the release notes", () => {
  const fixture = emberDhtFixture({
    previous: 2,
    current: 3,
    bullets: [
      "<strong>Transfers.</strong> Failure reasons are translated rather than shown as backend English",
      "<strong>Search.</strong> A wedged diagnostics poll no longer disables the Search button",
    ],
  });
  try {
    assert.throws(
      () => verifyEmberDhtVersion({ root: fixture }),
      /wire version went from 2 .* to 3, but the .* notes .* never say so/s,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("notes that state the new wire version satisfy the check", () => {
  const fixture = emberDhtFixture({
    previous: 2,
    current: 3,
    bullets: [
      "<strong>Ember DHT version 3.</strong> The wire format changed, so this build and older ones will not see each other on the overlay until both sides update",
      "<strong>Search.</strong> A wedged diagnostics poll no longer disables the Search button",
    ],
  });
  try {
    assert.deepEqual(verifyEmberDhtVersion({ root: fixture }), {
      wireVersion: 3,
      previousWireVersion: 2,
      checked: true,
    });
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("an unbumped wire version and unwritten notes are both left alone", () => {
  // Two situations that must never fail a build: nothing moved, and the notes
  // for a freshly bumped version have not been written yet. The second is what
  // `release-notes.test.mjs` covers at tag time; requiring it here would leave
  // main red for the whole gap between a bump and its changelog.
  const unchanged = emberDhtFixture({ previous: 3, current: 3, bullets: null });
  try {
    assert.equal(verifyEmberDhtVersion({ root: unchanged }).checked, false);
  } finally {
    rmSync(unchanged, { recursive: true, force: true });
  }

  const unwritten = emberDhtFixture({ previous: 2, current: 3, bullets: null });
  try {
    assert.deepEqual(verifyEmberDhtVersion({ root: unwritten }), {
      wireVersion: 3,
      previousWireVersion: 2,
      checked: false,
    });
  } finally {
    rmSync(unwritten, { recursive: true, force: true });
  }
});

test("the declared Ember DHT wire version is the one this release ships", () => {
  // Hardcoded like the security epoch above: a bump is supposed to be noticed
  // here, not absorbed by a check that reads whatever the source happens to say.
  assert.equal(verifyEmberDhtVersion({ root }).wireVersion, 3);
});

test("a missing wire-version constant is a hard error, not a skip", () => {
  const fixture = policyFixture();
  try {
    const dhtPath = join(fixture, "src-tauri/src/network/ember/dht/mod.rs");
    writeFileSync(
      dhtPath,
      readFileSync(dhtPath, "utf8").replace(
        /pub const EMBER_DHT_VERSION:\s*u8\s*=\s*\d+\s*;/,
        "pub const EMBER_DHT_WIRE: u8 = 3;",
      ),
    );
    assert.throws(
      () => verifyEmberDhtVersion({ root: fixture }),
      /EMBER_DHT_VERSION constant not found/,
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
