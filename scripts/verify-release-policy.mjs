#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { extractReleaseNotes } from "./release-notes.mjs";

const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const RELEASE_TAG_RE = /^v\d+\.\d+\.\d+$/;

/**
 * The release tag from the environment, if this build is running on one.
 *
 * `GITHUB_REF_NAME` is the tag only on a tagged build; on a push to `main` it
 * is `main`, and on a pull request it is `<number>/merge`. Reading those as a
 * tag made every non-release run fail with "expected v1.2.3, got main", which
 * is why the checks below could only ever be run from the release workflow.
 * An explicit `--tag` is honoured exactly as given, mismatch included.
 */
function envReleaseTag() {
  const ref = process.env.GITHUB_REF_NAME;
  return ref && RELEASE_TAG_RE.test(ref) ? ref : null;
}

function read(root, relativePath) {
  return readFileSync(join(root, relativePath), "utf8");
}

function packageTable(toml, relativePath, errors) {
  const header = toml.match(/^\[package\]\s*$/m);
  if (!header) {
    errors.push(`${relativePath}: missing [package] table`);
    return "";
  }
  const afterHeader = toml
    .slice(header.index + header[0].length)
    .replace(/^\r?\n/, "");
  const nextTable = afterHeader.search(/^\[/m);
  return nextTable >= 0 ? afterHeader.slice(0, nextTable) : afterHeader;
}

function tomlString(table, key, relativePath, errors) {
  const match = table.match(new RegExp(`^${key}\\s*=\\s*"([^"]+)"\\s*$`, "m"));
  if (!match) {
    errors.push(`${relativePath}: missing ${key}`);
    return null;
  }
  return match[1];
}

function cargoLockRootVersion(lock, packageName, errors) {
  const blocks = lock.split(/(?=^\[\[package\]\]\s*$)/m);
  const candidates = blocks.filter((block) => {
    const name = block.match(/^name\s*=\s*"([^"]+)"\s*$/m)?.[1];
    return name === packageName;
  });
  if (candidates.length !== 1) {
    errors.push(
      `src-tauri/Cargo.lock: expected one root package named ${packageName}, found ${candidates.length}`,
    );
    return null;
  }
  return tomlString(
    candidates[0],
    "version",
    "src-tauri/Cargo.lock root package",
    errors,
  );
}

export function verifyVersions({
  root = scriptRoot,
  tag = null,
  requireTag = false,
} = {}) {
  const errors = [];
  const packageJson = JSON.parse(read(root, "package.json"));
  const packageLock = JSON.parse(read(root, "package-lock.json"));
  const tauriConfig = JSON.parse(read(root, "src-tauri/tauri.conf.json"));
  const cargoToml = read(root, "src-tauri/Cargo.toml");
  const cargoLock = read(root, "src-tauri/Cargo.lock");
  const cargoPackage = packageTable(cargoToml, "src-tauri/Cargo.toml", errors);
  const cargoName = tomlString(
    cargoPackage,
    "name",
    "src-tauri/Cargo.toml [package]",
    errors,
  );
  const cargoVersion = tomlString(
    cargoPackage,
    "version",
    "src-tauri/Cargo.toml [package]",
    errors,
  );
  const lockRootVersion = cargoName
    ? cargoLockRootVersion(cargoLock, cargoName, errors)
    : null;

  const version = packageJson.version;
  if (typeof version !== "string" || !VERSION_RE.test(version)) {
    errors.push(
      `package.json: version must be exact major.minor.patch, got ${String(version)}`,
    );
  }

  const values = [
    ["package-lock.json top-level", packageLock.version],
    ["package-lock.json root package", packageLock.packages?.[""]?.version],
    ["src-tauri/Cargo.toml [package]", cargoVersion],
    ["src-tauri/Cargo.lock root package", lockRootVersion],
    ["src-tauri/tauri.conf.json", tauriConfig.version],
  ];
  for (const [label, value] of values) {
    if (value !== version) {
      errors.push(`${label}: expected ${version}, got ${String(value)}`);
    }
  }

  const wixVersion = tauriConfig.bundle?.windows?.wix?.version;
  const expectedWix = `${version}.0`;
  if (wixVersion !== expectedWix) {
    errors.push(
      `src-tauri/tauri.conf.json WiX version: expected ${expectedWix}, got ${String(wixVersion)}`,
    );
  }

  const targets = tauriConfig.bundle?.targets;
  const requiredTargets = ["nsis", "msi", "deb", "appimage"];
  if (!Array.isArray(targets)) {
    errors.push("src-tauri/tauri.conf.json bundle.targets must be an array");
  } else {
    for (const target of requiredTargets) {
      if (!targets.includes(target)) {
        errors.push(
          `src-tauri/tauri.conf.json bundle.targets must include ${target}`,
        );
      }
    }
  }

  const effectiveTag = tag ?? envReleaseTag();
  if (requireTag && !effectiveTag) {
    errors.push(
      "release tag is required (pass --tag vX.Y.Z or set GITHUB_REF_NAME)",
    );
  }
  if (effectiveTag) {
    const expectedTag = `v${version}`;
    if (effectiveTag !== expectedTag) {
      errors.push(`release tag: expected ${expectedTag}, got ${effectiveTag}`);
    }
  }

  if (errors.length) {
    throw new Error(`Release version policy failed:\n- ${errors.join("\n- ")}`);
  }
  return version;
}

/** Split `1.2.3` into comparable numbers. */
function parseVersion(version) {
  return version.split(".").map((part) => Number(part));
}

/** -1, 0 or 1 comparing two `major.minor.patch` strings. */
function compareVersions(a, b) {
  const left = parseVersion(a);
  const right = parseVersion(b);
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] < right[index] ? -1 : 1;
  }
  return 0;
}

/** Every `X.Y.Z` release tag in the repository, tag prefix stripped. */
function releaseTags(root) {
  let output;
  try {
    output = execFileSync("git", ["tag", "--list", "v*.*.*"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    // No git, no repository, or no tags: nothing to compare against. Callers
    // treat that as "cannot check" rather than as a failure, so a source
    // tarball build is not blocked by the absence of history.
    return [];
  }
  return output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^v\d+\.\d+\.\d+$/.test(line))
    .map((line) => line.slice(1));
}

/** The highest `vX.Y.Z` tag in the repository, or `null` if there are none. */
function latestReleaseTag(root) {
  const versions = releaseTags(root);
  if (versions.length === 0) return null;
  return versions.reduce((best, next) =>
    compareVersions(next, best) > 0 ? next : best,
  );
}

/**
 * The newest release tag strictly older than `version`.
 *
 * Deliberately not `latestReleaseTag`: the release workflow builds from the tag
 * it is cutting, where the newest tag *is* the declared version, and comparing
 * a release against itself would report no change and skip every check below.
 */
function previousReleaseTag(root, version) {
  const older = releaseTags(root).filter(
    (tag) => compareVersions(tag, version) < 0,
  );
  if (older.length === 0) return null;
  return older.reduce((best, next) =>
    compareVersions(next, best) > 0 ? next : best,
  );
}

/**
 * Between releases the declared version must be higher than the newest release
 * tag.
 *
 * `verifyVersions` only proves the five manifests agree with each other, which
 * they also do when nothing was bumped at all. Ten commits of work once sat on
 * develop still declaring the released version: two builds reported the same
 * number while differing in their DHT wire format and in whether the overlay was
 * on by default, so the updater could not tell them apart and neither could a
 * bug report.
 *
 * On a tagged release (`--require-tag` / `GITHUB_REF_NAME=vX.Y.Z`) this check
 * is skipped: the version must *equal* the tag being cut (enforced by
 * `verifyVersions`), and being ahead of that same tag is impossible.
 */
export function verifyVersionAdvanced({
  root = scriptRoot,
  tag = null,
  requireTag = false,
} = {}) {
  const version = JSON.parse(read(root, "package.json")).version;
  const latest = latestReleaseTag(root);
  if (!latest) return { version, latestTag: null, checked: false };

  const effectiveTag = tag ?? envReleaseTag();
  const cuttingRelease =
    requireTag || (effectiveTag != null && effectiveTag === `v${version}`);
  if (cuttingRelease) {
    return { version, latestTag: latest, checked: false };
  }

  if (compareVersions(version, latest) <= 0) {
    throw new Error(
      `Release version policy failed:\n- package.json version ${version} is not ahead of the ` +
        `latest release tag v${latest}; run \`npm run bump-version <next>\``,
    );
  }
  return { version, latestTag: latest, checked: true };
}

/**
 * Every workflow in the repository, newest-named last.
 *
 * Pinning and default permissions are properties of the whole Actions surface,
 * not of the release workflow alone: a mutable `uses:` in a workflow that runs
 * on pull requests hands the same supply-chain foothold to an attacker, on a
 * machine that shares a repository with the signing job.
 */
function workflowFiles(root) {
  return readdirSync(join(root, ".github", "workflows"))
    .filter((name) => /\.ya?ml$/.test(name))
    .sort()
    .map((name) => ({
      path: `.github/workflows/${name}`,
      source: read(root, `.github/workflows/${name}`),
    }));
}

export function verifyWorkflow({ root = scriptRoot } = {}) {
  const errors = [];
  let actions = 0;

  for (const { path, source } of workflowFiles(root)) {
    const actionLines = [
      ...source.matchAll(/^\s*uses:\s*([^@\s]+)@([^\s#]+)(?:\s+#\s*(.+))?$/gm),
    ];
    if (actionLines.length === 0) {
      errors.push(`${path} has no actions to verify`);
    }
    actions += actionLines.length;
    for (const [, action, ref, comment] of actionLines) {
      if (!/^[0-9a-f]{40}$/.test(ref)) {
        errors.push(
          `${path}: ${action} is not pinned to a full lowercase commit SHA (got ${ref})`,
        );
      }
      if (!comment?.trim()) {
        errors.push(
          `${path}: ${action}@${ref} is missing a human-readable version comment`,
        );
      }
    }

    const checkoutCount = actionLines.filter(
      ([, action]) => action === "actions/checkout",
    ).length;
    const noCredentialCount = (
      source.match(/^\s*persist-credentials:\s*false\s*$/gm) ?? []
    ).length;
    if (checkoutCount === 0 || noCredentialCount !== checkoutCount) {
      errors.push(`${path}: every checkout must set persist-credentials: false`);
    }

    const jobsIndex = source.indexOf("\njobs:");
    const topLevel = jobsIndex >= 0 ? source.slice(0, jobsIndex) : source;
    if (!/permissions:\s*\r?\n\s{2}contents:\s*read\b/.test(topLevel)) {
      errors.push(`${path}: top-level permissions must be contents: read`);
    }
  }

  const workflow = read(root, ".github/workflows/release.yml");
  for (const job of ["verify", "build", "sign-publish"]) {
    if (!new RegExp(`^  ${job}:\\s*$`, "m").test(workflow)) {
      errors.push(`missing ${job} job`);
    }
  }

  const signStart = workflow.search(/^  sign-publish:\s*$/m);
  const signJob = signStart >= 0 ? workflow.slice(signStart) : "";
  if (!/^\s{4}environment:\s*release-signing\s*$/m.test(signJob)) {
    errors.push(
      "sign-publish must use the protected release-signing environment",
    );
  }
  if (!/permissions:\s*\r?\n\s{6}contents:\s*write\b/.test(signJob)) {
    errors.push("only sign-publish may request contents: write");
  }
  if (!/needs:\s*\[verify,\s*build\]/.test(signJob)) {
    errors.push("sign-publish must depend on both verify and build");
  }
  if (!/releaseDraft:\s*true\b/.test(signJob)) {
    errors.push("release must remain a draft");
  }

  const policyGate = signJob.indexOf("Re-verify release policy before secrets");
  const firstSecret = signJob.indexOf("secrets.");
  if (policyGate < 0 || firstSecret < 0 || policyGate > firstSecret) {
    errors.push(
      "the sign-publish policy gate must run before any secret-bearing step",
    );
  }

  if (errors.length) {
    throw new Error(
      `Release workflow policy failed:\n- ${errors.join("\n- ")}`,
    );
  }
  return actions;
}

export function verifySecurityEpoch({ root = scriptRoot } = {}) {
  const errors = [];
  const updaterSource = read(root, "src-tauri/src/commands/updater.rs");
  const workflow = read(root, ".github/workflows/release.yml");

  const rustMatch = updaterSource.match(
    /^\s*const CURRENT_SECURITY_EPOCH:\s*u64\s*=\s*(\d+)\s*;/m,
  );
  if (!rustMatch) {
    errors.push(
      "src-tauri/src/commands/updater.rs: CURRENT_SECURITY_EPOCH constant not found",
    );
  }

  const workflowMatches = [
    ...workflow.matchAll(/^\s*EMBER_UPDATE_SECURITY_EPOCH:\s*"(\d+)"\s*$/gm),
  ];
  if (workflowMatches.length !== 1) {
    errors.push(
      `release.yml: expected exactly one EMBER_UPDATE_SECURITY_EPOCH assignment, found ${workflowMatches.length}`,
    );
  }

  let epoch = null;
  if (rustMatch && workflowMatches.length === 1) {
    const rustEpoch = Number(rustMatch[1]);
    const workflowEpoch = Number(workflowMatches[0][1]);
    if (
      !Number.isSafeInteger(rustEpoch) ||
      rustEpoch < 1 ||
      !Number.isSafeInteger(workflowEpoch) ||
      workflowEpoch < 1
    ) {
      errors.push(
        `security epoch must be a positive safe integer (updater.rs=${rustMatch[1]}, release.yml=${workflowMatches[0][1]})`,
      );
    } else if (rustEpoch !== workflowEpoch) {
      errors.push(
        `security epoch mismatch: updater.rs CURRENT_SECURITY_EPOCH=${rustEpoch}, release.yml EMBER_UPDATE_SECURITY_EPOCH=${workflowEpoch}`,
      );
    } else {
      epoch = rustEpoch;
    }
  }

  if (errors.length) {
    throw new Error(
      `Release security epoch policy failed:\n- ${errors.join("\n- ")}`,
    );
  }
  return epoch;
}

const EMBER_DHT_SOURCE = "src-tauri/src/network/ember/dht/mod.rs";
const EMBER_DHT_VERSION_RE = /^\s*pub const EMBER_DHT_VERSION:\s*u8\s*=\s*(\d+)\s*;/m;

/** `EMBER_DHT_VERSION` as of a given release tag, or `null` if unreadable. */
function emberDhtVersionAtTag(root, tag) {
  let source;
  try {
    source = execFileSync("git", ["show", `v${tag}:${EMBER_DHT_SOURCE}`], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    // The file did not exist at that tag, or there is no git history here.
    return null;
  }
  const match = source.match(EMBER_DHT_VERSION_RE);
  return match ? Number(match[1]) : null;
}

/**
 * A bumped Ember DHT wire version has to be in the release notes.
 *
 * Nothing else connects the two. `docs/ember-dht.md` spells out the
 * consequence: incompatible peers fail cleanly but neither is told why, so a
 * node left on the old version just watches the network shrink as everyone
 * else updates, with nothing in the UI to explain it. The release notes are
 * the only place that can say so, and 1.5.5, 1.5.7 and 1.5.8 all set the
 * precedent by stating the wire version explicitly even when it did not move.
 *
 * Two things are deliberately *not* required here. Whether the section exists
 * at all is `release-notes.test.mjs`'s job, which is what runs at tag time —
 * notes for a freshly bumped version are legitimately unwritten for a while,
 * and failing on that would leave main red between a bump and its changelog.
 * And a repository with no older tag to read simply cannot be checked, which
 * is treated the same way `verifyVersionAdvanced` treats a tagless checkout.
 */
export function verifyEmberDhtVersion({ root = scriptRoot } = {}) {
  const version = JSON.parse(read(root, "package.json")).version;
  const source = read(root, EMBER_DHT_SOURCE);
  const match = source.match(EMBER_DHT_VERSION_RE);
  if (!match) {
    throw new Error(
      `Release Ember DHT policy failed:\n- ${EMBER_DHT_SOURCE}: EMBER_DHT_VERSION constant not found`,
    );
  }
  const wireVersion = Number(match[1]);
  const skipped = { wireVersion, previousWireVersion: null, checked: false };

  const previousTag = previousReleaseTag(root, version);
  if (!previousTag) return skipped;
  const previousWireVersion = emberDhtVersionAtTag(root, previousTag);
  if (previousWireVersion === null) return skipped;
  if (previousWireVersion === wireVersion) {
    return { wireVersion, previousWireVersion, checked: false };
  }

  const html = read(root, "docs/index.html");
  const articleId = `release-${version.split(".").join("-")}`;
  if (!new RegExp(`<article\\b[^>]*id="${articleId}"`, "i").test(html)) {
    return { wireVersion, previousWireVersion, checked: false };
  }

  // Both precedents put the statement in one bullet, so require one line to
  // carry the protocol name and the number rather than hoping two distant
  // mentions are about each other.
  const mentions = new RegExp(String.raw`\b(?:version\s+|v)${wireVersion}\b`, "i");
  const stated = extractReleaseNotes(html, version)
    .split("\n")
    .some((line) => /ember dht/i.test(line) && mentions.test(line));
  if (!stated) {
    throw new Error(
      `Release Ember DHT policy failed:\n- the Ember DHT wire version went from ${previousWireVersion} ` +
        `(v${previousTag}) to ${wireVersion}, but the ${version} notes in docs/index.html never say so; ` +
        `add a bullet naming "Ember DHT" and "version ${wireVersion}", as 1.5.8 did for the unchanged case`,
    );
  }
  return { wireVersion, previousWireVersion, checked: true };
}

export function verifyReleasePolicy(options = {}) {
  const version = verifyVersions(options);
  const { latestTag, checked: versionAdvanced } = verifyVersionAdvanced(options);
  const actions = verifyWorkflow(options);
  const securityEpoch = verifySecurityEpoch(options);
  const emberDht = verifyEmberDhtVersion(options);
  return {
    version,
    latestTag,
    versionAdvanced,
    actions,
    securityEpoch,
    emberDht,
  };
}

function parseArgs(argv) {
  let tag = null;
  let requireTag = false;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--require-tag") {
      requireTag = true;
    } else if (argv[index] === "--tag") {
      tag = argv[index + 1] ?? null;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argv[index]}`);
    }
  }
  return { tag, requireTag };
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    const result = verifyReleasePolicy(parseArgs(process.argv.slice(2)));
    const against = !result.latestTag
      ? "no release tags to compare against"
      : result.versionAdvanced
        ? `ahead of v${result.latestTag}`
        : `release tag matches v${result.version}`;
    console.log(
      `release policy verified: version ${result.version} (${against}), security epoch ${result.securityEpoch}, ` +
        `Ember DHT wire version ${result.emberDht.wireVersion}${result.emberDht.checked ? " (bump documented)" : ""}, ` +
        `${result.actions} SHA-pinned action uses`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
