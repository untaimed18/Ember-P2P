#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const VERSION_RE = /^\d+\.\d+\.\d+$/;

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

  const effectiveTag = tag ?? process.env.GITHUB_REF_NAME ?? null;
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

export function verifyWorkflow({ root = scriptRoot } = {}) {
  const workflow = read(root, ".github/workflows/release.yml");
  const errors = [];
  const actionLines = [
    ...workflow.matchAll(/^\s*uses:\s*([^@\s]+)@([^\s#]+)(?:\s+#\s*(.+))?$/gm),
  ];

  if (actionLines.length === 0) {
    errors.push("release workflow has no actions to verify");
  }
  for (const [, action, ref, comment] of actionLines) {
    if (!/^[0-9a-f]{40}$/.test(ref)) {
      errors.push(
        `${action} is not pinned to a full lowercase commit SHA (got ${ref})`,
      );
    }
    if (!comment?.trim()) {
      errors.push(
        `${action}@${ref} is missing a human-readable version comment`,
      );
    }
  }

  const checkoutCount = actionLines.filter(
    ([, action]) => action === "actions/checkout",
  ).length;
  const noCredentialCount = (
    workflow.match(/^\s*persist-credentials:\s*false\s*$/gm) ?? []
  ).length;
  if (checkoutCount === 0 || noCredentialCount !== checkoutCount) {
    errors.push("every checkout must set persist-credentials: false");
  }

  const jobsIndex = workflow.indexOf("\njobs:");
  const topLevel = jobsIndex >= 0 ? workflow.slice(0, jobsIndex) : workflow;
  if (!/permissions:\s*\r?\n\s{2}contents:\s*read\b/.test(topLevel)) {
    errors.push("top-level permissions must be contents: read");
  }
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
  return actionLines.length;
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

export function verifyReleasePolicy(options = {}) {
  const version = verifyVersions(options);
  const actions = verifyWorkflow(options);
  const securityEpoch = verifySecurityEpoch(options);
  return { version, actions, securityEpoch };
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
    console.log(
      `release policy verified: version ${result.version}, security epoch ${result.securityEpoch}, ${result.actions} SHA-pinned action uses`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
