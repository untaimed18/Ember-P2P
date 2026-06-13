#!/usr/bin/env node
// Bump the app version across the three files that MUST stay in lockstep:
//   - package.json
//   - src-tauri/tauri.conf.json
//   - src-tauri/Cargo.toml  ([package] version only)
//
// The Tauri updater compares the running app's version (baked in from
// tauri.conf.json) against the published manifest, so a release that forgets
// any of these would either never offer the update or offer it in a loop.
//
// Usage: node scripts/bump-version.mjs 1.2.3
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const version = process.argv[2];

if (!version || !/^\d+\.\d+\.\d+$/.test(version)) {
  console.error('Usage: node scripts/bump-version.mjs <major.minor.patch>');
  process.exit(1);
}

function updateJson(rel, mutate) {
  const path = join(root, rel);
  const json = JSON.parse(readFileSync(path, 'utf8'));
  mutate(json);
  writeFileSync(path, JSON.stringify(json, null, 2) + '\n');
  console.log(`updated ${rel}`);
}

updateJson('package.json', (j) => {
  j.version = version;
});
updateJson('src-tauri/tauri.conf.json', (j) => {
  j.version = version;
});

// Cargo.toml: replace only the [package] `version = "x.y.z"` line (anchored to
// line start so the many `name = { version = "..." }` dependency specs are
// left untouched).
const cargoPath = join(root, 'src-tauri/Cargo.toml');
const cargo = readFileSync(cargoPath, 'utf8');
const next = cargo.replace(/^version = "\d+\.\d+\.\d+"/m, `version = "${version}"`);
if (next === cargo) {
  console.error('error: could not find [package] version line in src-tauri/Cargo.toml');
  process.exit(1);
}
writeFileSync(cargoPath, next);
console.log('updated src-tauri/Cargo.toml');

console.log(`\nVersion set to ${version}.`);
console.log(`Next: git commit, then \`git tag v${version} && git push origin v${version}\`.`);
