import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ReleaseHasher,
  base32,
  binaryCollection,
  ed2kLink,
  encodeLinkName,
  hashBuffer,
  md4,
  prepareRelease,
} from "./ed2k-links.mjs";

test("MD4 matches RFC 1320", () => {
  const vectors = [
    ["", "31d6cfe0d16ae931b73c59d7e0c089c0"],
    ["a", "bde52cb31de33e46245e05fbdbd6fb24"],
    ["abc", "a448017aaf21d8525fc10ae87aa6729d"],
    ["message digest", "d9130a8164549fe818874806e1c7014b"],
    ["abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"],
    ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"],
    ["1234567890".repeat(8), "e33b4ddc9c38f2199c3e7b164fcc0536"],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(md4(Buffer.from(input)).toString("hex"), expected, JSON.stringify(input));
  }
});

/**
 * The files and hashes `the_release_script_hashes_installers_as_ember_does`
 * (src-tauri/src/network/ed2k/aich.rs) pins Ember's own hashing to.
 */
const VECTORS = [
  [0, "31d6cfe0d16ae931b73c59d7e0c089c0", "da39a3ee5e6b4b0d3255bfef95601890afd80709"],
  [1, "a8deec165ed8ad822e82bc0563574d68", "5d1be7e9dda1ee8896be5b7e34a85ee16452a7b4"],
  [184_319, "ee6d726c83d54b639b0d8c9eef68bffb", "5006ecc755ff60521b4313274e9963e6c9998f31"],
  [184_320, "99ee334be8e5bede81e51d4db0416987", "ec5e0467fdf1e5d8ae0fed4507d582970f4888c6"],
  [184_321, "f33c50dce3bdac4ed8aa22cdc836c15d", "96724d22a5433596242aead93ec72d2ad1ec2f93"],
  [9_727_999, "aa6417ea31b5447f899aa39e739c7ee2", "c5b5843bb938b9ace5f45291fdb816dcd330e192"],
  [9_728_000, "5ad70831b824ead053cf0a8ff867a417", "55904bdda3bca5080511a22be2345ec0198e62da"],
  [9_728_001, "0c98fcd995b4b25efa6c00e93609b7e9", "103edd33024070ab962fd502c8af467a0fe9d82d"],
  [19_456_000, "ec4e51f2c8fff914ca6de048386579e1", "dc300bdc843d9500194f1627dfbf38ee0bab9a8f"],
  [19_640_327, "8444746ea9731f7c7109ea8b992bab71", "a11773b339c1e9b44a16ae29ecc73d5d53f1d900"],
  [58_368_001, "bc82f08bb4f50a6fa073d0aa9811d21a", "73e8a34bed92a37bf781c2bd4afff1efa090bbda"],
  [68_096_000, "fb71f4dbe698742cfad059fa7d1b3a98", "1a34277b7c945beae8be4591d25957241856007f"],
];

test("installers are hashed exactly as Ember hashes them, whatever the read size", () => {
  const largest = Math.max(...VECTORS.map(([length]) => length));
  const data = Buffer.alloc(largest);
  for (let i = 0; i < largest; i++) data[i] = (i * 31 + 7) % 251;
  for (const [length, ed2k, aich] of VECTORS) {
    const file = data.subarray(0, length);
    const whole = hashBuffer(file);
    assert.equal(whole.ed2k, ed2k, `ed2k, ${length} bytes`);
    assert.equal(whole.aich, aich, `AICH, ${length} bytes`);
    assert.equal(whole.size, length);

    // Reads that straddle every block and part boundary somewhere.
    const streamed = new ReleaseHasher();
    for (let offset = 0; offset < length; offset += 65_537) {
      streamed.update(file.subarray(offset, Math.min(length, offset + 65_537)));
    }
    assert.deepEqual(streamed.finish(), whole, `streamed, ${length} bytes`);
  }
});

test("links are written the way hash.rs writes them", () => {
  assert.equal(base32(Buffer.from("foobar")), "MZXW6YTBOI", "RFC 4648, unpadded");
  assert.equal(encodeLinkName("Ember 1.8.0|ü.exe"), "Ember%201.8.0%7C%C3%BC.exe");
  assert.equal(
    ed2kLink({
      name: "Ember_1.8.0_x64-setup.exe",
      size: 5,
      ed2k: "00112233445566778899aabbccddeeff",
      aich: "0123456789abcdef0123456789abcdef01234567",
      webSources: ["https://github.com/o/r/releases/download/v1.8.0/Ember_1.8.0_x64-setup.exe"],
    }),
    "ed2k://|file|Ember_1.8.0_x64-setup.exe|5|00112233445566778899AABBCCDDEEFF|h=AERUKZ4JVPG66AJDIVTYTK6N54ASGRLH|s=https://github.com/o/r/releases/download/v1.8.0/Ember_1.8.0_x64-setup.exe|/",
  );
  assert.throws(() => ed2kLink({ name: "a", size: 1, ed2k: "00".repeat(16), aich: "", webSources: ["https://x/|y"] }));
});

/**
 * Bytes Ember reads back in `a_release_collection_from_the_script_loads_in_ember`
 * (src-tauri/src/network/ed2k/collection.rs).
 */
export const COLLECTION_FIXTURE = {
  name: "Ember 9.9.9",
  author: "Ember",
  files: [
    {
      name: "Ember_9.9.9_x64-setup.exe",
      size: 20_000_000,
      ed2k: "00112233445566778899aabbccddeeff",
      aich: "0123456789abcdef0123456789abcdef01234567",
      note: "Windows 10 and 11, 64-bit.",
    },
    {
      name: "Ember_9.9.9_amd64.AppImage",
      size: 5_000_000_000,
      ed2k: "ffeeddccbbaa99887766554433221100",
      aich: "76543210fedcba9876543210fedcba9876543210",
    },
  ],
};

test("the collection is the binary form Ember reads", () => {
  assert.equal(
    binaryCollection(COLLECTION_FIXTURE).toString("hex"),
    readFileSync(new URL("./fixtures/ember-release.emulecollection.hex", import.meta.url), "utf8").trim(),
  );
});

test("a release gets one link per installer, the notes and a collection of them", () => {
  const dir = mkdtempSync(join(tmpdir(), "ember-ed2k-"));
  try {
    const windows = join(dir, "windows");
    const linux = join(dir, "linux");
    const files = {
      [join(windows, "nsis", "Ember_9.9.9_x64-setup.exe")]: "setup",
      [join(windows, "nsis", "Ember_9.9.9_x64-setup.exe.sig")]: "sig",
      [join(windows, "msi", "Ember_9.9.9_x64_en-US.msi")]: "msi",
      [join(linux, "deb", "Ember_9.9.9_amd64.deb")]: "deb",
      [join(linux, "appimage", "Ember_9.9.9_amd64.AppImage")]: "appimage",
    };
    for (const [path, contents] of Object.entries(files)) {
      mkdirSync(join(path, ".."), { recursive: true });
      writeFileSync(path, contents);
    }
    const out = join(dir, "out");
    const { downloads, section } = prepareRelease({
      version: "9.9.9",
      tag: "v9.9.9",
      repository: "owner/repo",
      bundleDirectories: [windows, linux],
      outDir: out,
      notesText: "### Fixed\n- Things",
    });

    assert.deepEqual(
      downloads.installers.map((file) => file.kind),
      ["windows-installer", "windows-msi", "linux-deb", "linux-appimage"],
    );
    const setup = downloads.installers[0];
    assert.equal(setup.size, 5);
    assert.equal(setup.ed2k, md4(Buffer.from("setup")).toString("hex"));
    assert.equal(setup.url, "https://github.com/owner/repo/releases/download/v9.9.9/Ember_9.9.9_x64-setup.exe");
    assert.ok(setup.link.includes(`|s=${setup.url}|`));
    assert.equal(readFileSync(join(out, "Ember_9.9.9_release-notes.md"), "utf8"), "# Ember 9.9.9\n\n### Fixed\n- Things\n");
    assert.equal(downloads.collection.name, "Ember_9.9.9.emulecollection");
    const saved = JSON.parse(readFileSync(join(out, "Ember_9.9.9_downloads.json"), "utf8"));
    assert.deepEqual(saved, downloads);

    for (const file of [...downloads.installers, downloads.notes, downloads.collection]) {
      assert.ok(section.includes(file.link), `${file.name} is linked`);
      assert.ok(section.includes(file.sha256), `${file.name} has its SHA-256`);
    }

    writeFileSync(join(windows, "nsis", "Ember_9.9.8_x64-setup.exe"), "stale");
    assert.throws(
      () => prepareRelease({ version: "9.9.9", tag: "v9.9.9", repository: "owner/repo", bundleDirectories: [windows, linux], outDir: out, notesText: "x" }),
      /exactly one windows-installer/,
    );
    assert.throws(
      () => prepareRelease({ version: "9.9", tag: "v9.9", repository: "owner/repo", bundleDirectories: [windows, linux], outDir: out, notesText: "x" }),
      /not a release version/,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
