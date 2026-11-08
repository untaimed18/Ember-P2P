#!/usr/bin/env node
// eD2K links for a release's installers, for people who cannot reach GitHub.
//
// Runs in `sign-publish`, beside the signing key, so it uses nothing but Node
// itself: MD4 is written out here because OpenSSL 3 no longer offers it, and
// the AICH tree is a port of `src-tauri/src/network/ed2k/aich.rs`. Both are
// held to the hashes Ember itself computes for the same files
// (`the_release_script_hashes_installers_as_ember_does` in that file, and
// `scripts/ed2k-links.test.mjs`), so a link from here is one Ember, eMule and
// aMule all agree on.
//
// It writes, into `EMBER_ED2K_OUT_DIR`, the files attached to the release:
//   Ember_<version>_release-notes.md      the notes, so the collection can carry them
//   Ember_<version>.emulecollection       every installer and the notes, binary format
//   Ember_<version>_downloads.json        name, size, SHA-256, ed2k, AICH and link of each,
//                                         which `scripts/website-downloads.mjs` reads
// and, to `EMBER_ED2K_SECTION`, the Markdown appended to the release body.
//
// Each link carries the file's AICH root (`h=`) and its GitHub download as a
// web source (`s=`), which Ember and eMule fetch from when it is reachable and
// skip when it is not. Integrity rests on the hashes, not on who serves the
// bytes: the website and the release body list each file's SHA-256.
import { createHash } from "node:crypto";
import {
  appendFileSync,
  closeSync,
  existsSync,
  mkdirSync,
  openSync,
  readdirSync,
  readSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** eD2K part size, and the AICH block size within a part. */
export const PART_SIZE = 9_728_000;
export const AICH_BLOCK_SIZE = 184_320;

// --- MD4 (RFC 1320) --------------------------------------------------------

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/** Streaming MD4. */
export class Md4 {
  constructor() {
    this.state = new Int32Array([0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476]);
    this.block = new Uint8Array(64);
    this.used = 0;
    this.length = 0;
    this.words = new Int32Array(16);
  }

  update(data) {
    let offset = 0;
    this.length += data.length;
    if (this.used > 0) {
      const take = Math.min(64 - this.used, data.length);
      this.block.set(data.subarray(0, take), this.used);
      this.used += take;
      offset = take;
      if (this.used < 64) return this;
      this.#compress(this.block, 0);
      this.used = 0;
    }
    for (; offset + 64 <= data.length; offset += 64) this.#compress(data, offset);
    if (offset < data.length) {
      this.block.set(data.subarray(offset), 0);
      this.used = data.length - offset;
    }
    return this;
  }

  digest() {
    const bits = this.length * 8;
    const tail = new Uint8Array(this.used < 56 ? 64 : 128);
    tail.set(this.block.subarray(0, this.used));
    tail[this.used] = 0x80;
    const end = tail.length - 8;
    const low = bits >>> 0;
    const high = Math.floor(bits / 0x1_0000_0000) >>> 0;
    for (let i = 0; i < 4; i++) {
      tail[end + i] = (low >>> (8 * i)) & 0xff;
      tail[end + 4 + i] = (high >>> (8 * i)) & 0xff;
    }
    for (let offset = 0; offset < tail.length; offset += 64) this.#compress(tail, offset);
    const out = Buffer.alloc(16);
    for (let i = 0; i < 4; i++) out.writeInt32LE(this.state[i], i * 4);
    return out;
  }

  #compress(data, offset) {
    const x = this.words;
    for (let i = 0; i < 16; i++) {
      const at = offset + i * 4;
      x[i] = data[at] | (data[at + 1] << 8) | (data[at + 2] << 16) | (data[at + 3] << 24);
    }
    let [a, b, c, d] = this.state;
    const f = (p, q, r) => (p & q) | (~p & r);
    const g = (p, q, r) => (p & q) | (p & r) | (q & r);
    const h = (p, q, r) => p ^ q ^ r;
    for (let i = 0; i < 16; i += 4) {
      a = rotl((a + f(b, c, d) + x[i]) | 0, 3);
      d = rotl((d + f(a, b, c) + x[i + 1]) | 0, 7);
      c = rotl((c + f(d, a, b) + x[i + 2]) | 0, 11);
      b = rotl((b + f(c, d, a) + x[i + 3]) | 0, 19);
    }
    for (let i = 0; i < 4; i++) {
      a = rotl((a + g(b, c, d) + x[i] + 0x5a827999) | 0, 3);
      d = rotl((d + g(a, b, c) + x[i + 4] + 0x5a827999) | 0, 5);
      c = rotl((c + g(d, a, b) + x[i + 8] + 0x5a827999) | 0, 9);
      b = rotl((b + g(c, d, a) + x[i + 12] + 0x5a827999) | 0, 13);
    }
    for (const i of [0, 2, 1, 3]) {
      a = rotl((a + h(b, c, d) + x[i] + 0x6ed9eba1) | 0, 3);
      d = rotl((d + h(a, b, c) + x[i + 8] + 0x6ed9eba1) | 0, 9);
      c = rotl((c + h(d, a, b) + x[i + 4] + 0x6ed9eba1) | 0, 11);
      b = rotl((b + h(c, d, a) + x[i + 12] + 0x6ed9eba1) | 0, 15);
    }
    this.state[0] += a;
    this.state[1] += b;
    this.state[2] += c;
    this.state[3] += d;
  }
}

export const md4 = (data) => new Md4().update(data).digest();

// --- AICH tree (aich.rs) ---------------------------------------------------

const sha1 = (...parts) => {
  const hash = createHash("sha1");
  for (const part of parts) hash.update(part);
  return hash.digest();
};

/** `build_tree_recursive`: eMule splits `(n + isLeft) / 2` to the left. */
function aichTree(leaves, isLeft) {
  if (leaves.length <= 1) return leaves[0] ?? sha1();
  const left = Math.floor((leaves.length + (isLeft ? 1 : 0)) / 2);
  return sha1(aichTree(leaves.slice(0, left), true), aichTree(leaves.slice(left), false));
}

/** `compute_part_is_left`: each part's branch in the top-level tree. */
function partIsLeft(parts) {
  const out = new Array(parts).fill(false);
  const walk = (start, length, isLeft) => {
    if (length === 0) return;
    if (length === 1) {
      out[start] = isLeft;
      return;
    }
    const left = Math.floor((length + (isLeft ? 1 : 0)) / 2);
    walk(start, left, true);
    walk(start + left, length - left, false);
  };
  walk(0, parts, true);
  return out;
}

/** `hierarchical_root`, from the per-part block leaves. */
function aichRoot(partLeaves, size) {
  const all = partLeaves.flat();
  if (all.length === 0) return sha1();
  if (all.length === 1) return all[0];
  const parts = Math.ceil(size / PART_SIZE);
  if (parts <= 1) return aichTree(all, true);
  const branches = partIsLeft(parts);
  const partHashes = partLeaves.map((leaves, part) =>
    leaves.length === 1 ? leaves[0] : aichTree(leaves, branches[part]),
  );
  return aichTree(partHashes, true);
}

// --- One pass over a file --------------------------------------------------

/**
 * SHA-256, eD2K and AICH of a file fed in chunks, in one pass.
 *
 * eD2K: one MD4 per part, then MD4 of the part hashes, with the MD4 of an
 * empty part appended when the size is an exact multiple of a part; a file
 * smaller than a part is its own MD4 (`ed2k_hash_bytes`). AICH: SHA-1 per
 * block, blocks restarting at every part boundary (`hash_leaves_from_reader`).
 */
export class ReleaseHasher {
  constructor() {
    this.size = 0;
    this.sha256 = createHash("sha256");
    this.part = new Md4();
    this.partFill = 0;
    this.partHashes = [];
    this.block = createHash("sha1");
    this.blockFill = 0;
    this.leaves = [[]];
  }

  update(data) {
    this.sha256.update(data);
    this.size += data.length;
    let offset = 0;
    while (offset < data.length) {
      const take = Math.min(
        data.length - offset,
        PART_SIZE - this.partFill,
        AICH_BLOCK_SIZE - this.blockFill,
      );
      const slice = data.subarray(offset, offset + take);
      this.part.update(slice);
      this.block.update(slice);
      this.partFill += take;
      this.blockFill += take;
      offset += take;
      if (this.blockFill === AICH_BLOCK_SIZE || this.partFill === PART_SIZE) {
        this.leaves.at(-1).push(this.block.digest());
        this.block = createHash("sha1");
        this.blockFill = 0;
      }
      if (this.partFill === PART_SIZE) {
        this.partHashes.push(this.part.digest());
        this.part = new Md4();
        this.partFill = 0;
        this.leaves.push([]);
      }
    }
    return this;
  }

  finish() {
    if (this.blockFill > 0) this.leaves.at(-1).push(this.block.digest());
    if (this.leaves.at(-1).length === 0) this.leaves.pop();
    let ed2k;
    if (this.size < PART_SIZE) {
      ed2k = this.part.digest();
    } else {
      const parts = [...this.partHashes];
      // A trailing partial part, or the empty one an exact multiple carries.
      parts.push(this.part.digest());
      ed2k = md4(Buffer.concat(parts));
    }
    return {
      size: this.size,
      sha256: this.sha256.digest("hex"),
      ed2k: ed2k.toString("hex"),
      aich: aichRoot(this.leaves, this.size).toString("hex"),
    };
  }
}

export function hashBuffer(data) {
  return new ReleaseHasher().update(data).finish();
}

export function hashFile(path) {
  const hasher = new ReleaseHasher();
  const buffer = Buffer.alloc(1024 * 1024);
  const fd = openSync(path, "r");
  try {
    for (;;) {
      const read = readSync(fd, buffer, 0, buffer.length, null);
      if (read === 0) break;
      hasher.update(buffer.subarray(0, read));
    }
  } finally {
    closeSync(fd);
  }
  return hasher.finish();
}

// --- Links and collections (hash.rs, collection.rs) ------------------------

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, upper case, unpadded: the form of an ed2k link's `h=`. */
export function base32(bytes) {
  let out = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(buffer << (5 - bits)) & 31];
  return out;
}

const UNRESERVED = /[A-Za-z0-9\-_.~()[\]!',;@]/;

/** `percent_encode_ed2k`: everything else, `|` included, as `%XX` of its UTF-8. */
export function encodeLinkName(name) {
  let out = "";
  for (const byte of Buffer.from(name, "utf8")) {
    const char = String.fromCharCode(byte);
    out += byte < 0x80 && UNRESERVED.test(char)
      ? char
      : `%${byte.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

/** `format_ed2k_link_ext`, with web sources as eMule's `s=` fields. */
export function ed2kLink({ name, size, ed2k, aich, webSources = [] }) {
  let link = `ed2k://|file|${encodeLinkName(name)}|${size}|${ed2k.toUpperCase()}|`;
  if (aich) link += `h=${base32(Buffer.from(aich, "hex"))}|`;
  for (const url of webSources) {
    if (url.includes("|")) throw new Error(`a web source cannot contain "|": ${url}`);
    link += `s=${url}|`;
  }
  return `${link}/`;
}

const FT_FILENAME = 0x01;
const FT_FILESIZE = 0x02;
const FT_AICH_HASH = 0x27;
const FT_FILEHASH = 0x28;
const FT_COLLECTIONAUTHOR = 0x31;
const FT_EMBER_NOTE = 0xe3;
const TAG_HASH = 0x01;
const TAG_STRING = 0x02;
const TAG_UINT32 = 0x03;
const TAG_UINT64 = 0x0b;

function u32(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(value);
  return out;
}

function stringTag(id, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > 0xffff) throw new Error(`collection text is too long: ${value.slice(0, 40)}…`);
  const head = Buffer.from([TAG_STRING | 0x80, id, bytes.length & 0xff, bytes.length >> 8]);
  return Buffer.concat([head, bytes]);
}

function sizeTag(size) {
  if (size > 0xffff_ffff) {
    const value = Buffer.alloc(8);
    value.writeBigUInt64LE(BigInt(size));
    return Buffer.concat([Buffer.from([TAG_UINT64 | 0x80, FT_FILESIZE]), value]);
  }
  return Buffer.concat([Buffer.from([TAG_UINT32 | 0x80, FT_FILESIZE]), u32(size)]);
}

/**
 * A binary `.emulecollection` (version 2), as `Collection::to_binary_bytes`
 * writes it: eMule's compact tags, the AICH root in base32, and Ember's note
 * tag, which eMule skips as it does any tag id it does not know.
 */
export function binaryCollection({ name, author, files }) {
  const header = [stringTag(FT_FILENAME, name), stringTag(FT_COLLECTIONAUTHOR, author)];
  const parts = [u32(2), u32(header.length), ...header, u32(files.length)];
  for (const file of files) {
    const tags = [
      stringTag(FT_FILENAME, file.name),
      sizeTag(file.size),
      Buffer.concat([Buffer.from([TAG_HASH | 0x80, FT_FILEHASH]), Buffer.from(file.ed2k, "hex")]),
      stringTag(FT_AICH_HASH, base32(Buffer.from(file.aich, "hex"))),
    ];
    if (file.note) tags.push(stringTag(FT_EMBER_NOTE, file.note));
    parts.push(u32(tags.length), ...tags);
  }
  return Buffer.concat(parts);
}

// --- The release -----------------------------------------------------------

/** The installers a release carries, in the order the website lists them. */
export const INSTALLERS = [
  { kind: "windows-installer", label: "Windows 10/11 (64-bit), installer", matches: (n) => n.endsWith("-setup.exe") },
  { kind: "windows-msi", label: "Windows 10/11 (64-bit), MSI", matches: (n) => n.endsWith(".msi") },
  { kind: "linux-deb", label: "Linux x86-64, .deb", matches: (n) => n.endsWith(".deb") },
  { kind: "linux-appimage", label: "Linux x86-64, AppImage", matches: (n) => n.endsWith(".appimage") },
];

function walkFiles(directory, out = []) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walkFiles(path, out);
    else if (entry.isFile()) out.push(path);
  }
  return out;
}

/** Exactly one of each installer under `directories`, signatures aside. */
export function collectInstallers(directories) {
  const paths = directories.flatMap((directory) => {
    if (!existsSync(directory) || !statSync(directory).isDirectory()) {
      throw new Error(`bundle directory ${directory} does not exist`);
    }
    return walkFiles(directory);
  }).filter((path) => !path.toLowerCase().endsWith(".sig"));
  return INSTALLERS.map((installer) => {
    const found = paths.filter((path) => installer.matches(basename(path).toLowerCase()));
    if (found.length !== 1) {
      throw new Error(`expected exactly one ${installer.kind} bundle, found ${found.length}`);
    }
    return { ...installer, path: found[0], name: basename(found[0]) };
  });
}

export function releaseDownloadUrl(repository, tag, name) {
  return `https://github.com/${repository}/releases/download/${tag}/${encodeURIComponent(name)}`;
}

function describe(file, repository, tag) {
  const hashes = hashFile(file.path);
  const url = releaseDownloadUrl(repository, tag, file.name);
  return {
    kind: file.kind,
    label: file.label,
    name: file.name,
    ...hashes,
    url,
    link: ed2kLink({ name: file.name, ...hashes, webSources: [url] }),
  };
}

/** Every installer under `bundleDirectories`, hashed and linked. */
export function describeInstallers({ bundleDirectories, repository, tag }) {
  return collectInstallers(bundleDirectories).map((file) => describe(file, repository, tag));
}

/** The Markdown the release body gains. */
export function releaseSection({ installers, notes, collection }) {
  const lines = [
    "",
    "## Download with eD2K",
    "",
    "If GitHub cannot be reached, these links fetch the same files from the eD2K network in Ember, eMule or aMule. Each carries the file's AICH hash, and this release's GitHub download as a web source for when GitHub is reachable. Check what you get against the SHA-256 below.",
    "",
    ...installers.map((file) => `- **${file.label}**\n  \`${file.link}\``),
    `- **Release notes**\n  \`${notes.link}\``,
    `- **All of the above, as an eMule collection** (\`${collection.name}\`)\n  \`${collection.link}\``,
    "",
    "| File | Size | SHA-256 |",
    "|---|---:|---|",
    ...[...installers, notes, collection].map(
      (file) => `| \`${file.name}\` | ${file.size.toLocaleString("en-US")} bytes | \`${file.sha256}\` |`,
    ),
  ];
  return `${lines.join("\n")}\n`;
}

export function prepareRelease({ version, tag, repository, bundleDirectories, outDir, notesText }) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`not a release version: ${version}`);
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw new Error(`not a repository: ${repository}`);
  if (!notesText?.trim()) throw new Error("the release notes are empty");
  mkdirSync(outDir, { recursive: true });

  const installers = describeInstallers({ bundleDirectories, repository, tag });

  const notesName = `Ember_${version}_release-notes.md`;
  writeFileSync(join(outDir, notesName), `# Ember ${version}\n\n${notesText.trim()}\n`);
  const notes = describe(
    { kind: "release-notes", label: "Release notes", path: join(outDir, notesName), name: notesName },
    repository,
    tag,
  );

  const collectionName = `Ember_${version}.emulecollection`;
  const notesFor = {
    "windows-installer": "Windows 10 and 11, 64-bit. The installer most people want.",
    "windows-msi": "Windows 10 and 11, 64-bit. For managed installs.",
    "linux-deb": "Linux x86-64. Install with your package manager.",
    "linux-appimage": "Linux x86-64. Mark it executable and run it; needs FUSE 2.",
    "release-notes": `What is new in Ember ${version}.`,
  };
  writeFileSync(
    join(outDir, collectionName),
    binaryCollection({
      name: `Ember ${version}`,
      author: "Ember",
      files: [...installers, notes].map((file) => ({ ...file, note: notesFor[file.kind] })),
    }),
  );
  const collection = describe(
    { kind: "collection", label: "eMule collection", path: join(outDir, collectionName), name: collectionName },
    repository,
    tag,
  );

  const downloads = { version, tag, installers, notes, collection };
  writeFileSync(join(outDir, `Ember_${version}_downloads.json`), `${JSON.stringify(downloads, null, 2)}\n`);
  return { downloads, section: releaseSection({ installers, notes, collection }) };
}

function main() {
  const tag = process.env.GITHUB_REF_NAME ?? "";
  const repository = process.env.GITHUB_REPOSITORY ?? "";
  const outDir = process.env.EMBER_ED2K_OUT_DIR;
  const sectionPath = process.env.EMBER_ED2K_SECTION;
  const bundleDirectories = [process.env.EMBER_WINDOWS_BUNDLE_DIR, process.env.EMBER_LINUX_BUNDLE_DIR];
  if (!outDir || !sectionPath || bundleDirectories.some((dir) => !dir)) {
    throw new Error(
      "EMBER_ED2K_OUT_DIR, EMBER_ED2K_SECTION, EMBER_WINDOWS_BUNDLE_DIR and EMBER_LINUX_BUNDLE_DIR must all be set",
    );
  }
  const { downloads, section } = prepareRelease({
    version: tag.replace(/^v/, ""),
    tag,
    repository,
    bundleDirectories: bundleDirectories.map((dir) => resolve(root, dir)),
    outDir: resolve(root, outDir),
    notesText: process.env.EMBER_RELEASE_NOTES,
  });
  writeFileSync(sectionPath, section);
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `section=${sectionPath}\n`);
  for (const file of [...downloads.installers, downloads.notes, downloads.collection]) {
    console.log(`${file.name}\n  ${file.link}`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
