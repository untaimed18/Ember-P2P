import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

/**
 * The room composer and message editor refuse a line the backend would refuse
 * only while they hold the backend's numbers. Rust pins its own to the frames
 * it builds (`the_frontends_line_limits_are_where_the_frames_stop_fitting` in
 * `commands/channels.rs`), but that runs under `cargo test` alone; this makes a
 * divergence visible to `npm test` too. A frontend limit above the backend's
 * lets a user type a line the counter calls fine and have it refused on send;
 * one below it refuses lines that would have gone out.
 */
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rustCommands = readFileSync(
  join(root, "src-tauri", "src", "commands", "channels.rs"),
  "utf8",
);
const rustChannel = readFileSync(
  join(root, "src-tauri", "src", "network", "ember", "channel.rs"),
  "utf8",
);
const api = readFileSync(join(root, "src", "lib", "api", "channels.ts"), "utf8");
const conversation = readFileSync(
  join(root, "src", "lib", "components", "ChatConversation.svelte"),
  "utf8",
);

function rustConst(source, name, file) {
  const found = source.match(new RegExp(`const ${name}: usize = ([\\d_]+);`));
  assert.ok(found, `${file} no longer declares ${name} as a number`);
  return Number(found[1].replaceAll("_", ""));
}

function tsConst(name) {
  const found = api.match(new RegExp(`export const ${name} = ([\\d_]+);`));
  assert.ok(found, `src/lib/api/channels.ts no longer exports ${name} as a number`);
  return Number(found[1].replaceAll("_", ""));
}

for (const name of ["CHANNEL_LINE_MAX_TEXT_BYTES", "CHANNEL_EDIT_MAX_TEXT_BYTES"]) {
  test(`${name} is the same in Rust and TypeScript`, () => {
    assert.equal(
      tsConst(name),
      rustConst(rustCommands, name, "src-tauri/src/commands/channels.rs"),
    );
  });
}

test("REPLY_REFERENCE_BYTES is Rust's REPLY_TRAILER_BYTES", () => {
  const chars = rustChannel.match(/pub const REPLY_TRAILER_CHARS: usize = ([\d+ ]+);/);
  assert.ok(chars, "network/ember/channel.rs no longer declares REPLY_TRAILER_CHARS as a sum");
  const perChar = rustChannel.match(
    /pub const REPLY_TRAILER_BYTES: usize = REPLY_TRAILER_CHARS \* (\d+);/,
  );
  assert.ok(perChar, "network/ember/channel.rs no longer derives REPLY_TRAILER_BYTES from REPLY_TRAILER_CHARS");
  const sum = chars[1].split("+").reduce((total, term) => total + Number(term.trim()), 0);
  assert.equal(tsConst("REPLY_REFERENCE_BYTES"), sum * Number(perChar[1]));
});

test("the room composer and editor measure against these limits", () => {
  // Guards the use as well as the numbers: a guard drifting back to the
  // 4096-byte text cap would pass every check above.
  assert.match(
    conversation,
    /CHANNEL_LINE_MAX_TEXT_BYTES\s*-\s*\(reply \? REPLY_REFERENCE_BYTES : 0\)/,
    "ChatConversation.svelte's send guard no longer uses CHANNEL_LINE_MAX_TEXT_BYTES",
  );
  assert.match(
    conversation,
    /CHANNEL_EDIT_MAX_TEXT_BYTES\s*-\s*\(msg\.reply_to \? REPLY_REFERENCE_BYTES : 0\)/,
    "ChatConversation.svelte's editor limit no longer uses CHANNEL_EDIT_MAX_TEXT_BYTES",
  );
});
