import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src");
const rustRoot = join(root, "src-tauri", "src");

/** The names in `CHAT_WINDOW_DENIED_COMMANDS`. */
function deniedCommands() {
  const text = readFileSync(join(rustRoot, "commands", "chat_window.rs"), "utf8");
  const start = text.indexOf("pub const CHAT_WINDOW_DENIED_COMMANDS");
  const body = text.slice(start, text.indexOf("];", start));
  return [...body.matchAll(/"([a-z0-9_]+)"/g)].map((m) => m[1]);
}

/** Every command name registered with `generate_handler!`. */
function registeredCommands() {
  const text = readFileSync(join(rustRoot, "lib.rs"), "utf8");
  const start = text.indexOf("generate_handler![");
  const body = text.slice(start, text.indexOf("]", start));
  return new Set([...body.matchAll(/::([a-z][a-z0-9_]*)\s*,/g)].map((m) => m[1]));
}

/** The file an import names, `null` for a package, or `undefined` for a
 *  local import that resolves to nothing, which the walk must not skip. */
function resolveImport(from, spec) {
  let base;
  if (spec.startsWith("$lib/")) base = join(src, "lib", spec.slice(5));
  else if (spec.startsWith(".")) base = resolve(dirname(from), spec);
  else return null;
  const stem = base.replace(/\.js$/, "");
  for (const candidate of [
    base,
    `${base}.ts`,
    `${base}.js`,
    `${base}.svelte`,
    `${stem}.ts`,
    join(base, "index.ts"),
    join(base, "index.js"),
    join(base, "index.svelte"),
  ]) {
    if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  }
  return undefined;
}

/** The chat window's own code: what `+layout.svelte` renders in its chat
 *  branch, and everything that imports. The layout's own script returns early
 *  there (`if (chatWindow) return` in its `onMount`), so it is not a root. */
function chatWindowSources() {
  const seen = new Set();
  const unresolved = [];
  const stack = [
    join(src, "lib", "components", "ChatWindowShell.svelte"),
    join(src, "lib", "components", "ErrorBoundary.svelte"),
  ];
  while (stack.length > 0) {
    const file = stack.pop();
    if (seen.has(file) || file.includes("paraglide")) continue;
    seen.add(file);
    const text = readFileSync(file, "utf8");
    const imports = text.matchAll(
      /(?:import|export)\s[^'"`;]*?from\s*['"]([^'"]+)['"]|import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g,
    );
    for (const m of imports) {
      const spec = m[1] ?? m[2] ?? m[3];
      const resolved = resolveImport(file, spec);
      if (resolved === undefined && !spec.includes("paraglide")) {
        unresolved.push(`${spec} in ${file.slice(root.length + 1)}`);
      } else if (resolved) {
        stack.push(resolved);
      }
    }
  }
  assert.deepEqual(unresolved, [], "imports the walk could not follow; teach resolveImport their shape");
  return seen;
}

/** A source file without its whole-line block and `//` comments. Only ones that
 *  start a line: a trailing `//` may be inside a URL on a line that also names
 *  a command, and a `/*` inside a string (`'image/*'`) would hide everything up
 *  to the next comment's end. */
function withoutComments(file) {
  return readFileSync(file, "utf8")
    .replace(/^\s*\/\*[\s\S]*?\*\//gm, "")
    .replace(/^\s*\/\/.*$/gm, "");
}

test("every command the chat window is refused is a registered command", () => {
  const registered = registeredCommands();
  assert.ok(registered.size > 100, "the handler list was not found");
  const unknown = deniedCommands().filter((name) => !registered.has(name));
  assert.deepEqual(unknown, [], "CHAT_WINDOW_DENIED_COMMANDS names commands that do not exist");
});

test("nothing the chat window's code can reach is refused to it", () => {
  const denied = deniedCommands();
  assert.ok(denied.length > 0, "the deny list was not found");
  const reached = [];
  for (const file of chatWindowSources()) {
    const text = withoutComments(file);
    for (const name of denied) {
      if (new RegExp(`['"\`]${name}['"\`]`).test(text)) reached.push(`${name} in ${file.slice(root.length + 1)}`);
    }
  }
  assert.deepEqual(
    reached,
    [],
    "the popped-out chat calls these, and CHAT_WINDOW_DENIED_COMMANDS would refuse them there",
  );
});

/**
 * Commands the chat window never calls that refuse every window but the main
 * one themselves, with `require_main_window`. Mostly ones whose wrapper module
 * the chat imports, so the deny list cannot name them.
 *
 * `rust` is the file under `src-tauri/src` defining the command. `callers` are
 * the frontend functions that reach it, each with the files allowed to name
 * it: its definition, and a helper wrapping it. `labelCheck` marks the older
 * commands that test `window.label()` inline instead of calling the guard.
 *
 * Every command that guards itself must be listed here, so a guard removed
 * later fails the test rather than going unnoticed.
 */
const MAIN_WINDOW_ONLY = [
  { command: "quit_app", rust: "commands/settings.rs", callers: [["quitApp", ["src/lib/api/settings.ts"]]] },
  {
    command: "update_settings",
    rust: "commands/settings.rs",
    callers: [["updateSettings", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "pick_download_folder",
    rust: "commands/settings.rs",
    labelCheck: true,
    callers: [["pickDownloadFolder", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "pick_preview_player",
    rust: "commands/settings.rs",
    labelCheck: true,
    callers: [["pickPreviewPlayer", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "pick_shared_folder",
    rust: "commands/sharing.rs",
    labelCheck: true,
    callers: [["addSharedFolder", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "open_chat_window",
    rust: "commands/chat_window.rs",
    labelCheck: true,
    callers: [
      ["openChatWindow", ["src/lib/api/chatWindow.ts", "src/lib/chatPopout.ts"]],
      ["showChatWindow", ["src/lib/chatPopout.ts", "src/lib/updateResume.ts"]],
    ],
  },
  {
    command: "pick_emule_folder",
    rust: "commands/emule_import.rs",
    labelCheck: true,
    callers: [["pickEmuleFolder", ["src/lib/api/emuleImport.ts"]]],
  },
  {
    command: "open_share_browser",
    rust: "commands/share_browser.rs",
    callers: [["openShareBrowser", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "list_share_browser_children",
    rust: "commands/share_browser.rs",
    callers: [["listShareBrowserChildren", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "navigate_share_browser",
    rust: "commands/share_browser.rs",
    callers: [["navigateShareBrowser", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "share_browser_selection",
    rust: "commands/share_browser.rs",
    callers: [["shareBrowserSelection", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "measure_share_browser_entries",
    rust: "commands/share_browser.rs",
    callers: [["measureShareBrowserEntries", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "close_share_browser",
    rust: "commands/share_browser.rs",
    callers: [["closeShareBrowser", ["src/lib/api/sharing.ts"]]],
  },
  {
    command: "connection_doctor_action",
    rust: "commands/connection_doctor.rs",
    callers: [["connectionDoctorAction", ["src/lib/api/connectionDoctor.ts"]]],
  },
  {
    command: "open_feed_item",
    rust: "commands/feeds.rs",
    callers: [["openFeedItem", ["src/lib/api/feeds.ts"]]],
  },
  {
    command: "show_feed_item",
    rust: "commands/feeds.rs",
    callers: [["showFeedItem", ["src/lib/api/feeds.ts"]]],
  },
  { command: "set_tray_labels", rust: "tray.rs", callers: [["setTrayLabels", ["src/lib/api/system.ts"]]] },
  {
    command: "quit_flush_pending",
    rust: "commands/settings.rs",
    callers: [["finishRequestedQuit", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "finish_requested_quit",
    rust: "commands/settings.rs",
    callers: [["finishRequestedQuit", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "set_pending_undo",
    rust: "commands/settings.rs",
    callers: [["setPendingUndo", ["src/lib/api/settings.ts"]]],
  },
  { command: "hide_to_tray", rust: "commands/settings.rs", callers: [["hideToTray", ["src/lib/api/settings.ts"]]] },
  {
    command: "set_close_behavior",
    rust: "commands/settings.rs",
    callers: [["setCloseBehavior", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "set_quick_limits",
    rust: "commands/settings.rs",
    callers: [["setQuickLimits", ["src/lib/api/settings.ts"]]],
  },
  {
    command: "set_friend_overrides",
    rust: "commands/settings.rs",
    callers: [["setFriendOverrides", ["src/lib/api/settings.ts"]]],
  },
  { command: "open_file", rust: "commands/transfers.rs", callers: [["openFile", ["src/lib/api/transfers.ts"]]] },
  {
    command: "delete_finished_downloads",
    rust: "commands/transfers.rs",
    callers: [["deleteFinishedDownloads", ["src/lib/api/transfers.ts"]]],
  },
  {
    command: "recover_archive",
    rust: "commands/transfers.rs",
    callers: [["recoverArchive", ["src/lib/api/transfers.ts"]]],
  },
  {
    command: "remove_transfer",
    rust: "commands/transfers.rs",
    callers: [["removeTransfer", ["src/lib/api/transfers.ts"]]],
  },
  {
    command: "cancel_transfers_batch",
    rust: "commands/transfers.rs",
    callers: [["cancelTransfersBatch", ["src/lib/api/transfers.ts"]]],
  },
  {
    command: "add_transfer_web_sources",
    rust: "commands/transfers.rs",
    callers: [["addTransferWebSources", ["src/lib/api/transfers.ts"]]],
  },
  {
    command: "download_ipfilter",
    rust: "commands/settings.rs",
    callers: [["downloadIpfilter", ["src/lib/api/settings.ts"]]],
  },
  { command: "add_friend", rust: "commands/peers.rs", callers: [["addFriend", ["src/lib/api/friends.ts"]]] },
  { command: "remove_friend", rust: "commands/peers.rs", callers: [["removeFriend", ["src/lib/api/friends.ts"]]] },
  { command: "block_friend", rust: "commands/peers.rs", callers: [["blockFriend", ["src/lib/api/friends.ts"]]] },
  { command: "unblock_friend", rust: "commands/peers.rs", callers: [["unblockFriend", ["src/lib/api/friends.ts"]]] },
  {
    command: "update_friend_nickname",
    rust: "commands/peers.rs",
    callers: [["updateFriendNickname", ["src/lib/api/friends.ts"]]],
  },
  {
    command: "accept_friend_request",
    rust: "commands/peers.rs",
    callers: [["acceptFriendRequest", ["src/lib/api/friends.ts"]]],
  },
  {
    command: "reject_friend_request",
    rust: "commands/peers.rs",
    callers: [["rejectFriendRequest", ["src/lib/api/friends.ts"]]],
  },
  {
    command: "get_my_ember_hash",
    rust: "commands/peers.rs",
    callers: [["getMyEmberHash", ["src/lib/api/friends.ts"]]],
  },
  {
    command: "reset_friend_code",
    rust: "commands/peers.rs",
    callers: [["resetFriendCode", ["src/lib/api/friends.ts"]]],
  },
  { command: "kad_bootstrap_ip", rust: "commands/peers.rs", callers: [["kadBootstrapIp", ["src/lib/api/kad.ts"]]] },
  {
    command: "delete_owned_channel",
    rust: "commands/channels.rs",
    callers: [["deleteOwnedChannel", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "transfer_channel_ownership",
    rust: "commands/channels.rs",
    callers: [["transferChannelOwnership", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "set_channel_successor_nominee",
    rust: "commands/channels.rs",
    callers: [["setChannelSuccessorNominee", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "claim_channel_ownership",
    rust: "commands/channels.rs",
    callers: [["claimChannelOwnership", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "add_channel_moderator",
    rust: "commands/channels.rs",
    callers: [["addChannelModerator", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "remove_channel_moderator",
    rust: "commands/channels.rs",
    callers: [["removeChannelModerator", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "ban_channel_member",
    rust: "commands/channels.rs",
    callers: [["banChannelMember", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "unban_channel_member",
    rust: "commands/channels.rs",
    callers: [["unbanChannelMember", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "rotate_channel_room_key",
    rust: "commands/channels.rs",
    callers: [["rotateChannelRoomKey", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "rename_channel",
    rust: "commands/channels.rs",
    callers: [["renameChannel", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "claim_channel_username",
    rust: "commands/channels.rs",
    callers: [["claimChannelUsername", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "update_channel_moderation",
    rust: "commands/channels.rs",
    callers: [["updateChannelModeration", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "set_channel_invite_policy",
    rust: "commands/channels.rs",
    callers: [["setChannelInvitePolicy", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "set_channel_slow_mode",
    rust: "commands/channels.rs",
    callers: [["setChannelSlowMode", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "set_channel_announce_only",
    rust: "commands/channels.rs",
    callers: [["setChannelAnnounceOnly", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "set_channel_language",
    rust: "commands/channels.rs",
    callers: [["setChannelLanguage", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "read_clipboard_text",
    rust: "commands/system.rs",
    callers: [
      ["readClipboardText", ["src/lib/api/system.ts", "src/lib/utils.ts"]],
      ["readFromClipboard", ["src/lib/utils.ts"]],
    ],
  },
  {
    command: "silent_update_postpone",
    rust: "auto_update/silent.rs",
    callers: [["silentUpdatePostpone", ["src/lib/stores/silentUpdate.ts"]]],
  },
  {
    command: "silent_update_skip",
    rust: "auto_update/silent.rs",
    callers: [["silentUpdateSkip", ["src/lib/stores/silentUpdate.ts"]]],
  },
  { command: "publish_note", rust: "commands/search.rs", callers: [["publishNote", ["src/lib/api/search.ts"]]] },
  {
    command: "set_file_comment",
    rust: "commands/comments.rs",
    callers: [["setFileComment", ["src/lib/api/comments.ts"]]],
  },
];

/** The body of `fn name(` in a Rust file under `src-tauri/src`, from after
 *  its opening brace up to its closing one. */
function rustFunctionBody(file, name) {
  const text = readFileSync(join(rustRoot, file), "utf8");
  const start = text.search(new RegExp(`\\bfn ${name}\\s*\\(`));
  assert.ok(start >= 0, `${name} was not found in ${file}`);
  const open = text.slice(start).search(/\)\s*(?:->[^{;]*)?\{/);
  assert.ok(open >= 0, `the body of ${name} was not found in ${file}`);
  const bodyStart = text.indexOf("{", start + open) + 1;
  const end = text.indexOf("\n}\n", bodyStart);
  return text.slice(bodyStart, end < 0 ? undefined : end);
}

/** An inline `window.label()` refusal, before anything is awaited. */
function refusesByLabel(body) {
  const check = body.search(/if window\.label\(\) != "main" \{\s*return Err\(/);
  const firstAwait = body.indexOf(".await");
  return check >= 0 && (firstAwait < 0 || check < firstAwait);
}

test("main-window-only commands refuse every other window", () => {
  const registered = registeredCommands();
  // Only comments and `use` items may come before the guard.
  const guardFirst =
    /^(?:\s|\/\/[^\n]*|use\s[^;]+;)*(?:crate::commands::chat_window::)?require_main_window\(&window\)\?;/;
  const unguarded = MAIN_WINDOW_ONLY.filter(({ command, rust, labelCheck }) => {
    assert.ok(registered.has(command), `${command} is not a registered command`);
    const body = rustFunctionBody(rust, command);
    return labelCheck ? !refusesByLabel(body) : !guardFirst.test(body);
  }).map(({ command }) => command);
  assert.deepEqual(unguarded, [], "these must call require_main_window before doing anything");
});

/** Every `.rs` file under `dir`. */
function rustFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return rustFiles(path);
    return entry.name.endsWith(".rs") ? [path] : [];
  });
}

test("every command that refuses other windows is listed as main-window-only", () => {
  const listed = new Set(MAIN_WINDOW_ONLY.map(({ command }) => command));
  const unlisted = [];
  for (const file of rustFiles(rustRoot)) {
    const text = readFileSync(file, "utf8");
    const commands = [
      ...text.matchAll(/#\[tauri::command[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*pub\s+(?:async\s+)?fn\s+([a-z][a-z0-9_]*)/g),
    ];
    for (const [i, m] of commands.entries()) {
      const next = commands[i + 1]?.index ?? text.length;
      const end = text.indexOf("\n}\n", m.index);
      const body = text.slice(m.index, end < 0 || end > next ? next : end);
      if (/require_main_window\(&window\)|window\.label\(\) != "main"/.test(body) && !listed.has(m[1])) {
        unlisted.push(`${m[1]} in ${file.slice(rustRoot.length + 1).replaceAll("\\", "/")}`);
      }
    }
  }
  assert.deepEqual(unlisted, [], "list these in MAIN_WINDOW_ONLY, so removing their guard fails this test");
});

test("every main-window-only command is listed once", () => {
  const seen = new Set();
  const repeated = MAIN_WINDOW_ONLY.map(({ command }) => command).filter((c) => seen.has(c) || !seen.add(c));
  assert.deepEqual(repeated, []);
});

/** The names a file imports `name` under: `import { name as alias }`. */
function importAliases(text, name) {
  return [...text.matchAll(new RegExp(`\\b${name}\\s+as\\s+([A-Za-z_$][\\w$]*)`, "g"))].map((m) => m[1]);
}

/** A file's text without its static import and re-export statements, so a
 *  name only imported is not mistaken for one used. */
function withoutImports(text) {
  return text
    .replace(/\bimport\s+(?:type\s+)?(?:[\w$*\s,]*\{[^}]*\}|[\w$*\s,]+)\s*from\s*['"][^'"]+['"]/g, "")
    .replace(/\bexport\s+(?:type\s+)?\{[^}]*\}\s*from\s*['"][^'"]+['"]/g, "");
}

test("the chat window's code never calls a main-window-only command", () => {
  const called = [];
  for (const file of chatWindowSources()) {
    const relative = file.slice(root.length + 1).replaceAll("\\", "/");
    const text = withoutComments(file);
    const body = withoutImports(text);
    for (const { command, callers } of MAIN_WINDOW_ONLY) {
      // Named directly, as `invoke('command')` would, outside the wrapper's own file.
      const wrapperFiles = callers.flatMap(([, allowed]) => allowed);
      if (!wrapperFiles.includes(relative) && new RegExp(`['"\`]${command}['"\`]`).test(text)) {
        called.push(`${command} by name in ${relative}`);
      }
      for (const [caller, allowed] of callers) {
        if (allowed.includes(relative)) continue;
        // Any use, not only a call: a wrapper handed over as a callback runs too.
        for (const name of [caller, ...importAliases(text, caller)]) {
          if (new RegExp(`(?<![\\w$])${name.replaceAll("$", "\\$")}(?![\\w$])`).test(body)) {
            called.push(`${command} via ${name === caller ? caller : `${caller} as ${name}`} in ${relative}`);
          }
        }
      }
    }
  }
  assert.deepEqual(called, [], "the popped-out chat calls these, and require_main_window would refuse them there");
});
