import assert from "node:assert/strict";
import { existsSync, readFileSync, statSync } from "node:fs";
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
    // Block comments and whole-line `//` comments only: a trailing `//` may
    // be inside a URL on a line that also names a command.
    const text = readFileSync(file, "utf8")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
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
 * Commands whose wrapper module the chat window imports, so the deny list
 * cannot name them, but which the chat never calls. Each refuses every window
 * but the main one itself, with `require_main_window`.
 *
 * `callers` are the frontend functions that reach the command, each with the
 * files allowed to name it: its definition, and a helper wrapping it.
 */
const MAIN_WINDOW_ONLY = [
  { command: "quit_app", rust: "settings.rs", callers: [["quitApp", ["src/lib/api/settings.ts"]]] },
  {
    command: "finish_requested_quit",
    rust: "settings.rs",
    callers: [["finishRequestedQuit", ["src/lib/api/settings.ts"]]],
  },
  { command: "recover_archive", rust: "transfers.rs", callers: [["recoverArchive", ["src/lib/api/transfers.ts"]]] },
  { command: "remove_friend", rust: "peers.rs", callers: [["removeFriend", ["src/lib/api/friends.ts"]]] },
  { command: "get_my_ember_hash", rust: "peers.rs", callers: [["getMyEmberHash", ["src/lib/api/friends.ts"]]] },
  { command: "reset_friend_code", rust: "peers.rs", callers: [["resetFriendCode", ["src/lib/api/friends.ts"]]] },
  { command: "kad_bootstrap_ip", rust: "peers.rs", callers: [["kadBootstrapIp", ["src/lib/api/kad.ts"]]] },
  {
    command: "delete_owned_channel",
    rust: "channels.rs",
    callers: [["deleteOwnedChannel", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "transfer_channel_ownership",
    rust: "channels.rs",
    callers: [["transferChannelOwnership", ["src/lib/api/channels.ts"]]],
  },
  {
    command: "read_clipboard_text",
    rust: "system.rs",
    callers: [
      ["readClipboardText", ["src/lib/api/system.ts", "src/lib/utils.ts"]],
      ["readFromClipboard", ["src/lib/utils.ts"]],
    ],
  },
];

/** The body of `fn name(` in a commands file, up to its closing brace. */
function rustFunctionBody(file, name) {
  const text = readFileSync(join(rustRoot, "commands", file), "utf8");
  const start = text.search(new RegExp(`\\bfn ${name}\\s*\\(`));
  assert.ok(start >= 0, `${name} was not found in commands/${file}`);
  const end = text.indexOf("\n}\n", start);
  return text.slice(start, end < 0 ? undefined : end);
}

test("main-window-only commands refuse every other window", () => {
  const registered = registeredCommands();
  const unguarded = MAIN_WINDOW_ONLY.filter(({ command, rust }) => {
    assert.ok(registered.has(command), `${command} is not a registered command`);
    return !/require_main_window\(&window\)\?/.test(rustFunctionBody(rust, command));
  }).map(({ command }) => command);
  assert.deepEqual(unguarded, [], "these must call require_main_window before doing anything");
});

test("the chat window's code never calls a main-window-only command", () => {
  const called = [];
  for (const file of chatWindowSources()) {
    const relative = file.slice(root.length + 1).replaceAll("\\", "/");
    const text = readFileSync(file, "utf8");
    for (const { command, callers } of MAIN_WINDOW_ONLY) {
      for (const [caller, allowed] of callers) {
        if (allowed.includes(relative)) continue;
        if (new RegExp(`\\b${caller}\\s*\\(`).test(text)) called.push(`${command} via ${caller} in ${relative}`);
      }
    }
  }
  assert.deepEqual(called, [], "the popped-out chat calls these, and require_main_window would refuse them there");
});
