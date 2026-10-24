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
