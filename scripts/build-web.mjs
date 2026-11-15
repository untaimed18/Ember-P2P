// The web UI emberd serves: the same app as the desktop's, built for a
// browser into build-web/ (see vite.config.js and src/lib/runtime).
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vite = join(root, "node_modules", "vite", "bin", "vite.js");
const result = spawnSync(process.execPath, [vite, "build"], {
  cwd: root,
  stdio: "inherit",
  env: { ...process.env, EMBER_WEB: "1" },
});
process.exit(result.status ?? 1);
