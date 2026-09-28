// Copies circle-flags' SVGs into static/flags/ (gitignored): country flags at
// the top level for peer locations, language flags under language/ for a
// channel's default language.
import { copyFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";

const src = join("node_modules", "circle-flags", "flags");
const dest = join("static", "flags");

if (!existsSync(src)) process.exit(0);

function copySvgs(from, to) {
  mkdirSync(to, { recursive: true });
  const files = readdirSync(from).filter((f) => f.endsWith(".svg"));
  for (const f of files) copyFileSync(join(from, f), join(to, f));
  return files.length;
}

const countries = copySvgs(src, dest);
const languages = existsSync(join(src, "language"))
  ? copySvgs(join(src, "language"), join(dest, "language"))
  : 0;
console.log(`Copied ${countries} country and ${languages} language flag SVGs to static/flags/`);
