#!/usr/bin/env bash
# Rebuild docs/ember-dht-specification.pdf from the HTML source.
# Requires WeasyPrint:  pip install weasyprint
# On Windows, also install the GTK3 runtime (Pango) and leave it on PATH, e.g.
#   winget install tschoonj.GTKForWindows
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"

gtk_bin="/c/Program Files/GTK3-Runtime Win64/bin"
if [[ -d "$gtk_bin" ]]; then
  export WEASYPRINT_DLL_DIRECTORIES="$gtk_bin"
  export PATH="$gtk_bin:$PATH"
fi

py=python3
command -v python3 >/dev/null 2>&1 || py=python
exec "$py" -m weasyprint \
  "$root/docs/ember-dht-specification.html" \
  "$root/docs/ember-dht-specification.pdf"
