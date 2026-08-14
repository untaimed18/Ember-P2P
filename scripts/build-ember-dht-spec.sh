#!/usr/bin/env bash
# Rebuild docs/ember-dht-specification.pdf from the HTML source.
# Requires WeasyPrint:  pip install weasyprint
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
exec python3 -m weasyprint \
  "$root/docs/ember-dht-specification.html" \
  "$root/docs/ember-dht-specification.pdf"
