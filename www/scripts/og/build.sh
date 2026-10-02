#!/usr/bin/env bash
# Draws the Open Graph image of every page in config/pages.json into
# public/og/<key>.png (1200×630), from card.html in headless Chromium.
#
#   cd www && scripts/og/build.sh
#
# Needs chromium (or google-chrome), jq and network access for the fonts.
# The images are committed: production serves public/ as-is.
set -euo pipefail

cd "$(dirname "$0")/../.."
browser="$(command -v chromium || command -v chromium-browser || command -v google-chrome || true)"
[ -n "$browser" ] || { echo "chromium or google-chrome is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

mkdir -p public/og
card="file://$PWD/scripts/og/card.html"
profile="$(mktemp -d)"
trap 'rm -rf "$profile"' EXIT

seed=1
# Fields joined by the unit separator, not a tab: `read` merges consecutive
# whitespace separators, so an empty kicker would shift every field after it.
jq -r 'to_entries[] | [.key, .value.kicker, .value.title, .value.description] | join("\u001f")' config/pages.json |
while IFS=$'\x1f' read -r key kicker title desc; do
  query="$(jq -rn --arg k "$kicker" --arg t "$title" --arg d "$desc" --arg s "$seed" \
    '"kicker=\($k|@uri)&title=\($t|@uri)&desc=\($d|@uri)&seed=\($s)"')"
  # --virtual-time-budget lets the web fonts load before the capture.
  "$browser" --headless=new --disable-gpu --hide-scrollbars --no-first-run \
    --user-data-dir="$profile" --window-size=1200,630 --force-device-scale-factor=1 \
    --virtual-time-budget=8000 --screenshot="public/og/$key.png" "$card?$query" >/dev/null 2>&1
  [ -s "public/og/$key.png" ] || { echo "no image for $key" >&2; exit 1; }
  echo "public/og/$key.png"
  seed=$((seed + 7919))
done
