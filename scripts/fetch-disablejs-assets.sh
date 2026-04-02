#!/usr/bin/env bash
# Fetch disablejs favicon assets via Google's favicon proxy.
# Usage: bash static/scripts/fetch-disablejs-assets.sh
# Run from the theme root (smigle-lagom/).

set -uo pipefail

DEST="../images/disablejs"

echo "Fetching favicon assets..."

curl -fsSL -o "$DEST/sy.png"   "https://www.google.com/s2/favicons?domain=scientology.org&sz=32"
curl -fsSL -o "$DEST/hn.png"   "https://www.google.com/s2/favicons?domain=news.ycombinator.com&sz=32"
curl -fsSL -o "$DEST/go.ico"   "https://www.google.com/s2/favicons?domain=google.com&sz=32"
curl -fsSL -o "$DEST/gm.png"   "https://www.google.com/s2/favicons?domain=maps.google.com&sz=32"
curl -fsSL -o "$DEST/cgpt.png" "https://www.google.com/s2/favicons?domain=chatgpt.com&sz=32"
curl -fsSL -o "$DEST/fes.png"  "https://www.google.com/s2/favicons?domain=tfes.org&sz=32"
curl -fsSL -o "$DEST/az.ico"   "https://www.google.com/s2/favicons?domain=amazon.com&sz=32"
curl -fsSL -o "$DEST/rd.png"   "https://www.google.com/s2/favicons?domain=reddit.com&sz=32"
curl -fsSL -o "$DEST/gr.png"   "https://www.google.com/s2/favicons?domain=goodreads.com&sz=32"
curl -fsSL -o "$DEST/ph.png"   "https://www.google.com/s2/favicons?domain=pornhub.com&sz=32"
curl -fsSL -o "$DEST/xv.png"   "https://www.google.com/s2/favicons?domain=xvideos.com&sz=32"
curl -fsSL -o "$DEST/yt.ico"   "https://www.google.com/s2/favicons?domain=youtube.com&sz=32"

echo "Done. Files:"
ls -la "$DEST"/*.png "$DEST"/*.ico 2>/dev/null
