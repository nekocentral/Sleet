#!/usr/bin/env bash
# Install sleet: private venv with requests, a `sleet` launcher in ~/bin (or $1), config dir.
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HOME/bin}"
VENV="${XDG_DATA_HOME:-$HOME/.local/share}/sleet/venv"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/sleet"

python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade requests
mkdir -p "$BIN" "$CONF" && chmod 700 "$CONF"

# only replace a launcher this script wrote earlier, never some other "sleet"
if [ -e "$BIN/sleet" ] && ! grep -q 'sleet\.py' "$BIN/sleet"; then
  echo "$BIN/sleet exists and is not a sleet launcher; remove it or pass another directory" >&2
  exit 1
fi
# %q keeps paths with spaces, quotes or \$ intact
printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$VENV/bin/python" "$SRC/sleet.py" > "$BIN/sleet"
chmod +x "$BIN/sleet"

[ -f "$CONF/config.json" ] || cp "$SRC/config.example.json" "$CONF/config.json"

echo "Installed: $BIN/sleet"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Add to PATH:  export PATH=\"$BIN:\$PATH\"";; esac
echo "Next: set \"instance\" in $CONF/config.json, then save your browser Cookie header to $CONF/cookie (chmod 600)"
