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

cat > "$BIN/sleet" << LAUNCH
#!/usr/bin/env bash
exec "$VENV/bin/python" "$SRC/sleet.py" "\$@"
LAUNCH
chmod +x "$BIN/sleet"

[ -f "$CONF/config.json" ] || cp "$SRC/config.example.json" "$CONF/config.json"

echo "Installed: $BIN/sleet"
case ":$PATH:" in *":$BIN:"*) ;; *) echo "Add to PATH:  export PATH=\"$BIN:\$PATH\"";; esac
echo "Next: set \"instance\" in $CONF/config.json, then save your browser Cookie header to $CONF/cookie (chmod 600)"
