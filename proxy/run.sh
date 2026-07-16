#!/usr/bin/env bash
#
# Launch the host-side AI proxy so disposable devboxes never hold credentials.
# Reads API keys from ~/.config/devbox/api-keys.env (if present) and a route
# config from ~/.config/devbox/proxy.config.json (falls back to the bundled
# example). Bind address/port come from the config's "listen" field.
#
# Requires: python3 (standard library only).
#
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

envfile="${DEVBOX_PROXY_ENV:-$HOME/.config/devbox/api-keys.env}"
if [[ -f "$envfile" ]]; then set -a; . "$envfile"; set +a; fi

cfg="${DEVBOX_PROXY_CONFIG:-$HOME/.config/devbox/proxy.config.json}"
[[ -f "$cfg" ]] || cfg="$here/proxy.config.example.json"
export DEVBOX_PROXY_CONFIG="$cfg"

exec python3 "$here/devbox-ai-proxy.py"
