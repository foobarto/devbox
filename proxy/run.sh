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

if [[ "${1:-}" == "-V" || "${1:-}" == "--version" || "${1:-}" == "version" ]]; then
  version="$(tr -d '[:space:]' < "$here/../VERSION" 2>/dev/null || printf 'dev')"
  printf 'devbox-ai-proxy %s\n' "$version"
  exit 0
fi

envfile="${DEVBOX_PROXY_ENV:-$HOME/.config/devbox/api-keys.env}"
if [[ -f "$envfile" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$envfile"
  set +a
fi

cfg="${DEVBOX_PROXY_CONFIG:-$HOME/.config/devbox/proxy.config.json}"
[[ -f "$cfg" ]] || cfg="$here/proxy.config.example.json"
export DEVBOX_PROXY_CONFIG="$cfg"

exec python3 "$here/devbox-ai-proxy.py"
