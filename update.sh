#!/usr/bin/env bash
# Update netinv: fetch the latest version and reinstall it with the options used before. Run: ./update.sh
set -euo pipefail
cd "$(dirname "$0")"

# The checkout belongs to you, not to root: fetch as you, install as root.
if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
  sudo -u "$SUDO_USER" git pull --ff-only
  exec ./install.sh
fi
git pull --ff-only
exec sudo ./install.sh
