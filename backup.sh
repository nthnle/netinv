#!/usr/bin/env bash
# Back up lanledger, or put a backup back.
#
#   sudo ./backup.sh                      writes lanledger-backup-<date>.tar.gz in the current folder
#   sudo ./backup.sh somewhere/file.tar.gz
#   sudo ./backup.sh --restore file.tar.gz
#
# A backup holds everything that cannot be fetched again: the database (devices, names, history,
# blocks, password) and the installer options. Keep it somewhere other than the Pi's own card.
# To move to a new card or a new Pi: install lanledger there (sudo ./install.sh), then restore.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
DATA=/var/lib/lanledger
CONF=/etc/lanledger/install.conf

if [[ "${1:-}" == --restore ]]; then
  FILE="${2:?Give the backup file to restore.}"
  [[ -f "$FILE" ]] || { echo "No such file: $FILE" >&2; exit 1; }
  [[ -d "$DATA" ]] || { echo "lanledger is not installed here yet. Run sudo ./install.sh first, then restore." >&2; exit 1; }
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  tar -xzf "$FILE" -C "$TMP"
  [[ -f "$TMP/lanledger.db" ]] || { echo "That file is not a lanledger backup." >&2; exit 1; }
  systemctl stop lanledger
  if [[ -f "$DATA/lanledger.db" ]]; then mv "$DATA/lanledger.db" "$DATA/lanledger.db.before-restore"; fi
  rm -f "$DATA/lanledger.db-wal" "$DATA/lanledger.db-shm"
  install -o lanledger -g lanledger -m 600 "$TMP/lanledger.db" "$DATA/lanledger.db"
  if [[ -f "$TMP/install.conf" && ! -f "$CONF" ]]; then install -D -m 600 "$TMP/install.conf" "$CONF"; fi
  systemctl start lanledger
  echo "Restored. What was there before is kept as $DATA/lanledger.db.before-restore"
  echo "If the installer options in the backup matter here (port, interface), run sudo ./install.sh once more."
  exit 0
fi

OUT="${1:-lanledger-backup-$(date +%Y%m%d-%H%M).tar.gz}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
chown lanledger "$TMP"
# a consistent copy, taken through SQLite itself, so it is safe while lanledger is running
sudo -u lanledger python3 /opt/lanledger/lanledger.py --backup "$TMP/lanledger.db" >/dev/null
if [[ -f "$CONF" ]]; then cp "$CONF" "$TMP/install.conf"; fi
(umask 077; tar -czf "$OUT" -C "$TMP" .)
if [[ -n "${SUDO_USER:-}" ]]; then chown "$SUDO_USER" "$OUT"; fi
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1)). It contains your household's browsing history and the dashboard's"
echo "password hash, and the Deco password if you connected one: store it as carefully as you would those."
